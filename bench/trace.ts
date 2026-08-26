/**
 * Trace export (Node-only dev tool).
 *
 * Runs one op under V8's CPU + sampling-heap profilers and records the
 * `crypto.subtle` call timeline, then writes artifacts for external tools:
 *   bench/.trace/<op>.cpuprofile  -> speedscope.app, or Chrome DevTools
 *                                    (Performance > Load profile): flame graph / stacks
 *   bench/.trace/<op>.heapprofile -> Chrome DevTools (Memory > Load profile):
 *                                    where bytes are allocated
 *   bench/.trace/<op>.trace.json  -> ui.perfetto.dev / chrome://tracing:
 *                                    the crypto.subtle dispatch timeline (overlap)
 *
 * Uses node:inspector; never shipped (the library stays runtime-agnostic).
 *
 * Run: OP=decapsulateRequest SIZE=1048576 npm run bench:trace
 *      OP one of: encapsulateRequest decapsulateRequest encryptResponse decryptResponse roundTrip
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { Session } from "node:inspector/promises";
import { client, makeFixture, server } from "./fixtures.ts";

const { OP = "decapsulateRequest", SIZE = "1048576", ITERS = "2000" } = process.env;
const f = await makeFixture(Number(SIZE));

const ops: Record<string, () => Promise<unknown>> = {
	encapsulateRequest: () => client.encapsulate(f.payload),
	decapsulateRequest: () => server.decapsulate(f.encapsulatedRequest),
	encryptResponse: () => f.serverCtx.encryptResponse(f.payload),
	decryptResponse: () => f.clientCtx.decryptResponse(f.encryptedResponse),
	roundTrip: async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(f.payload);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		await context.decryptResponse(await sctx.encryptResponse(f.payload));
	},
};
const op =
	ops[OP] ??
	(() => {
		throw new Error(`unknown OP=${OP} (one of: ${Object.keys(ops).join(", ")})`);
	});

// crypto.subtle dispatch timeline, in Chrome Trace Event format (µs).
interface TraceEvent {
	name: string;
	ph: "X";
	pid: number;
	tid: number;
	ts: number;
	dur: number;
}
const events: TraceEvent[] = [];
let tracing = false;
const origin = performance.now();
(function patchSubtle() {
	const subtle = crypto.subtle as unknown as Record<string, unknown>;
	for (const name of Object.getOwnPropertyNames(Object.getPrototypeOf(crypto.subtle))) {
		if (name === "constructor" || typeof (subtle[name] as unknown) !== "function") continue;
		const orig = (subtle[name] as (...a: unknown[]) => unknown).bind(crypto.subtle);
		subtle[name] = (...args: unknown[]) => {
			if (!tracing) return orig(...args);
			const ts = (performance.now() - origin) * 1000;
			return Promise.resolve(orig(...args)).finally(() => {
				events.push({
					name,
					ph: "X",
					pid: 1,
					tid: 1,
					ts,
					dur: (performance.now() - origin) * 1000 - ts,
				});
			});
		};
	}
})();

const session = new Session();
session.connect();
await session.post("Profiler.enable");
await session.post("Profiler.setSamplingInterval", { interval: 50 });
await session.post("HeapProfiler.enable");

for (let i = 0; i < 200; i++) await op(); // warm up the JIT

await session.post("HeapProfiler.startSampling", { samplingInterval: 4096 });
await session.post("Profiler.start");
tracing = true;
for (let i = 0; i < Number(ITERS); i++) await op();
tracing = false;
const { profile } = await session.post("Profiler.stop");
const { profile: heap } = await session.post("HeapProfiler.stopSampling");
session.disconnect();

mkdirSync("bench/.trace", { recursive: true });
const out = `bench/.trace/${OP}`;
writeFileSync(`${out}.cpuprofile`, JSON.stringify(profile));
writeFileSync(`${out}.heapprofile`, JSON.stringify(heap));
writeFileSync(`${out}.trace.json`, JSON.stringify({ traceEvents: events }));

console.log(
	`wrote ${out}.{cpuprofile,heapprofile,trace.json}  (${events.length} crypto.subtle calls traced)`,
);
console.log("  .cpuprofile  -> speedscope.app or Chrome DevTools (Performance > Load profile)");
console.log("  .heapprofile -> Chrome DevTools (Memory > Load profile)");
console.log("  .trace.json  -> ui.perfetto.dev (crypto.subtle dispatch timeline)");
