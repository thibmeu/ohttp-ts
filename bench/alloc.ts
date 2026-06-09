/**
 * Allocation benchmark (Node-only).
 *
 * Time-based benches (`*.bench.ts`) can't tell whether a zero-copy change
 * actually removed allocations — they only report ns/op. This harness reports
 * per-op deltas of:
 *   - arrayBuffers : ArrayBuffer backing-store bytes — where Uint8Array copies
 *     live. This is the signal the recent zero-copy work (subarray views,
 *     StreamBuffer cursor) targets. The V8 *heap* profiler can't see these;
 *     they're external memory, hence process.memoryUsage().
 *   - heapUsed     : JS-heap objects (wrappers, promises, closures).
 *
 * Method: force GC for a clean baseline, run N ops, read memory WITHOUT a
 * trailing GC so transient buffers still count. This is approximate — if a GC
 * fires mid-loop it frees transients and the delta becomes a lower bound (can
 * even go slightly negative). Iteration counts are kept small for large
 * payloads to make a mid-loop GC unlikely. Requires --expose-gc.
 *
 * Browser/Workers can't run this, so it stays out of the vitest bench glob and
 * is Node-only.
 *
 * Run: npm run bench:alloc
 */

import { AEAD_AES_128_GCM } from "hpke";
import { client, makeFixture, server } from "./fixtures.js";
import { randomBytes, streamDecrypt, streamEncrypt } from "./util.js";

declare const gc: (() => void) | undefined;

interface Alloc {
	heap: number;
	ab: number;
}

/** Per-op delta of heapUsed and arrayBuffers (bytes). See file header for caveats. */
async function measure(iters: number, fn: () => Promise<unknown>): Promise<Alloc> {
	if (!gc) throw new Error("run with --expose-gc (use `npm run bench:alloc`)");

	// Warm up so one-time setup (key import, etc.) isn't attributed to the op.
	for (let i = 0; i < Math.min(iters, 10); i++) await fn();

	// Two passes: the first collects young-gen, the second sweeps what the first
	// promoted/freed, so the baseline has no collectible buffers left to skew the
	// loop delta negative.
	gc();
	gc();
	const before = process.memoryUsage();
	for (let i = 0; i < iters; i++) await fn();
	const after = process.memoryUsage(); // no trailing GC: keep transients counted

	return {
		heap: (after.heapUsed - before.heapUsed) / iters,
		ab: (after.arrayBuffers - before.arrayBuffers) / iters,
	};
}

function median(xs: number[]): number {
	const s = [...xs].sort((a, b) => a - b);
	const m = Math.floor(s.length / 2);
	return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

/** Median of several measure() runs — damps the GC noise on large payloads. */
async function measureMedian(iters: number, fn: () => Promise<unknown>): Promise<Alloc> {
	const runs: Alloc[] = [];
	for (let i = 0; i < 5; i++) runs.push(await measure(iters, fn));
	return { heap: median(runs.map((r) => r.heap)), ab: median(runs.map((r) => r.ab)) };
}

function fmt(bytes: number): string {
	const sign = bytes < 0 ? "-" : "";
	const b = Math.abs(bytes);
	if (b >= 1024 * 1024) return `${sign}${(b / 1024 / 1024).toFixed(2)} MB`;
	if (b >= 1024) return `${sign}${(b / 1024).toFixed(1)} KB`;
	return `${sign}${b.toFixed(0)} B`;
}

// AEAD fixtures for the streaming paths.
const aead = AEAD_AES_128_GCM();
const skey = crypto.getRandomValues(new Uint8Array(16));
const snonce = crypto.getRandomValues(new Uint8Array(12));

async function main(): Promise<void> {
	const f1k = await makeFixture(1_024);
	const f1m = await makeFixture(1_048_576);
	const _512KB = randomBytes(512 * 1024);
	const framed16 = await streamEncrypt(aead, skey, snonce, _512KB, 16_384);

	// Few iters for large payloads so a mid-loop GC stays unlikely (see header).
	const cases: Array<[string, number, () => Promise<unknown>]> = [
		["encapsulateRequest 1KB", 100, () => client.encapsulate(f1k.payload)],
		["encapsulateRequest 1MB", 5, () => client.encapsulate(f1m.payload)],
		["decapsulateRequest 1KB", 100, () => server.decapsulate(f1k.encapsulatedRequest)],
		["decapsulateRequest 1MB", 5, () => server.decapsulate(f1m.encapsulatedRequest)],
		["encryptResponse 1MB", 5, () => f1m.serverCtx.encryptResponse(f1m.payload)],
		["decryptResponse 1MB", 5, () => f1m.clientCtx.decryptResponse(f1m.encryptedResponse)],
		["round-trip 1KB", 100, () => roundTrip(f1k.payload)],
		["round-trip 1MB", 5, () => roundTrip(f1m.payload)],
		[
			"stream encrypt 512KB / 16KB chunks",
			5,
			() => streamEncrypt(aead, skey, snonce, _512KB, 16_384),
		],
		[
			"stream decrypt 512KB / 64KB reads",
			5,
			() => streamDecrypt(aead, skey, snonce, framed16, 65_536),
		],
	];

	console.log("Allocation per op (process.memoryUsage deltas; approximate)\n");
	console.log(`${"case".padEnd(40)}  ${"arrayBuf/op".padStart(12)}  ${"heap/op".padStart(10)}`);
	console.log("-".repeat(66));
	for (const [label, iters, fn] of cases) {
		const { heap, ab } = await measureMedian(iters, fn);
		console.log(`${label.padEnd(40)}  ${fmt(ab).padStart(12)}  ${fmt(heap).padStart(10)}`);
	}
}

async function roundTrip(payload: Uint8Array): Promise<void> {
	const { encapsulatedRequest, context } = await client.encapsulate(payload);
	const { context: sctx } = await server.decapsulate(encapsulatedRequest);
	const encRes = await sctx.encryptResponse(payload);
	await context.decryptResponse(encRes);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
