/**
 * CPU profiler for the OHTTP hot paths (Node-only dev tool).
 *
 * Brackets each scenario's tight loop with V8's sampling CPU profiler
 * (node:inspector) and aggregates self-time by function, so startup and harness
 * noise are excluded and each hot path is attributed independently.
 *
 * Self-time spent inside WebCrypto / HKDF lands in native frames (shown as
 * "(native)") — that's the crypto cost we can't move. The JS frames in `src/…`
 * are the optimization surface: framing, copies, varint, factory churn.
 *
 * This uses node:inspector and is never shipped; the library itself stays
 * runtime-agnostic.
 *
 * Run: npm run bench:profile
 */

import { Session } from "node:inspector/promises";
import { AEAD_AES_128_GCM } from "hpke";
import { chunkedClient, chunkedServer, client, server } from "./fixtures.ts";
import { randomBytes, streamDecrypt, streamEncrypt } from "./util.ts";

interface CallFrame {
	functionName: string;
	url: string;
	lineNumber: number;
}
interface ProfileNode {
	id: number;
	callFrame: CallFrame;
	hitCount?: number;
}
interface CpuProfile {
	nodes: ProfileNode[];
	samples: number[];
	timeDeltas: number[];
}

function label(f: CallFrame): string {
	const name = f.functionName || "(anonymous)";
	if (!f.url || f.url.startsWith("node:")) return `${name}  (native)`;
	// shorten url to repo-relative-ish
	const short = f.url.replace(/^.*\/ohttp-ts\//, "").replace(/^.*\/node_modules\//, "…/");
	return `${name}  ${short}:${f.lineNumber + 1}`;
}

async function profile(
	session: Session,
	iters: number,
	fn: () => Promise<unknown>,
): Promise<Array<[string, number]>> {
	for (let i = 0; i < Math.min(iters, 20); i++) await fn(); // warm up JIT

	await session.post("Profiler.start");
	for (let i = 0; i < iters; i++) await fn();
	const { profile } = (await session.post("Profiler.stop")) as { profile: CpuProfile };

	const byId = new Map<number, CallFrame>();
	for (const n of profile.nodes) byId.set(n.id, n.callFrame);

	// self time per node from timeDeltas attributed to the sampled node
	const selfById = new Map<number, number>();
	for (let i = 0; i < profile.samples.length; i++) {
		const id = profile.samples[i]!;
		const dt = profile.timeDeltas[i] ?? 0;
		selfById.set(id, (selfById.get(id) ?? 0) + dt);
	}

	// aggregate by function label
	const byFn = new Map<string, number>();
	for (const [id, us] of selfById) {
		const frame = byId.get(id);
		if (!frame) continue;
		const key = label(frame);
		byFn.set(key, (byFn.get(key) ?? 0) + us);
	}

	return [...byFn.entries()].sort((a, b) => b[1] - a[1]);
}

// streaming fixtures: a raw AEAD with fixed key/nonce, fed to the shared helpers
const aead = AEAD_AES_128_GCM();
const skey = crypto.getRandomValues(new Uint8Array(16));
const snonce = crypto.getRandomValues(new Uint8Array(12));

async function main(): Promise<void> {
	const _1KB = randomBytes(1_024);
	const _1MB = randomBytes(1_048_576);
	const _512KB = randomBytes(512 * 1024);

	const enc1MB = await client.encapsulate(_1MB);
	const framed16 = await streamEncrypt(aead, skey, snonce, _512KB, 16_384);
	const framed256 = await streamEncrypt(aead, skey, snonce, _512KB, 256);

	// High-level API fixtures: exercises bhttp-ts encode/decode + Headers + URL.
	const makeRequest = (n: number): Request =>
		new Request("https://example.com/api/v1/resource?q=1&lang=en", {
			method: "POST",
			headers: {
				"content-type": "application/json",
				accept: "application/json",
				"user-agent": "ohttp-bench/1.0",
				"x-request-id": "0123456789abcdef",
			},
			body: randomBytes(n),
		});
	const makeResponse = (n: number): Response =>
		new Response(randomBytes(n), {
			status: 200,
			headers: { "content-type": "application/json", "cache-control": "no-store" },
		});

	const relayInit = (await client.encapsulateRequest(makeRequest(1_024))).init;
	const relayUrl = "https://relay.example.com/";

	const hlRoundTrip = async (): Promise<void> => {
		const { init, context } = await client.encapsulateRequest(makeRequest(1_024));
		const { request: inner, context: sctx } = await server.decapsulateRequest(
			new Request(relayUrl, init),
		);
		await inner.arrayBuffer(); // force bhttp decode of the body
		const encRes = await sctx.encapsulateResponse(makeResponse(1_024));
		const finalRes = await context.decapsulateResponse(encRes);
		await finalRes.arrayBuffer();
	};

	const chunkedEnc1MB = (await chunkedClient.encapsulate(_1MB)).encapsulatedRequest;

	// Chunked (draft-ietf-ohai-chunked-ohttp): same payloads, 16KB chunks, framed.
	const chunkedRoundTrip = async (p: Uint8Array): Promise<void> => {
		const { encapsulatedRequest, createResponseContext } = await chunkedClient.encapsulate(p);
		const { createResponseContext: srvCreateResponse } =
			await chunkedServer.decapsulate(encapsulatedRequest);
		const rctx = await srvCreateResponse();
		const encRes = await chunkedServer.encapsulateResponse(rctx, p);
		await chunkedClient.decapsulateResponse(createResponseContext, encRes);
	};

	// Chunked high-level API: streaming bhttp encode/decode both ways.
	const chunkedHlRoundTrip = async (): Promise<void> => {
		const { init, context } = await chunkedClient.encapsulateRequest(makeRequest(1_024));
		const { request: inner, context: sctx } = await chunkedServer.decapsulateRequest(
			new Request(relayUrl, init as RequestInit),
		);
		await inner.arrayBuffer();
		const encRes = await sctx.encapsulateResponse(makeResponse(1_024));
		const finalRes = await context.decapsulateResponse(encRes);
		await finalRes.arrayBuffer();
	};

	const roundTrip = async (p: Uint8Array): Promise<void> => {
		const { encapsulatedRequest, context } = await client.encapsulate(p);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(p);
		await context.decryptResponse(encRes);
	};

	const scenarios: Array<[string, number, () => Promise<unknown>]> = [
		// high-level API: bhttp encode/decode + Headers/URL on top of the crypto core
		[
			"HL encapsulateRequest 1KB+headers",
			3000,
			() => client.encapsulateRequest(makeRequest(1_024)),
		],
		[
			"HL decapsulateRequest 1KB+headers",
			3000,
			() => server.decapsulateRequest(new Request(relayUrl, relayInit)),
		],
		["HL round-trip 1KB+headers", 2000, hlRoundTrip],
		["round-trip 1KB (setup-dominated)", 4000, () => roundTrip(_1KB)],
		["encapsulateRequest 1MB", 1500, () => client.encapsulate(_1MB)],
		["decapsulateRequest 1MB", 1500, () => server.decapsulate(enc1MB.encapsulatedRequest)],
		// chunked equivalents of the four above
		["chunked HL round-trip 1KB+headers", 1000, chunkedHlRoundTrip],
		["chunked round-trip 1KB (setup-dominated)", 2000, () => chunkedRoundTrip(_1KB)],
		["chunked encapsulateRequest 1MB", 500, () => chunkedClient.encapsulate(_1MB)],
		["chunked decapsulateRequest 1MB", 500, () => chunkedServer.decapsulate(chunkedEnc1MB)],
		[
			"stream encrypt 512KB / 16KB chunks",
			400,
			() => streamEncrypt(aead, skey, snonce, _512KB, 16_384),
		],
		[
			"stream decrypt 512KB / 16KB / 1500B reads",
			400,
			() => streamDecrypt(aead, skey, snonce, framed16, 1_500),
		],
		[
			"stream encrypt 512KB / 256B chunks (slow)",
			60,
			() => streamEncrypt(aead, skey, snonce, _512KB, 256),
		],
		[
			"stream decrypt 512KB / 256B / 64KB reads (slow)",
			60,
			() => streamDecrypt(aead, skey, snonce, framed256, 65_536),
		],
	];

	const session = new Session();
	session.connect();
	await session.post("Profiler.enable");
	await session.post("Profiler.setSamplingInterval", { interval: 100 }); // 100µs

	const TOP = 12;
	for (const [name, iters, fn] of scenarios) {
		const ranked = await profile(session, iters, fn);
		const total = ranked.reduce((s, [, us]) => s + us, 0) || 1;
		console.log(`\n=== ${name}  (${iters} iters, ${(total / 1000).toFixed(0)}ms sampled) ===`);
		console.log(`${"self%".padStart(6)}  ${"self ms".padStart(8)}  function`);
		for (const [fn2, us] of ranked.slice(0, TOP)) {
			const pct = ((us / total) * 100).toFixed(1);
			console.log(`${pct.padStart(6)}  ${(us / 1000).toFixed(1).padStart(8)}  ${fn2}`);
		}
	}
	session.disconnect();
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
