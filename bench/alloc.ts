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
 * Method: warm up, force GC for a clean baseline, run exactly one operation,
 * then take two readings: before GC (short-lived working memory) and after GC
 * (memory retained by live state). Measuring one operation prevents a
 * collection in the middle of an iteration batch from producing misleading
 * per-op ratios. Heap deltas remain approximate; ArrayBuffer deltas are the
 * more useful signal. Requires --expose-gc.
 *
 * Browser/Workers can't run this, so it stays out of the vitest bench glob and
 * is Node-only.
 *
 * Run: npm run bench:alloc
 */

import { AEAD_AES_128_GCM } from "hpke";
import { chunkedClient, chunkedServer, client, makeFixture, server } from "./fixtures.ts";
import { randomBytes, streamDecrypt, streamEncrypt } from "./util.ts";

declare const gc: (() => void) | undefined;

interface Snapshot {
	heap: number;
	ab: number;
}

interface Alloc {
	transient: Snapshot;
	retained: Snapshot;
}

function snapshot(before: NodeJS.MemoryUsage, after: NodeJS.MemoryUsage): Snapshot {
	return {
		heap: after.heapUsed - before.heapUsed,
		ab: after.arrayBuffers - before.arrayBuffers,
	};
}

/** Memory visible after one operation, before and after collecting garbage. */
async function measure(fn: () => Promise<unknown>): Promise<Alloc> {
	if (!gc) throw new Error("run with --expose-gc (use `npm run bench:alloc`)");

	gc();
	gc();
	const before = process.memoryUsage();
	await fn();
	const transient = process.memoryUsage();
	gc();
	gc();
	const retained = process.memoryUsage();
	return { transient: snapshot(before, transient), retained: snapshot(before, retained) };
}

function median(xs: number[]): number {
	const s = [...xs].sort((a, b) => a - b);
	const m = Math.floor(s.length / 2);
	return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

/** Median of several one-operation runs damps heap and collector noise. */
async function measureMedian(fn: () => Promise<unknown>): Promise<Alloc> {
	const runs: Alloc[] = [];
	for (let i = 0; i < 9; i++) runs.push(await measure(fn));
	return {
		transient: {
			heap: median(runs.map((r) => r.transient.heap)),
			ab: median(runs.map((r) => r.transient.ab)),
		},
		retained: {
			heap: median(runs.map((r) => r.retained.heap)),
			ab: median(runs.map((r) => r.retained.ab)),
		},
	};
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

	// Chunked equivalents (16KB chunks, framed): same payloads, same shapes.
	const chunkedEnc1KB = (await chunkedClient.encapsulate(f1k.payload)).encapsulatedRequest;
	const chunkedEnc1MB = (await chunkedClient.encapsulate(f1m.payload)).encapsulatedRequest;
	const chunkedRoundTrip = async (payload: Uint8Array): Promise<void> => {
		const { encapsulatedRequest, createResponseContext } = await chunkedClient.encapsulate(payload);
		const { createResponseContext: srvCreateResponse } =
			await chunkedServer.decapsulate(encapsulatedRequest);
		const encRes = await chunkedServer.encapsulateResponse(await srvCreateResponse(), payload);
		await chunkedClient.decapsulateResponse(createResponseContext, encRes);
	};

	const cases: Array<[string, () => Promise<unknown>]> = [
		["encapsulateRequest 1KB", () => client.encapsulate(f1k.payload)],
		["encapsulateRequest 1MB", () => client.encapsulate(f1m.payload)],
		["decapsulateRequest 1KB", () => server.decapsulate(f1k.encapsulatedRequest)],
		["decapsulateRequest 1MB", () => server.decapsulate(f1m.encapsulatedRequest)],
		["encryptResponse 1MB", () => f1m.serverCtx.encryptResponse(f1m.payload)],
		["decryptResponse 1MB", () => f1m.clientCtx.decryptResponse(f1m.encryptedResponse)],
		["round-trip 1KB", () => roundTrip(f1k.payload)],
		["round-trip 1MB", () => roundTrip(f1m.payload)],
		["chunked encapsulateRequest 1KB", () => chunkedClient.encapsulate(f1k.payload)],
		["chunked encapsulateRequest 1MB", () => chunkedClient.encapsulate(f1m.payload)],
		["chunked decapsulateRequest 1KB", () => chunkedServer.decapsulate(chunkedEnc1KB)],
		["chunked decapsulateRequest 1MB", () => chunkedServer.decapsulate(chunkedEnc1MB)],
		["chunked round-trip 1KB", () => chunkedRoundTrip(f1k.payload)],
		["chunked round-trip 1MB", () => chunkedRoundTrip(f1m.payload)],
		["stream encrypt 512KB / 16KB chunks", () => streamEncrypt(aead, skey, snonce, _512KB, 16_384)],
		[
			"stream decrypt 512KB / 64KB reads",
			() => streamDecrypt(aead, skey, snonce, framed16, 65_536),
		],
	];

	for (const [, fn] of cases) for (let i = 0; i < 10; i++) await fn();

	console.log("Memory after one operation (median process.memoryUsage delta)\n");
	console.log(
		`${"case".padEnd(40)}  ${"temporary AB".padStart(12)}  ${"temporary heap".padStart(14)}  ${"retained AB".padStart(11)}  ${"retained heap".padStart(13)}`,
	);
	console.log("-".repeat(98));
	for (const [label, fn] of cases) {
		const { transient, retained } = await measureMedian(fn);
		console.log(
			`${label.padEnd(40)}  ${fmt(transient.ab).padStart(12)}  ${fmt(transient.heap).padStart(14)}  ${fmt(retained.ab).padStart(11)}  ${fmt(retained.heap).padStart(13)}`,
		);
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
