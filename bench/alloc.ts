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

import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { AeadId, KdfId, KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";
import {
	createChunkerTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
} from "../src/streaming.js";

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const keyConfig = await KeyConfig.generate(suite, 0x01, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);
const client = new OHTTPClient(suite, keyConfig);
const server = new OHTTPServer([keyConfig]);

function randomBytes(size: number): Uint8Array {
	const buf = new Uint8Array(size);
	const chunkSize = 65_536;
	for (let offset = 0; offset < size; offset += chunkSize) {
		crypto.getRandomValues(buf.subarray(offset, Math.min(offset + chunkSize, size)));
	}
	return buf;
}

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

async function streamEncrypt(plaintext: Uint8Array, chunkSize: number): Promise<Uint8Array> {
	let off = 0;
	const src = new ReadableStream<Uint8Array>({
		pull(c) {
			if (off >= plaintext.length) return c.close();
			c.enqueue(plaintext.subarray(off, plaintext.length));
			off = plaintext.length;
		},
	});
	const out = src
		.pipeThrough(createChunkerTransform(chunkSize))
		.pipeThrough(createResponseEncryptTransform(aead, skey, snonce));
	const parts: Uint8Array[] = [];
	const reader = out.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		parts.push(value);
	}
	const buf = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
	let o = 0;
	for (const p of parts) {
		buf.set(p, o);
		o += p.length;
	}
	return buf;
}

async function drainDecrypt(framed: Uint8Array, readSize: number): Promise<void> {
	let off = 0;
	const src = new ReadableStream<Uint8Array>({
		pull(c) {
			if (off >= framed.length) return c.close();
			const end = Math.min(off + readSize, framed.length);
			c.enqueue(framed.subarray(off, end));
			off = end;
		},
	});
	const reader = src.pipeThrough(createResponseDecryptTransform(aead, skey, snonce)).getReader();
	for (;;) {
		const { done } = await reader.read();
		if (done) break;
	}
}

async function main(): Promise<void> {
	const _1KB = randomBytes(1_024);
	const _1MB = randomBytes(1_048_576);
	const _512KB = randomBytes(512 * 1024);

	// Fixtures for isolated decap/decrypt.
	const enc1KB = await client.encapsulate(_1KB);
	const dec1KB = await server.decapsulate(enc1KB.encapsulatedRequest);
	const resp1KB = await dec1KB.context.encryptResponse(_1KB);
	const enc1MB = await client.encapsulate(_1MB);
	const dec1MB = await server.decapsulate(enc1MB.encapsulatedRequest);
	const resp1MB = await dec1MB.context.encryptResponse(_1MB);

	const framed16 = await streamEncrypt(_512KB, 16_384);

	// Few iters for large payloads so a mid-loop GC stays unlikely (see header).
	const cases: Array<[string, number, () => Promise<unknown>]> = [
		["encapsulateRequest 1KB", 100, () => client.encapsulate(_1KB)],
		["encapsulateRequest 1MB", 5, () => client.encapsulate(_1MB)],
		["decapsulateRequest 1KB", 100, () => server.decapsulate(enc1KB.encapsulatedRequest)],
		["decapsulateRequest 1MB", 5, () => server.decapsulate(enc1MB.encapsulatedRequest)],
		["encryptResponse 1MB", 5, () => dec1MB.context.encryptResponse(_1MB)],
		["decryptResponse 1MB", 5, () => enc1MB.context.decryptResponse(resp1MB)],
		["round-trip 1KB", 100, () => roundTrip(_1KB)],
		["round-trip 1MB", 5, () => roundTrip(_1MB)],
		["stream encrypt 512KB / 16KB chunks", 5, () => streamEncrypt(_512KB, 16_384)],
		["stream decrypt 512KB / 64KB reads", 5, () => drainDecrypt(framed16, 65_536)],
	];

	// keep fixtures referenced
	void resp1KB;

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
