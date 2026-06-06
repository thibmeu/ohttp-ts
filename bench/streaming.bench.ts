/**
 * Streaming transform microbenchmark.
 *
 * Isolates the chunked-OHTTP streaming layer (chunker + response encrypt/decrypt
 * transforms) from the KEM, using a raw AES-128-GCM AEAD with a fixed key/nonce.
 * This measures the JS plumbing — buffering, framing, copies — that dominates
 * per-chunk cost, independent of public-key crypto.
 *
 * Run: npx tsx bench/streaming.bench.ts
 *
 * Scenarios:
 *  - encrypt: chunker + response-encrypt throughput (sensitive to per-frame
 *    framing copies).
 *  - decrypt: response-decrypt throughput when the framed input is re-fragmented
 *    at `readSize` boundaries (sensitive to buffer accumulation / per-frame
 *    slicing — the O(n^2) regime when readSize >> chunkSize).
 */
import { AEAD_AES_128_GCM } from "hpke";
import {
	createChunkerTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
} from "../src/streaming.js";

const aead = AEAD_AES_128_GCM();
const key = crypto.getRandomValues(new Uint8Array(16));
const nonce = crypto.getRandomValues(new Uint8Array(12));

const ITERS = Number(process.env.ITERS ?? 15);
const WARMUP = Number(process.env.WARMUP ?? 5);
const TOTAL = Number(process.env.TOTAL ?? 512 * 1024);

function streamFrom(bytes: Uint8Array, readSize: number): ReadableStream<Uint8Array> {
	let off = 0;
	return new ReadableStream<Uint8Array>({
		pull(controller) {
			if (off >= bytes.length) return controller.close();
			const end = Math.min(off + readSize, bytes.length);
			controller.enqueue(bytes.subarray(off, end));
			off = end;
		},
	});
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<number> {
	const reader = stream.getReader();
	let n = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		n += value.length;
	}
	return n;
}

async function encrypt(payload: Uint8Array, chunkSize: number): Promise<Uint8Array> {
	const out = streamFrom(payload, payload.length)
		.pipeThrough(createChunkerTransform(chunkSize))
		.pipeThrough(createResponseEncryptTransform(aead, key, nonce));
	const parts: Uint8Array[] = [];
	const reader = out.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		parts.push(value);
	}
	const total = parts.reduce((s, p) => s + p.length, 0);
	const buf = new Uint8Array(total);
	let o = 0;
	for (const p of parts) {
		buf.set(p, o);
		o += p.length;
	}
	return buf;
}

function median(xs: number[]): number {
	const s = [...xs].sort((a, b) => a - b);
	const m = Math.floor(s.length / 2);
	return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

async function time(fn: () => Promise<void>): Promise<number> {
	for (let i = 0; i < WARMUP; i++) await fn();
	const ts: number[] = [];
	for (let i = 0; i < ITERS; i++) {
		const t0 = performance.now();
		await fn();
		ts.push(performance.now() - t0);
	}
	return median(ts);
}

const payload = new Uint8Array(TOTAL);
crypto.getRandomValues(payload.subarray(0, Math.min(TOTAL, 65536)));

// scenario: [label, chunkSize, readSize-for-decrypt]
const scenarios: Array<[string, number, number]> = [
	["16KB chunks, 1500B reads (realistic TLS/TCP)", 16384, 1500],
	["16KB chunks, 64KB reads (bulk)", 16384, 65536],
	["256B chunks, 64KB reads (small chunks, bulk read)", 256, 65536],
	["256B chunks, 256B reads (small chunks, fragmented)", 256, 256],
];

console.log(`payload=${(TOTAL / 1024).toFixed(0)}KB  iters=${ITERS}  warmup=${WARMUP}\n`);
console.log("scenario                                              enc ms   enc MB/s   dec ms   dec MB/s");

async function decryptOnce(framed: Uint8Array, readSize: number): Promise<number> {
	return drain(
		streamFrom(framed, readSize).pipeThrough(createResponseDecryptTransform(aead, key, nonce)),
	);
}

for (const [label, chunkSize, readSize] of scenarios) {
	const encMs = await time(async () => {
		await encrypt(payload, chunkSize);
	});
	const framed = await encrypt(payload, chunkSize);
	const encMbps = TOTAL / 1024 / 1024 / (encMs / 1000);

	let decCol: string;
	try {
		const decN = await decryptOnce(framed, readSize);
		if (decN !== TOTAL) throw new Error(`mismatch ${decN}`);
		const decMs = await time(async () => {
			await decryptOnce(framed, readSize);
		});
		const decMbps = TOTAL / 1024 / 1024 / (decMs / 1000);
		decCol = `${decMs.toFixed(2).padStart(6)}  ${decMbps.toFixed(1).padStart(8)}`;
	} catch (e) {
		decCol = `  FAIL (${(e as Error).message ?? e})`;
	}
	console.log(
		`${label.padEnd(52)}  ${encMs.toFixed(2).padStart(6)}  ${encMbps.toFixed(1).padStart(8)}   ${decCol}`,
	);
}
