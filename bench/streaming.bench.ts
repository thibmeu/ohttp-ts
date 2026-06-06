/**
 * Streaming transform microbenchmark.
 *
 * Isolates the chunked-OHTTP streaming layer (chunker + response encrypt/decrypt
 * transforms) from the KEM, using a raw AES-128-GCM AEAD with a fixed key/nonce.
 * This measures the JS plumbing — buffering, framing, copies — that dominates
 * per-chunk cost, independent of public-key crypto.
 *
 * Scenarios pick out the regimes that stress different code:
 *  - 16KB chunks, 1500B reads : realistic TLS/TCP fragmentation
 *  - 16KB chunks, 64KB reads  : bulk delivery
 *  - 256B chunks, 64KB reads  : many small frames per read
 *  - 256B chunks, 256B reads  : worst-case fragmentation (StreamBuffer accumulation)
 *
 * decrypt re-fragments the framed input at `readSize` boundaries to exercise the
 * buffer-accumulation path (the previous concat/slice pattern was O(n²) here).
 *
 * Run: npm run bench            (Node)
 *      npm run bench:browser    (Chromium, same file)
 */
import { AEAD_AES_128_GCM } from "hpke";
import { bench, describe } from "vitest";
import {
	createChunkerTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
} from "../src/streaming.js";

const aead = AEAD_AES_128_GCM();
const key = crypto.getRandomValues(new Uint8Array(16));
const nonce = crypto.getRandomValues(new Uint8Array(12));

const TOTAL = 512 * 1024;
const payload = new Uint8Array(TOTAL);
crypto.getRandomValues(payload.subarray(0, Math.min(TOTAL, 65_536)));

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

async function encrypt(plaintext: Uint8Array, chunkSize: number): Promise<Uint8Array> {
	const out = streamFrom(plaintext, plaintext.length)
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

// scenario: [label, chunkSize, readSize-for-decrypt]
const scenarios: Array<[string, number, number]> = [
	["16KB chunks / 1500B reads (TLS-like)", 16_384, 1_500],
	["16KB chunks / 64KB reads (bulk)", 16_384, 65_536],
	["256B chunks / 64KB reads (small frames)", 256, 65_536],
	["256B chunks / 256B reads (fragmented)", 256, 256],
];

describe("streaming encrypt (chunker + response-encrypt)", () => {
	for (const [label, chunkSize] of scenarios) {
		bench(label, async () => {
			await encrypt(payload, chunkSize);
		});
	}
});

// Pre-frame each scenario once so the decrypt bench measures only decryption.
const framedByLabel = new Map<string, Uint8Array>();
for (const [label, chunkSize] of scenarios) {
	framedByLabel.set(label, await encrypt(payload, chunkSize));
}

describe("streaming decrypt (response-decrypt)", () => {
	for (const [label, , readSize] of scenarios) {
		const framed = framedByLabel.get(label)!;
		bench(label, async () => {
			await drain(
				streamFrom(framed, readSize).pipeThrough(createResponseDecryptTransform(aead, key, nonce)),
			);
		});
	}
});
