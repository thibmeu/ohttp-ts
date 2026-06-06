/**
 * Shared helpers for the benchmark / profiler / alloc harnesses (dev-only).
 *
 * Keeping these in one place means every harness builds fixtures the same way,
 * so throughput, allocation, and CPU-profile numbers stay comparable.
 */

import type { AEAD as AeadImpl } from "hpke";
import { concat } from "../src/utils.js";
import {
	createChunkerTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
} from "../src/streaming.js";

export function randomBytes(size: number): Uint8Array {
	const buf = new Uint8Array(size);
	for (let off = 0; off < size; off += 65_536) {
		crypto.getRandomValues(buf.subarray(off, Math.min(off + 65_536, size)));
	}
	return buf;
}

/** ReadableStream that yields `bytes` in `readSize`-byte reads. */
export function streamFrom(bytes: Uint8Array, readSize: number): ReadableStream<Uint8Array> {
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

/** Read a stream to completion, returning the total byte count. */
export async function drain(stream: ReadableStream<Uint8Array>): Promise<number> {
	const reader = stream.getReader();
	let n = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		n += value.length;
	}
	return n;
}

/** Read a stream to completion, returning one contiguous buffer. */
export async function collectStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const parts: Uint8Array[] = [];
	const reader = stream.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		parts.push(value);
	}
	return concat(...parts);
}

/** Chunk + AEAD-encrypt a payload through the streaming transforms (whole payload as one read). */
export function streamEncrypt(
	aead: AeadImpl,
	key: Uint8Array,
	nonce: Uint8Array,
	payload: Uint8Array,
	chunkSize: number,
): Promise<Uint8Array> {
	return collectStream(
		streamFrom(payload, payload.length)
			.pipeThrough(createChunkerTransform(chunkSize))
			.pipeThrough(createResponseEncryptTransform(aead, key, nonce)),
	);
}

/** AEAD-decrypt framed input re-fragmented at `readSize` boundaries; returns plaintext byte count. */
export function streamDecrypt(
	aead: AeadImpl,
	key: Uint8Array,
	nonce: Uint8Array,
	framed: Uint8Array,
	readSize: number,
): Promise<number> {
	return drain(streamFrom(framed, readSize).pipeThrough(createResponseDecryptTransform(aead, key, nonce)));
}
