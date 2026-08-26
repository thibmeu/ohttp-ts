/**
 * Streaming transforms for chunked OHTTP
 *
 * Provides TransformStream-based encryption/decryption for true streaming
 * of chunked OHTTP requests and responses.
 */

import type { AEAD as AeadImpl, RecipientContext, SenderContext } from "hpke";
import { decode as decodeVarint, encode as encodeVarint } from "quicvarint";
import {
	AEAD_TAG_SIZE,
	DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE,
	DEFAULT_MAX_FRAME_SIZE,
} from "./constants.js";
import { FINAL_CHUNK_AAD, openResponseChunk, sealResponseChunk } from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import { concat, createChunkBudget } from "./utils.js";

/** A ReadableStream that emits `bytes` as a single chunk (if non-empty) then closes. */
export function streamOfBytes(bytes: Uint8Array): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		start(controller) {
			if (bytes.length > 0) controller.enqueue(bytes);
			controller.close();
		},
	});
}

/** Continue an existing reader, optionally emitting already-read bytes first. */
export function streamFromReader(
	reader: ReadableStreamDefaultReader<Uint8Array>,
	prefix: Uint8Array = EMPTY,
	signal?: AbortSignal,
	mapError: (error: unknown) => unknown = (error) => error,
): ReadableStream<Uint8Array> {
	let first = prefix;
	let released = false;
	function release() {
		if (released) return;
		released = true;
		signal?.removeEventListener("abort", abort);
		reader.releaseLock();
	}
	function abort() {
		void reader
			.cancel(signal?.reason)
			.catch(() => {})
			.finally(release);
	}
	if (signal?.aborted) abort();
	else signal?.addEventListener("abort", abort, { once: true });

	return new ReadableStream<Uint8Array>({
		async pull(controller) {
			if (signal?.aborted) throw signal.reason;
			if (first.length > 0) {
				controller.enqueue(first);
				first = EMPTY;
				return;
			}

			try {
				const { done, value } = await reader.read();
				if (!done) {
					controller.enqueue(value);
					return;
				}
				if (signal?.aborted) throw signal.reason;
				release();
				controller.close();
			} catch (error) {
				try {
					await reader?.cancel(error);
				} catch {}
				release();
				throw mapError(error);
			}
		},

		async cancel(reason) {
			try {
				await reader.cancel(reason);
			} finally {
				release();
			}
		},
	});
}

/** Preserve demand and cancellation while translating errors from a peer codec. */
export function mapStreamErrors(
	stream: ReadableStream<Uint8Array>,
	mapError: (error: unknown) => unknown,
): ReadableStream<Uint8Array> {
	return streamFromReader(stream.getReader(), EMPTY, undefined, mapError);
}

/**
 * Collect a stream of byte chunks into one contiguous buffer, optionally
 * prefixed. Passing `prefix` here rather than concatenating afterwards keeps
 * the whole payload to a single copy.
 */
export async function collectStream(
	stream: ReadableStream<Uint8Array>,
	prefix?: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
	const parts: Uint8Array[] = prefix === undefined ? [] : [prefix];
	const reader = stream.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		parts.push(value);
	}
	return concat(parts);
}

/**
 * Maximum chunks allowed per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
 */
const MAX_CHUNKS = 2 ** 32;

const EMPTY = new Uint8Array(0);

/** Cancellation shared by one high-level streaming operation. */
export interface StreamOperationOptions {
	/** Abort the operation and cancel its input stream with the signal's reason. */
	readonly signal?: AbortSignal;
}

/**
 * How many per-chunk AEAD calls a streaming transform keeps in flight.
 *
 * Chunk seals/opens are independent (counter-derived nonces, one fixed key, no
 * chaining), so a small window of them can run concurrently while output order
 * is preserved by draining a FIFO. On Node every `crypto.subtle` call runs on
 * the libuv threadpool (default size 4) and Chromium similarly dispatches to a
 * worker pool, so a window of 4 overlaps the per-call latency that otherwise
 * serializes the stream; on runtimes with synchronous-under-the-hood crypto
 * (workerd) it is harmless. Measured by bench:overlap (chunkedSeal c=1 vs c=4).
 */
const AEAD_PIPELINE_DEPTH = 4;

/** Settled result of an in-flight AEAD call: rejections are captured at issue
 * time so an abandoned window never surfaces an unhandled rejection, including
 * a window abandoned by a cancel. */
type SettledChunk = { ok: true; value: Uint8Array } | { ok: false; error: unknown };

function settle(p: Promise<Uint8Array>): Promise<SettledChunk> {
	return p.then(
		(value) => ({ ok: true, value }),
		(error: unknown) => ({ ok: false, error }),
	);
}

/**
 * Append-and-consume byte queue. Incoming chunks are held by reference, so
 * `append` is O(1) with no copy; bytes are copied only when a read spans a chunk
 * boundary, and a read contained in a single chunk returns a zero-copy subarray.
 * This keeps decoding O(n) even when the stream is delivered in many small reads
 * (the realistic TLS/TCP case) — the previous copy-the-remainder-per-append
 * approach was O(n·k) there.
 */
class StreamBuffer {
	readonly #chunks: Uint8Array[] = [];
	#headOff = 0; // bytes already consumed from chunks[0]
	#total = 0; // bytes currently available across all chunks

	get length(): number {
		return this.#total;
	}

	append(chunk: Uint8Array): void {
		if (chunk.length === 0) return;
		this.#chunks.push(chunk);
		this.#total += chunk.length;
	}

	/** First available byte without consuming (length must be >= 1). */
	firstByte(): number {
		return (this.#chunks[0] as Uint8Array)[this.#headOff] as number;
	}

	/** First `n` bytes as a contiguous array (must be <= length), without consuming. */
	peek(n: number): Uint8Array {
		if (n === 0) return EMPTY;
		const first = this.#chunks[0] as Uint8Array;
		return first.length - this.#headOff >= n
			? first.subarray(this.#headOff, this.#headOff + n) // zero copy: within one chunk
			: this.#collect(n);
	}

	/** First `n` bytes as a contiguous array (must be <= length), consuming them. */
	read(n: number): Uint8Array {
		const out = this.peek(n);
		this.skip(n);
		return out;
	}

	/** Drop the first `n` bytes (must be <= length). */
	skip(n: number): void {
		this.#total -= n;
		let rem = n;
		while (rem > 0) {
			const c = this.#chunks[0] as Uint8Array;
			const avail = c.length - this.#headOff;
			if (rem < avail) {
				this.#headOff += rem;
				return;
			}
			rem -= avail;
			this.#chunks.shift();
			this.#headOff = 0;
		}
	}

	#collect(n: number): Uint8Array {
		const out = new Uint8Array(n);
		let copied = 0;
		let off = this.#headOff;
		for (const c of this.#chunks) {
			if (copied >= n) break;
			const take = Math.min(c.length - off, n - copied);
			out.set(c.subarray(off, off + take), copied);
			copied += take;
			off = 0;
		}
		return out;
	}
}

// QUIC varint byte length from its first byte (1, 2, 4, or 8); mirrors quicvarint's read().
function varintLength(firstByte: number): number {
	return 1 << (firstByte >> 6);
}

/**
 * Create a TransformStream that encrypts plaintext chunks using HPKE sender context.
 *
 * Input: plaintext Uint8Array chunks (already chunked to maxChunkSize)
 * Output: framed ciphertext chunks (varint length + ciphertext)
 *
 * The transform handles:
 * - Sealing each chunk with HPKE (empty AAD for non-final, "final" for final)
 * - Framing with varint length prefix (0 for final chunk)
 *
 * Call controller.terminate() or let the stream end naturally to emit final chunk.
 */
export function createRequestEncryptTransform(
	senderContext: SenderContext,
	maxMessageSize: number = DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE,
): TransformStream<Uint8Array, Uint8Array> {
	const claim = createChunkBudget(maxMessageSize);
	let pendingChunk: Uint8Array | undefined;
	// Seals issued but not yet emitted, oldest first (all non-final chunks).
	// hpke's SenderContext.Seal claims its sequence number synchronously, so a
	// window of seals can run concurrently while output stays in order.
	const inflight: Array<Promise<SettledChunk>> = [];

	// Await the oldest in-flight seal and enqueue its frame (order-preserving).
	const emitOldest = async (
		controller: TransformStreamDefaultController<Uint8Array>,
	): Promise<boolean> => {
		const result = await (inflight.shift() as Promise<SettledChunk>);
		if (!result.ok) {
			controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
			return false;
		}
		// length prefix + ciphertext as two enqueues (avoids a copy)
		controller.enqueue(encodeVarint(result.value.length));
		controller.enqueue(result.value);
		return true;
	};

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			// Seal the previous chunk as non-final; emit once the window is full so
			// independent seals overlap.
			if (pendingChunk !== undefined) {
				claim(pendingChunk.length, false);
				inflight.push(settle(senderContext.Seal(pendingChunk)));
				if (inflight.length >= AEAD_PIPELINE_DEPTH && !(await emitOldest(controller))) return;
			}
			// Store current chunk as pending (might be final)
			pendingChunk = chunk;
		},

		async flush(controller) {
			// Seal the last chunk as final, draining the window in order first.
			claim((pendingChunk ?? EMPTY).length, true);
			const final = settle(senderContext.Seal(pendingChunk ?? EMPTY, FINAL_CHUNK_AAD));
			while (inflight.length > 0) {
				if (!(await emitOldest(controller))) return;
			}
			const result = await final;
			if (!result.ok) {
				controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
				return;
			}
			// Final chunk has length prefix 0
			controller.enqueue(encodeVarint(0));
			controller.enqueue(result.value);
		},
	});
}

/**
 * Decrypt length-prefixed ciphertext frames (draft-08), one per `openFrame`.
 *
 * The final chunk (length-0 marker) is delimited by end-of-stream, so it is
 * buffered and decrypted in flush() — decrypting earlier truncates it when it
 * arrives split across reads. `openFrame` owns any per-chunk state (e.g. a
 * counter) and may throw an {@link OHTTPError} to surface a specific code.
 */
function createFramedDecryptTransform(
	openFrame: (ciphertext: Uint8Array, isFinal: boolean) => Promise<Uint8Array>,
	maxFrameSize: number,
	maxMessageSize: number,
): TransformStream<Uint8Array, Uint8Array> {
	const claim = createChunkBudget(maxMessageSize);
	const buffer = new StreamBuffer();
	let inFinal = false;
	// Opens issued but not yet emitted, oldest first (all non-final frames).
	const inflight: Array<Promise<SettledChunk>> = [];

	// Await the oldest in-flight open and enqueue its plaintext (order-preserving).
	const emitOldest = async (
		controller: TransformStreamDefaultController<Uint8Array>,
	): Promise<boolean> => {
		const result = await (inflight.shift() as Promise<SettledChunk>);
		// A non-final chunk MUST NOT decrypt to zero-length plaintext (draft-08 Section 7.3).
		if (!result.ok || result.value.length === 0) {
			const e = result.ok ? undefined : result.error;
			controller.error(
				e instanceof OHTTPError ? e : new OHTTPError(OHTTPErrorCode.DecryptionFailed),
			);
			return false;
		}
		controller.enqueue(result.value);
		return true;
	};

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			buffer.append(chunk);

			if (!inFinal) {
				for (;;) {
					if (buffer.length < 1) break;
					const vlen = varintLength(buffer.firstByte());
					if (buffer.length < vlen) break; // varint itself incomplete

					let length: number;
					try {
						length = decodeVarint(buffer.peek(vlen)).value;
					} catch {
						controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
						return;
					}

					if (length === 0) {
						buffer.skip(vlen); // final marker; remaining bytes are the final chunk
						inFinal = true;
						break;
					}

					// `length` is the peer's claim: reject before buffering that much.
					if (length > maxFrameSize) {
						controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
						return;
					}

					const frameLen = vlen + length;
					if (buffer.length < frameLen) break; // frame incomplete, need more data

					// materialize exactly one frame (zero-copy when it sits in one read),
					// start its open immediately, and emit only once the window is full
					const frame = buffer.read(frameLen);
					const ciphertext = frame.subarray(vlen);
					if (ciphertext.length < AEAD_TAG_SIZE) {
						controller.error(new OHTTPError(OHTTPErrorCode.DecryptionFailed));
						return;
					}
					claim(ciphertext.length - AEAD_TAG_SIZE, false);
					inflight.push(settle(openFrame(ciphertext, false)));
					if (inflight.length >= AEAD_PIPELINE_DEPTH && !(await emitOldest(controller))) return;
				}
			}

			// The final chunk is delimited by end-of-stream, so it has no declared
			// length to bound it. Checking here covers both the marker arriving in
			// the same read as its payload and a payload spread over many reads.
			if (inFinal && buffer.length > maxFrameSize) {
				controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
			}
		},

		async flush(controller) {
			// The stream is only complete once a final (0-length prefix) chunk arrives;
			// ending without one is a truncated message (draft-08 Section 7.3).
			if (!inFinal) {
				controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
				return;
			}
			const ciphertext = buffer.read(buffer.length);
			if (ciphertext.length < AEAD_TAG_SIZE) {
				controller.error(new OHTTPError(OHTTPErrorCode.DecryptionFailed));
				return;
			}
			claim(ciphertext.length - AEAD_TAG_SIZE, true);
			const final = settle(openFrame(ciphertext, true));
			while (inflight.length > 0) {
				if (!(await emitOldest(controller))) return;
			}
			const result = await final;
			if (!result.ok) {
				const e = result.error;
				controller.error(
					e instanceof OHTTPError ? e : new OHTTPError(OHTTPErrorCode.DecryptionFailed),
				);
				return;
			}
			controller.enqueue(result.value);
		},
	});
}

/**
 * Create a TransformStream that decrypts framed request chunks using an HPKE
 * recipient context (the context owns its own sequence numbering).
 */
export function createRequestDecryptTransform(
	recipientContext: RecipientContext,
	maxFrameSize: number = DEFAULT_MAX_FRAME_SIZE,
	maxMessageSize: number = DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE,
): TransformStream<Uint8Array, Uint8Array> {
	return createFramedDecryptTransform(
		(ciphertext, isFinal) =>
			recipientContext.Open(ciphertext, isFinal ? FINAL_CHUNK_AAD : undefined),
		maxFrameSize,
		maxMessageSize,
	);
}

/**
 * Create a TransformStream that encrypts plaintext chunks for response.
 *
 * Input: plaintext Uint8Array chunks (already chunked to maxChunkSize)
 * Output: framed ciphertext chunks (varint length + ciphertext)
 *
 * Uses AEAD with counter-based nonces per draft-08 Section 6.2.
 */
export function createResponseEncryptTransform(
	aead: AeadImpl,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
	maxMessageSize: number = DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE,
): TransformStream<Uint8Array, Uint8Array> {
	const claim = createChunkBudget(maxMessageSize);
	let counter = 0;
	let pendingChunk: Uint8Array | undefined;
	// Seals issued but not yet emitted, oldest first (all non-final chunks).
	const inflight: Array<Promise<SettledChunk>> = [];

	// Await the oldest in-flight seal and enqueue its frame (order-preserving).
	const emitOldest = async (
		controller: TransformStreamDefaultController<Uint8Array>,
	): Promise<boolean> => {
		const result = await (inflight.shift() as Promise<SettledChunk>);
		if (!result.ok) {
			controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
			return false;
		}
		// length prefix + ciphertext as two enqueues (avoids a copy)
		controller.enqueue(encodeVarint(result.value.length));
		controller.enqueue(result.value);
		return true;
	};

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			// If we have a pending chunk, seal it as non-final; emit once the
			// window is full so independent seals overlap
			if (pendingChunk !== undefined) {
				claim(pendingChunk.length, false);
				if (counter >= MAX_CHUNKS) {
					controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
					return;
				}
				inflight.push(
					settle(sealResponseChunk(aead, aeadKey, baseNonce, counter++, pendingChunk, false)),
				);
				if (inflight.length >= AEAD_PIPELINE_DEPTH && !(await emitOldest(controller))) return;
			}
			pendingChunk = chunk;
		},

		async flush(controller) {
			if (counter >= MAX_CHUNKS) {
				controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
				return;
			}

			claim((pendingChunk ?? EMPTY).length, true);
			const final = settle(
				sealResponseChunk(aead, aeadKey, baseNonce, counter, pendingChunk ?? EMPTY, true),
			);
			while (inflight.length > 0) {
				if (!(await emitOldest(controller))) return;
			}
			const result = await final;
			if (!result.ok) {
				controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
				return;
			}
			// Final chunk has length prefix 0
			controller.enqueue(encodeVarint(0));
			controller.enqueue(result.value);
		},
	});
}

/**
 * Create a TransformStream that decrypts framed response ciphertext.
 *
 * Input: framed ciphertext (may be partial/streaming)
 * Output: decrypted plaintext Uint8Array chunks
 *
 * Uses AEAD with counter-based nonces per draft-08 Section 6.2.
 */
export function createResponseDecryptTransform(
	aead: AeadImpl,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
	maxFrameSize: number = DEFAULT_MAX_FRAME_SIZE,
	maxMessageSize: number = DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE,
): TransformStream<Uint8Array, Uint8Array> {
	let counter = 0;
	// The counter is claimed synchronously at call time: opens are pipelined, so
	// the next frame's open may start before this one's promise resolves.
	return createFramedDecryptTransform(
		(ciphertext, isFinal) => {
			if (counter >= MAX_CHUNKS) {
				return Promise.reject(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
			}
			return openResponseChunk(aead, aeadKey, baseNonce, counter++, ciphertext, isFinal);
		},
		maxFrameSize,
		maxMessageSize,
	);
}

/**
 * Create a TransformStream that chunks input into fixed-size pieces.
 *
 * Input: arbitrary Uint8Array chunks
 * Output: Uint8Array chunks of at most maxChunkSize bytes
 *
 * This is used to split large inputs before encryption.
 */
export function createChunkerTransform(
	maxChunkSize: number,
): TransformStream<Uint8Array, Uint8Array> {
	const buffer = new StreamBuffer();

	return new TransformStream<Uint8Array, Uint8Array>({
		transform(chunk, controller) {
			buffer.append(chunk);

			// emit views; input chunks are never mutated in place, so a downstream
			// consumer may safely hold one across its own async work
			while (buffer.length >= maxChunkSize) {
				controller.enqueue(buffer.read(maxChunkSize));
			}
		},

		flush(controller) {
			// Emit remaining data (may be empty, which is valid for final chunk)
			if (buffer.length > 0) {
				controller.enqueue(buffer.read(buffer.length));
			}
		},
	});
}
