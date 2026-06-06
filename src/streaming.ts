/**
 * Streaming transforms for chunked OHTTP
 *
 * Provides TransformStream-based encryption/decryption for true streaming
 * of chunked OHTTP requests and responses.
 */

import type { AEAD as AeadImpl, RecipientContext, SenderContext } from "hpke";
import { decode as decodeVarint, encode as encodeVarint } from "quicvarint";
import {
	type BHttpRequestPreambleEvent,
	BHttpRequestStreamEncoder,
	type BHttpResponsePreambleEvent,
	BHttpResponseStreamEncoder,
	BHttpStreamDecoder,
} from "./constants.js";
import { FINAL_CHUNK_AAD, openResponseChunk, sealResponseChunk } from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";

/**
 * Maximum chunks allowed per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
 */
const MAX_CHUNKS = 2 ** 32;

const EMPTY = new Uint8Array(0);

/**
 * Append-and-consume byte queue. Incoming chunks are held by reference, so
 * `append` is O(1) with no copy; bytes are copied only when a read spans a chunk
 * boundary, and a read contained in a single chunk returns a zero-copy subarray.
 * This keeps decoding O(n) even when the stream is delivered in many small reads
 * (the realistic TLS/TCP case) — the previous copy-the-remainder-per-append
 * approach was O(n·k) there.
 */
class StreamBuffer {
	private chunks: Uint8Array[] = [];
	private headOff = 0; // bytes already consumed from chunks[0]
	private total = 0; // bytes currently available across all chunks

	get length(): number {
		return this.total;
	}

	append(chunk: Uint8Array): void {
		if (chunk.length === 0) return;
		this.chunks.push(chunk);
		this.total += chunk.length;
	}

	/** First available byte without consuming (length must be >= 1). */
	firstByte(): number {
		return (this.chunks[0] as Uint8Array)[this.headOff] as number;
	}

	/** First `n` bytes as a contiguous array (must be <= length), without consuming. */
	peek(n: number): Uint8Array {
		if (n === 0) return EMPTY;
		const first = this.chunks[0] as Uint8Array;
		return first.length - this.headOff >= n
			? first.subarray(this.headOff, this.headOff + n) // zero copy: within one chunk
			: this.collect(n);
	}

	/** First `n` bytes as a contiguous array (must be <= length), consuming them. */
	read(n: number): Uint8Array {
		const out = this.peek(n);
		this.skip(n);
		return out;
	}

	/** Drop the first `n` bytes (must be <= length). */
	skip(n: number): void {
		this.total -= n;
		let rem = n;
		while (rem > 0) {
			const c = this.chunks[0] as Uint8Array;
			const avail = c.length - this.headOff;
			if (rem < avail) {
				this.headOff += rem;
				return;
			}
			rem -= avail;
			this.chunks.shift();
			this.headOff = 0;
		}
	}

	private collect(n: number): Uint8Array {
		const out = new Uint8Array(n);
		let copied = 0;
		let off = this.headOff;
		for (const c of this.chunks) {
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
): TransformStream<Uint8Array, Uint8Array> {
	let pendingChunk: Uint8Array | undefined;

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			// If we have a pending chunk, seal it as non-final
			if (pendingChunk !== undefined) {
				try {
					const sealed = await senderContext.Seal(pendingChunk);
					// length prefix + ciphertext as two enqueues (avoids a copy)
					controller.enqueue(encodeVarint(sealed.length));
					controller.enqueue(sealed);
				} catch {
					controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
					return;
				}
			}
			// Store current chunk as pending (might be final)
			pendingChunk = chunk;
		},

		async flush(controller) {
			// Seal the last chunk as final
			const finalChunk = pendingChunk ?? EMPTY;
			try {
				const sealed = await senderContext.Seal(finalChunk, FINAL_CHUNK_AAD);
				// Final chunk has length prefix 0
				controller.enqueue(encodeVarint(0));
				controller.enqueue(sealed);
			} catch {
				controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
			}
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
): TransformStream<Uint8Array, Uint8Array> {
	const buffer = new StreamBuffer();
	let inFinal = false;

	const open = async (
		controller: TransformStreamDefaultController<Uint8Array>,
		ciphertext: Uint8Array,
		isFinal: boolean,
	): Promise<boolean> => {
		try {
			controller.enqueue(await openFrame(ciphertext, isFinal));
			return true;
		} catch (e) {
			controller.error(
				e instanceof OHTTPError ? e : new OHTTPError(OHTTPErrorCode.DecryptionFailed),
			);
			return false;
		}
	};

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			buffer.append(chunk);
			if (inFinal) return; // accumulate the final ciphertext until flush

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

				const frameLen = vlen + length;
				if (buffer.length < frameLen) break; // frame incomplete, need more data

				// materialize exactly one frame (zero-copy when it sits in one read)
				const frame = buffer.read(frameLen);
				if (!(await open(controller, frame.subarray(vlen), false))) return;
			}
		},

		async flush(controller) {
			if (!inFinal) {
				if (buffer.length > 0) {
					controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
				}
				return;
			}
			await open(controller, buffer.read(buffer.length), true);
		},
	});
}

/**
 * Create a TransformStream that decrypts framed request chunks using an HPKE
 * recipient context (the context owns its own sequence numbering).
 */
export function createRequestDecryptTransform(
	recipientContext: RecipientContext,
): TransformStream<Uint8Array, Uint8Array> {
	return createFramedDecryptTransform((ciphertext, isFinal) =>
		recipientContext.Open(ciphertext, isFinal ? FINAL_CHUNK_AAD : undefined),
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
): TransformStream<Uint8Array, Uint8Array> {
	let counter = 0;
	let pendingChunk: Uint8Array | undefined;

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			if (counter >= MAX_CHUNKS) {
				controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
				return;
			}

			// If we have a pending chunk, seal it as non-final
			if (pendingChunk !== undefined) {
				try {
					const sealed = await sealResponseChunk(
						aead,
						aeadKey,
						baseNonce,
						counter,
						pendingChunk,
						false,
					);
					controller.enqueue(encodeVarint(sealed.length));
					controller.enqueue(sealed);
					counter++;
				} catch {
					controller.error(new OHTTPError(OHTTPErrorCode.DecryptionFailed));
					return;
				}
			}
			pendingChunk = chunk;
		},

		async flush(controller) {
			if (counter >= MAX_CHUNKS) {
				controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
				return;
			}

			const finalChunk = pendingChunk ?? EMPTY;
			try {
				const sealed = await sealResponseChunk(aead, aeadKey, baseNonce, counter, finalChunk, true);
				// Final chunk has length prefix 0
				controller.enqueue(encodeVarint(0));
				controller.enqueue(sealed);
			} catch {
				controller.error(new OHTTPError(OHTTPErrorCode.DecryptionFailed));
			}
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
): TransformStream<Uint8Array, Uint8Array> {
	let counter = 0;
	return createFramedDecryptTransform(async (ciphertext, isFinal) => {
		if (counter >= MAX_CHUNKS) {
			throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
		}
		const plaintext = await openResponseChunk(
			aead,
			aeadKey,
			baseNonce,
			counter,
			ciphertext,
			isFinal,
		);
		counter++;
		return plaintext;
	});
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

// ============================================================================
// BHTTP Streaming Bridges
// ============================================================================

/**
 * Result of decoding a BHTTP request stream.
 * The preamble (method, headers) is extracted; body streams separately.
 */
export interface DecodedBHttpRequest {
	readonly method: string;
	readonly scheme: string;
	readonly authority: string;
	readonly path: string;
	readonly headers: Headers;
	/** Stream of body chunks (may be empty for bodyless requests) */
	readonly body: ReadableStream<Uint8Array>;
}

/**
 * Result of decoding a BHTTP response stream.
 * The preamble (status, headers) is extracted; body streams separately.
 */
export interface DecodedBHttpResponse {
	readonly status: number;
	readonly headers: Headers;
	/** Stream of body chunks (may be empty for bodyless responses) */
	readonly body: ReadableStream<Uint8Array>;
}

/**
 * Decode a BHTTP request from a stream of plaintext bytes.
 *
 * Returns a promise that resolves once the preamble (method, headers) is parsed.
 * The body is returned as a ReadableStream that yields content chunks.
 *
 * @param source - Stream of decrypted BHTTP bytes
 * @returns Promise resolving to request metadata and body stream
 */
export async function decodeBHttpRequestStream(
	source: ReadableStream<Uint8Array>,
): Promise<DecodedBHttpRequest> {
	const decoder = new BHttpStreamDecoder();
	const reader = source.getReader();

	let preamble: BHttpRequestPreambleEvent | undefined;
	const pendingBodyChunks: Uint8Array[] = [];
	let sourceExhausted = false;

	// Read until we have the preamble
	while (preamble === undefined) {
		const { done, value } = await reader.read();
		if (done) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		const events = decoder.push(value);
		for (const event of events) {
			if (event.type === "request-preamble") {
				preamble = event;
			} else if (event.type === "content") {
				// Buffer body chunks that arrived with preamble
				pendingBodyChunks.push(event.data);
			}
		}
	}

	// Create body stream that continues reading from source
	const body = new ReadableStream<Uint8Array>({
		start(controller) {
			// Enqueue any chunks we already received
			for (const chunk of pendingBodyChunks) {
				controller.enqueue(chunk);
			}
		},

		async pull(controller) {
			if (sourceExhausted) {
				return;
			}

			// Read more from source until we get content or end
			while (true) {
				const { done, value } = await reader.read();
				if (done) {
					sourceExhausted = true;
					try {
						decoder.end();
					} catch {
						controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
						return;
					}
					controller.close();
					return;
				}

				const events = decoder.push(value);
				let enqueuedContent = false;
				for (const event of events) {
					if (event.type === "content") {
						controller.enqueue(event.data);
						enqueuedContent = true;
					} else if (event.type === "end") {
						sourceExhausted = true;
						controller.close();
						return;
					}
					// Ignore trailers for now
				}
				// Yield control after enqueuing all content from this read
				if (enqueuedContent) {
					return;
				}
			}
		},

		cancel() {
			reader.cancel();
		},
	});

	return {
		method: preamble.method,
		scheme: preamble.scheme,
		authority: preamble.authority,
		path: preamble.path,
		headers: preamble.headers,
		body,
	};
}

/**
 * Decode a BHTTP response from a stream of plaintext bytes.
 *
 * Returns a promise that resolves once the preamble (status, headers) is parsed.
 * The body is returned as a ReadableStream that yields content chunks.
 *
 * @param source - Stream of decrypted BHTTP bytes
 * @returns Promise resolving to response metadata and body stream
 */
export async function decodeBHttpResponseStream(
	source: ReadableStream<Uint8Array>,
): Promise<DecodedBHttpResponse> {
	const decoder = new BHttpStreamDecoder();
	const reader = source.getReader();

	let preamble: BHttpResponsePreambleEvent | undefined;
	const pendingBodyChunks: Uint8Array[] = [];
	let sourceExhausted = false;

	// Read until we have the preamble
	while (preamble === undefined) {
		const { done, value } = await reader.read();
		if (done) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		const events = decoder.push(value);
		for (const event of events) {
			if (event.type === "response-preamble") {
				preamble = event;
			} else if (event.type === "content") {
				pendingBodyChunks.push(event.data);
			}
			// Ignore informational responses for now
		}
	}

	// Create body stream
	const body = new ReadableStream<Uint8Array>({
		start(controller) {
			for (const chunk of pendingBodyChunks) {
				controller.enqueue(chunk);
			}
		},

		async pull(controller) {
			if (sourceExhausted) {
				return;
			}

			while (true) {
				const { done, value } = await reader.read();
				if (done) {
					sourceExhausted = true;
					try {
						decoder.end();
					} catch {
						controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
						return;
					}
					controller.close();
					return;
				}

				const events = decoder.push(value);
				let enqueuedContent = false;
				for (const event of events) {
					if (event.type === "content") {
						controller.enqueue(event.data);
						enqueuedContent = true;
					} else if (event.type === "end") {
						sourceExhausted = true;
						controller.close();
						return;
					}
				}
				// Yield control after enqueuing all content from this read
				if (enqueuedContent) {
					return;
				}
			}
		},

		cancel() {
			reader.cancel();
		},
	});

	return {
		status: preamble.status,
		headers: preamble.headers,
		body,
	};
}

/**
 * Encode an HTTP Request to a BHTTP byte stream.
 *
 * The returned stream yields BHTTP-encoded bytes (indeterminate-length format).
 *
 * @param request - The Request to encode
 * @returns ReadableStream of BHTTP bytes
 */
export function encodeBHttpRequestStream(request: Request): ReadableStream<Uint8Array> {
	const url = new URL(request.url);
	const encoder = new BHttpRequestStreamEncoder();

	return new ReadableStream<Uint8Array>({
		async start(controller) {
			// Encode and enqueue preamble
			const preamble = encoder.encodePreamble(
				request.method,
				url.protocol.replace(":", ""),
				url.host,
				url.pathname + url.search,
				request.headers,
			);
			controller.enqueue(preamble);

			// Stream body if present
			const body = request.body;
			if (body !== null) {
				const reader = body.getReader();
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value.length > 0) {
						controller.enqueue(encoder.encodeContentChunk(value));
					}
				}
			}

			// Encode end
			controller.enqueue(encoder.encodeEnd());
			controller.close();
		},
	});
}

/**
 * Encode an HTTP Response to a BHTTP byte stream.
 *
 * The returned stream yields BHTTP-encoded bytes (indeterminate-length format).
 *
 * @param response - The Response to encode
 * @returns ReadableStream of BHTTP bytes
 */
export function encodeBHttpResponseStream(response: Response): ReadableStream<Uint8Array> {
	const encoder = new BHttpResponseStreamEncoder();

	return new ReadableStream<Uint8Array>({
		async start(controller) {
			// Encode and enqueue preamble
			const preamble = encoder.encodePreamble(response.status, response.headers);
			controller.enqueue(preamble);

			// Stream body if present
			const body = response.body;
			if (body !== null) {
				const reader = body.getReader();
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value.length > 0) {
						controller.enqueue(encoder.encodeContentChunk(value));
					}
				}
			}

			// Encode end
			controller.enqueue(encoder.encodeEnd());
			controller.close();
		},
	});
}
