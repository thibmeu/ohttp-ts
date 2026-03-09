/**
 * Streaming transforms for chunked OHTTP
 *
 * Provides TransformStream-based encryption/decryption for true streaming
 * of chunked OHTTP requests and responses.
 */

import type { CipherSuite, RecipientContext, SenderContext } from "hpke";
import { encode as encodeVarint } from "quicvarint";
import {
	type BHttpContentEvent,
	type BHttpEvent,
	type BHttpRequestPreambleEvent,
	BHttpRequestStreamEncoder,
	type BHttpResponsePreambleEvent,
	BHttpResponseStreamEncoder,
	BHttpStreamDecoder,
} from "./constants.js";
import {
	FINAL_CHUNK_AAD,
	type ParsedChunk,
	openResponseChunk,
	parseFramedChunk,
	sealResponseChunk,
} from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import { concat } from "./utils.js";

/**
 * Maximum chunks allowed per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
 */
const MAX_CHUNKS = 2 ** 32;

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
					const lengthBytes = encodeVarint(sealed.length);
					controller.enqueue(concat(lengthBytes, sealed));
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
			const finalChunk = pendingChunk ?? new Uint8Array(0);
			try {
				const sealed = await senderContext.Seal(finalChunk, FINAL_CHUNK_AAD);
				// Final chunk has length prefix 0
				const lengthBytes = encodeVarint(0);
				controller.enqueue(concat(lengthBytes, sealed));
			} catch {
				controller.error(new OHTTPError(OHTTPErrorCode.EncryptionFailed));
			}
		},
	});
}

/**
 * Create a TransformStream that decrypts framed ciphertext chunks using HPKE recipient context.
 *
 * Input: framed ciphertext (may be partial/streaming)
 * Output: decrypted plaintext Uint8Array chunks
 *
 * Handles buffering of partial frames and detects final chunk.
 */
export function createRequestDecryptTransform(
	recipientContext: RecipientContext,
): TransformStream<Uint8Array, Uint8Array> {
	let buffer = new Uint8Array(0);
	let finished = false;

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			if (finished) {
				controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
				return;
			}

			// Append to buffer
			buffer = concat(buffer, chunk);

			// Parse and decrypt complete frames
			while (buffer.length > 0) {
				let parsed: ParsedChunk | undefined;
				try {
					parsed = parseFramedChunk(buffer);
				} catch (e) {
					controller.error(e);
					return;
				}

				if (parsed === undefined) {
					// Need more data
					break;
				}

				try {
					const aad = parsed.isFinal ? FINAL_CHUNK_AAD : undefined;
					const plaintext = await recipientContext.Open(parsed.ciphertext, aad);
					controller.enqueue(plaintext);
				} catch {
					controller.error(new OHTTPError(OHTTPErrorCode.DecryptionFailed));
					return;
				}

				if (parsed.isFinal) {
					finished = true;
					buffer = new Uint8Array(0);
					break;
				}

				buffer = buffer.slice(parsed.bytesConsumed);
			}
		},

		flush(controller) {
			if (!finished && buffer.length > 0) {
				// Incomplete message
				controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
			}
		},
	});
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
	suite: CipherSuite,
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
						suite,
						aeadKey,
						baseNonce,
						counter,
						pendingChunk,
						false,
					);
					const lengthBytes = encodeVarint(sealed.length);
					controller.enqueue(concat(lengthBytes, sealed));
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

			const finalChunk = pendingChunk ?? new Uint8Array(0);
			try {
				const sealed = await sealResponseChunk(
					suite,
					aeadKey,
					baseNonce,
					counter,
					finalChunk,
					true,
				);
				// Final chunk has length prefix 0
				const lengthBytes = encodeVarint(0);
				controller.enqueue(concat(lengthBytes, sealed));
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
	suite: CipherSuite,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
): TransformStream<Uint8Array, Uint8Array> {
	let buffer = new Uint8Array(0);
	let counter = 0;
	let finished = false;

	return new TransformStream<Uint8Array, Uint8Array>({
		async transform(chunk, controller) {
			if (finished) {
				controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
				return;
			}

			if (counter >= MAX_CHUNKS) {
				controller.error(new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded));
				return;
			}

			// Append to buffer
			buffer = concat(buffer, chunk);

			// Parse and decrypt complete frames
			while (buffer.length > 0) {
				let parsed: ParsedChunk | undefined;
				try {
					parsed = parseFramedChunk(buffer);
				} catch (e) {
					controller.error(e);
					return;
				}

				if (parsed === undefined) {
					// Need more data
					break;
				}

				try {
					const plaintext = await openResponseChunk(
						suite,
						aeadKey,
						baseNonce,
						counter,
						parsed.ciphertext,
						parsed.isFinal,
					);
					controller.enqueue(plaintext);
					counter++;
				} catch {
					controller.error(new OHTTPError(OHTTPErrorCode.DecryptionFailed));
					return;
				}

				if (parsed.isFinal) {
					finished = true;
					buffer = new Uint8Array(0);
					break;
				}

				buffer = buffer.slice(parsed.bytesConsumed);
			}
		},

		flush(controller) {
			if (!finished && buffer.length > 0) {
				// Incomplete message
				controller.error(new OHTTPError(OHTTPErrorCode.InvalidMessage));
			}
		},
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
	let buffer = new Uint8Array(0);

	return new TransformStream<Uint8Array, Uint8Array>({
		transform(chunk, controller) {
			buffer = concat(buffer, chunk);

			// Emit full chunks
			while (buffer.length >= maxChunkSize) {
				controller.enqueue(buffer.slice(0, maxChunkSize));
				buffer = buffer.slice(maxChunkSize);
			}
		},

		flush(controller) {
			// Emit remaining data (may be empty, which is valid for final chunk)
			if (buffer.length > 0) {
				controller.enqueue(buffer);
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
				for (const event of events) {
					if (event.type === "content") {
						controller.enqueue(event.data);
						return; // Yield control after enqueuing
					} else if (event.type === "end") {
						sourceExhausted = true;
						controller.close();
						return;
					}
					// Ignore trailers for now
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
				for (const event of events) {
					if (event.type === "content") {
						controller.enqueue(event.data);
						return;
					} else if (event.type === "end") {
						sourceExhausted = true;
						controller.close();
						return;
					}
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
