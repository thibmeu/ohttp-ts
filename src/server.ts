import type { RecipientContext } from "hpke";
import { MediaType, bhttp } from "./constants.js";
import {
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	FINAL_CHUNK_AAD,
	type ServerEncapsulationContext,
	buildRequestInfo,
	decapsulateRequest,
	deriveChunkedResponseKeys,
	encapsulateResponse,
	frameChunk,
	getEncLength,
	getResponseNonceLength,
	parseFramedChunk,
	parseRequestHeader,
	sealResponseChunk,
} from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import type { KeyConfigWithPrivate } from "./keyConfig.js";
import {
	createChunkerTransform,
	createRequestDecryptTransform,
	createResponseEncryptTransform,
	decodeBHttpRequestStream,
	encodeBHttpResponseStream,
} from "./streaming.js";
import { concat, toArrayBuffer } from "./utils.js";

/**
 * Options for OHTTP server
 */
export interface OHTTPServerOptions {
	/** Custom request label (default: "message/bhttp request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp response") */
	readonly responseLabel?: string;
}

/**
 * Options for chunked OHTTP server
 */
export interface ChunkedOHTTPServerOptions {
	/** Custom request label (default: "message/bhttp chunked request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp chunked response") */
	readonly responseLabel?: string;
	/** Maximum chunk size in bytes (default: 16384) */
	readonly maxChunkSize?: number;
}

/**
 * Result of decapsulating a request (bytes API)
 */
export interface DecapsulatedRequest {
	/** The decrypted binary HTTP request */
	readonly request: Uint8Array;
	/** Context needed to encrypt the response */
	readonly context: ServerContext;
}

/**
 * Result of decapsulating a request (Request/Response API)
 */
export interface DecapsulatedHttpRequest {
	/** The decrypted HTTP request */
	readonly request: Request;
	/** Context needed to encrypt the response */
	readonly context: HttpServerContext;
}

/**
 * Server context for encrypting responses (bytes API)
 */
export interface ServerContext {
	/** Encrypt a response */
	encryptResponse(response: Uint8Array): Promise<Uint8Array>;
}

/**
 * Server context for encrypting responses (Request/Response API)
 */
export interface HttpServerContext {
	/** Encrypt a response and return as OHTTP Response */
	encapsulateResponse(response: Response): Promise<Response>;
}

/**
 * Context for streaming chunked requests (server-side decryption)
 */
export interface ChunkedServerRequestContext {
	/** The key config used for decryption */
	readonly keyConfig: KeyConfigWithPrivate;
	/** Open a non-final chunk */
	openChunk(ciphertext: Uint8Array): Promise<Uint8Array>;
	/** Open the final chunk */
	openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array>;
	/** Create a response context for encrypting the response */
	createResponseContext(): Promise<ChunkedServerResponseContext>;
	/** @internal HPKE recipient context for streaming transforms */
	readonly _recipientContext: RecipientContext;
	/** @internal Encapsulated secret for response key derivation */
	readonly _enc: Uint8Array;
}

/**
 * Context for streaming chunked responses (server-side encryption)
 */
export interface ChunkedServerResponseContext {
	/** The response nonce (must be sent first) */
	readonly responseNonce: Uint8Array;
	/** Seal a non-final chunk */
	sealChunk(chunk: Uint8Array): Promise<Uint8Array>;
	/** Seal the final chunk */
	sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array>;
}

/**
 * Result of decapsulating a chunked HTTP request (Request/Response API)
 */
export interface DecapsulatedChunkedHttpRequest {
	/** The decrypted HTTP request */
	readonly request: Request;
	/** Context needed to encrypt the chunked response */
	readonly context: ChunkedHttpServerContext;
}

/**
 * Server context for encrypting chunked responses (Request/Response API)
 */
export interface ChunkedHttpServerContext {
	/** Encrypt a response and return as chunked OHTTP Response */
	encapsulateResponse(response: Response): Promise<Response>;
}

/**
 * OHTTP Server (Gateway) for decapsulating requests
 */
export class OHTTPServer {
	private readonly keyConfigs: readonly KeyConfigWithPrivate[];
	private readonly requestLabel: string;
	private readonly responseLabel: string;

	/**
	 * Create an OHTTP server
	 *
	 * @param keyConfigs - Array of key configurations with private keys
	 * @param options - Optional configuration
	 */
	constructor(keyConfigs: readonly KeyConfigWithPrivate[], options: OHTTPServerOptions = {}) {
		this.keyConfigs = keyConfigs;
		this.requestLabel = options.requestLabel ?? DEFAULT_REQUEST_LABEL;
		this.responseLabel = options.responseLabel ?? DEFAULT_RESPONSE_LABEL;
	}

	/**
	 * Decapsulate an encrypted request (low-level API)
	 *
	 * @param encapsulatedRequest - The encapsulated request bytes
	 * @returns The decrypted request bytes and context for encrypting the response
	 */
	async decapsulate(encapsulatedRequest: Uint8Array): Promise<DecapsulatedRequest> {
		const ctx = await decapsulateRequest(encapsulatedRequest, this.keyConfigs, this.requestLabel);

		const responseLabel = this.responseLabel;
		const context: ServerContext = {
			async encryptResponse(response: Uint8Array): Promise<Uint8Array> {
				// Generate random response nonce
				const nonceLength = getResponseNonceLength(ctx.suite);
				const responseNonce = crypto.getRandomValues(new Uint8Array(nonceLength));
				return encapsulateResponse(ctx, response, responseNonce, responseLabel);
			},
		};

		return {
			request: ctx.request,
			context,
		};
	}

	/**
	 * Decapsulate an OHTTP Request (high-level API)
	 *
	 * Decrypts and decodes Binary HTTP to return the inner Request.
	 *
	 * @param request - The OHTTP request from the relay
	 * @returns The decrypted inner Request and context for encapsulating the response
	 */
	async decapsulateRequest(request: Request): Promise<DecapsulatedHttpRequest> {
		// Validate content type
		const contentType = request.headers.get("content-type");
		if (contentType !== MediaType.REQUEST) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Read and decrypt
		const encapsulatedRequest = new Uint8Array(await request.arrayBuffer());
		const { request: binaryRequest, context: bytesContext } =
			await this.decapsulate(encapsulatedRequest);

		// Decode Binary HTTP to Request
		let innerRequest: Request;
		try {
			innerRequest = bhttp.decoder.decodeRequest(binaryRequest);
		} catch {
			// Wrap bhttp errors as opaque DecryptionFailed to prevent info leak
			throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
		}

		// Create HTTP context
		const context: HttpServerContext = {
			async encapsulateResponse(response: Response): Promise<Response> {
				// Encode response to Binary HTTP
				let binaryResponse: Uint8Array;
				try {
					binaryResponse = await bhttp.encoder.encodeResponse(response);
				} catch {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Encrypt
				const encapsulatedResponse = await bytesContext.encryptResponse(binaryResponse);

				// Return as OHTTP response
				return new Response(toArrayBuffer(encapsulatedResponse), {
					status: 200,
					headers: {
						"Content-Type": MediaType.RESPONSE,
					},
				});
			},
		};

		return { request: innerRequest, context };
	}
}

/**
 * Chunked OHTTP Server for streaming requests/responses (draft-ietf-ohai-chunked-ohttp-08)
 */
export class ChunkedOHTTPServer {
	private readonly keyConfigs: readonly KeyConfigWithPrivate[];
	private readonly requestLabel: string;
	private readonly responseLabel: string;
	readonly maxChunkSize: number;

	/**
	 * Create a chunked OHTTP server
	 *
	 * @param keyConfigs - Array of key configurations with private keys
	 * @param options - Optional configuration
	 */
	constructor(
		keyConfigs: readonly KeyConfigWithPrivate[],
		options: ChunkedOHTTPServerOptions = {},
	) {
		this.keyConfigs = keyConfigs;
		this.requestLabel = options.requestLabel ?? CHUNKED_REQUEST_LABEL;
		this.responseLabel = options.responseLabel ?? CHUNKED_RESPONSE_LABEL;
		this.maxChunkSize = options.maxChunkSize ?? DEFAULT_MAX_CHUNK_SIZE;
	}

	/**
	 * Create a streaming request context from the encapsulated header
	 *
	 * Use this for incremental request processing:
	 * 1. Parse header (first 7 + Nenc bytes)
	 * 2. For each chunk: await ctx.openChunk(ciphertext) or ctx.openFinalChunk(ciphertext)
	 */
	async createRequestContext(encapsulatedHeader: Uint8Array): Promise<ChunkedServerRequestContext> {
		// Parse header
		const { header, offset } = parseRequestHeader(encapsulatedHeader);

		// Verify we have the full header
		if (encapsulatedHeader.length < offset) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Find matching key config
		const keyConfig = this.keyConfigs.find((k) => k.keyId === header.keyId);
		if (keyConfig === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnknownKeyId);
		}

		// Verify KEM matches
		if (keyConfig.kemId !== header.kemId) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		// Verify symmetric algorithms
		const supportedAlgo = keyConfig.symmetricAlgorithms.find(
			(a) => a.kdfId === header.kdfId && a.aeadId === header.aeadId,
		);
		if (supportedAlgo === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		// Build info string
		const info = buildRequestInfo(
			header.keyId,
			header.kemId,
			header.kdfId,
			header.aeadId,
			this.requestLabel,
		);

		// Setup recipient context
		let recipientContext: RecipientContext;
		try {
			recipientContext = await keyConfig.suite.SetupRecipient(keyConfig.keyPair, header.enc, {
				info,
			});
		} catch {
			throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
		}

		const suite = keyConfig.suite;
		const enc = header.enc;
		const responseLabel = this.responseLabel;

		return {
			keyConfig,
			_recipientContext: recipientContext,
			_enc: enc,

			async openChunk(ciphertext: Uint8Array): Promise<Uint8Array> {
				try {
					return await recipientContext.Open(ciphertext);
				} catch {
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}
			},

			async openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array> {
				try {
					return await recipientContext.Open(ciphertext, FINAL_CHUNK_AAD);
				} catch {
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}
			},

			async createResponseContext(): Promise<ChunkedServerResponseContext> {
				// Generate random response nonce
				const nonceLength = getResponseNonceLength(suite);
				const responseNonce = crypto.getRandomValues(new Uint8Array(nonceLength));

				// Derive key material
				const { aeadKey, aeadNonce } = await deriveChunkedResponseKeys(
					suite,
					recipientContext,
					enc,
					responseNonce,
					responseLabel,
				);

				let counter = 0;
				// Max chunks: 2^32 per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
				const maxChunks = 2 ** 32;

				return {
					responseNonce,

					async sealChunk(chunk: Uint8Array): Promise<Uint8Array> {
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						const ct = await sealResponseChunk(suite, aeadKey, aeadNonce, counter, chunk, false);
						counter++;
						return ct;
					},

					async sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array> {
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						return sealResponseChunk(suite, aeadKey, aeadNonce, counter, chunk, true);
					},
				};
			},
		};
	}

	/**
	 * Decapsulate a complete chunked request
	 *
	 * Convenience method that parses and decrypts all request chunks.
	 */
	async decapsulate(encapsulatedRequest: Uint8Array): Promise<{
		request: Uint8Array;
		keyConfig: KeyConfigWithPrivate;
		createResponseContext: () => Promise<ChunkedServerResponseContext>;
	}> {
		// Parse header to get offset
		const { offset: headerOffset } = parseRequestHeader(encapsulatedRequest);
		const header = encapsulatedRequest.slice(0, headerOffset);

		const ctx = await this.createRequestContext(header);

		// Parse and decrypt all chunks
		const requestChunks: Uint8Array[] = [];
		let data = encapsulatedRequest.slice(headerOffset);

		while (data.length > 0) {
			const parsed = parseFramedChunk(data);
			if (parsed === undefined) {
				throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
			}

			if (parsed.isFinal) {
				const chunk = await ctx.openFinalChunk(parsed.ciphertext);
				requestChunks.push(chunk);
				break;
			}

			const chunk = await ctx.openChunk(parsed.ciphertext);
			requestChunks.push(chunk);
			data = data.slice(parsed.bytesConsumed);
		}

		return {
			request: concat(...requestChunks),
			keyConfig: ctx.keyConfig,
			createResponseContext: () => ctx.createResponseContext(),
		};
	}

	/**
	 * Encapsulate a complete chunked response
	 *
	 * Convenience method that splits response into chunks.
	 */
	async encapsulateResponse(
		responseContext: ChunkedServerResponseContext,
		response: Uint8Array,
	): Promise<Uint8Array> {
		const chunks: Uint8Array[] = [responseContext.responseNonce];

		// Split response into chunks
		let offset = 0;
		while (offset < response.length) {
			const remaining = response.length - offset;
			const isLast = remaining <= this.maxChunkSize;
			const chunkSize = Math.min(remaining, this.maxChunkSize);
			const chunk = response.slice(offset, offset + chunkSize);
			offset += chunkSize;

			if (isLast) {
				const sealed = await responseContext.sealFinalChunk(chunk);
				chunks.push(frameChunk(sealed, true));
			} else {
				const sealed = await responseContext.sealChunk(chunk);
				chunks.push(frameChunk(sealed, false));
			}
		}

		// Handle empty response
		if (response.length === 0) {
			const sealed = await responseContext.sealFinalChunk(new Uint8Array(0));
			chunks.push(frameChunk(sealed, true));
		}

		return concat(...chunks);
	}

	/**
	 * Decapsulate a chunked OHTTP Request (high-level streaming API)
	 *
	 * Decrypts and decodes streaming Binary HTTP to return the inner Request.
	 * The request body streams through without full buffering.
	 *
	 * @param request - The chunked OHTTP request from the relay
	 * @returns The decrypted inner Request (with streaming body) and context for encapsulating the response
	 */
	async decapsulateRequest(request: Request): Promise<DecapsulatedChunkedHttpRequest> {
		// Validate content type
		const contentType = request.headers.get("content-type");
		if (contentType !== MediaType.CHUNKED_REQUEST) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		const requestBody = request.body;
		if (requestBody === null) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		const reader = requestBody.getReader();
		let buffer = new Uint8Array(0);

		// Read until we have the header (7 bytes + Nenc)
		// We need at least 7 bytes to know the KEM ID, then we can compute header size
		while (buffer.length < 7) {
			const { done, value } = await reader.read();
			if (done) {
				throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
			}
			buffer = concat(buffer, value);
		}

		// Parse header to get KEM ID and compute full header size
		const kemId = ((buffer[1] ?? 0) << 8) | (buffer[2] ?? 0);
		const encLength = getEncLength(kemId);
		const headerSize = 7 + encLength;

		// Read until we have the full header
		while (buffer.length < headerSize) {
			const { done, value } = await reader.read();
			if (done) {
				throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
			}
			buffer = concat(buffer, value);
		}

		const headerBytes = buffer.slice(0, headerSize);
		const remainder = buffer.slice(headerSize);

		// Create request context from header
		const requestCtx = await this.createRequestContext(headerBytes);

		// Create decrypt transform
		const decryptTransform = createRequestDecryptTransform(requestCtx._recipientContext);

		// Create a stream from remainder + rest of request body
		const ciphertextStream = new ReadableStream<Uint8Array>({
			async start(controller) {
				// Enqueue any buffered remainder
				if (remainder.length > 0) {
					controller.enqueue(remainder);
				}

				// Continue reading from original stream
				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						controller.enqueue(value);
					}
				} finally {
					reader.releaseLock();
				}
				controller.close();
			},
		});

		// Decrypt stream
		const plaintextStream = ciphertextStream.pipeThrough(decryptTransform);

		// Decode BHTTP request
		const decoded = await decodeBHttpRequestStream(plaintextStream);

		// Build Request with streaming body
		// Note: GET/HEAD requests must not have a body per HTTP semantics
		const url = `${decoded.scheme}://${decoded.authority}${decoded.path}`;
		const bodylessMethod =
			decoded.method.toUpperCase() === "GET" || decoded.method.toUpperCase() === "HEAD";
		const innerRequest = new Request(url, {
			method: decoded.method,
			headers: decoded.headers,
			body: bodylessMethod ? null : decoded.body,
			// @ts-expect-error - duplex required for streaming request bodies in Node.js
			duplex: "half",
		});

		const suite = requestCtx.keyConfig.suite;
		const maxChunkSize = this.maxChunkSize;
		const responseLabel = this.responseLabel;

		// Create context for encapsulating response (streaming)
		const context: ChunkedHttpServerContext = {
			async encapsulateResponse(response: Response): Promise<Response> {
				// Generate response nonce
				const nonceLength = getResponseNonceLength(suite);
				const responseNonce = crypto.getRandomValues(new Uint8Array(nonceLength));

				// Derive response keys
				const { aeadKey, aeadNonce } = await deriveChunkedResponseKeys(
					suite,
					requestCtx._recipientContext,
					requestCtx._enc,
					responseNonce,
					responseLabel,
				);

				// Encode response to BHTTP stream
				const bhttpStream = encodeBHttpResponseStream(response);

				// Create the encryption pipeline
				const chunkerTransform = createChunkerTransform(maxChunkSize);
				const encryptTransform = createResponseEncryptTransform(suite, aeadKey, aeadNonce);

				// Pipe through transforms
				const encryptedStream = bhttpStream
					.pipeThrough(chunkerTransform)
					.pipeThrough(encryptTransform);

				// Create output stream that prepends response nonce
				const finalStream = new ReadableStream<Uint8Array>({
					async start(controller) {
						controller.enqueue(responseNonce);

						const streamReader = encryptedStream.getReader();
						try {
							while (true) {
								const { done, value } = await streamReader.read();
								if (done) break;
								controller.enqueue(value);
							}
						} finally {
							streamReader.releaseLock();
						}
						controller.close();
					},
				});

				return new Response(finalStream, {
					status: 200,
					headers: {
						"Content-Type": MediaType.CHUNKED_RESPONSE,
					},
				});
			},
		};

		return { request: innerRequest, context };
	}
}
