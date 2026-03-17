import type { CipherSuite, SenderContext } from "hpke";
import { bhttp, MediaType } from "./constants.js";
import {
	buildRequestHeader,
	buildRequestInfo,
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	decapsulateResponse,
	deriveChunkedResponseKeys,
	encapsulateRequest,
	FINAL_CHUNK_AAD,
	frameChunk,
	getResponseNonceLength,
	openResponseChunk,
	parseFramedChunk,
} from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import {
	type AeadId,
	isValidAeadId,
	isValidKdfId,
	type KdfId,
	type KeyConfig,
} from "./keyConfig.js";
import {
	createChunkerTransform,
	createRequestEncryptTransform,
	createResponseDecryptTransform,
	decodeBHttpResponseStream,
	encodeBHttpRequestStream,
} from "./streaming.js";
import { concat, toArrayBuffer } from "./utils.js";

/**
 * Options for OHTTP client
 */
export interface OHTTPClientOptions {
	/** Custom request label (default: "message/bhttp request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp response") */
	readonly responseLabel?: string;
}

/**
 * Options for chunked OHTTP client
 */
export interface ChunkedOHTTPClientOptions {
	/** Custom request label (default: "message/bhttp chunked request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp chunked response") */
	readonly responseLabel?: string;
	/** Maximum chunk size in bytes (default: 16384) */
	readonly maxChunkSize?: number;
}

/**
 * Result of encapsulating a request (bytes API)
 */
export interface EncapsulatedRequest {
	/** The encapsulated request bytes */
	readonly encapsulatedRequest: Uint8Array;
	/** Context needed to decrypt the response */
	readonly context: ClientContext;
}

/**
 * Result of encapsulating a request (Request/Response API)
 *
 * The `init` object is a valid `RequestInit` containing:
 * - method: "POST"
 * - headers: { "Content-Type": "message/ohttp-req" }
 * - body: ArrayBuffer (encapsulated request)
 *
 * Usage: `fetch(relayUrl, init)` or `new Request(relayUrl, init)`
 */
export interface EncapsulatedRequestInit {
	/** RequestInit for fetch() - POST with Content-Type: message/ohttp-req */
	readonly init: RequestInit;
	/** Context needed to decrypt the response */
	readonly context: HttpClientContext;
}

/**
 * Client context for decrypting responses (bytes API)
 */
export interface ClientContext {
	/** Decrypt an encapsulated response */
	decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array>;
}

/**
 * Client context for decrypting responses (Request/Response API)
 */
export interface HttpClientContext {
	/** Decrypt an encapsulated response and decode to HTTP Response */
	decapsulateResponse(response: Response): Promise<Response>;
}

/**
 * Context for streaming chunked requests (client-side)
 */
export interface ChunkedRequestContext {
	/** The request header bytes (must be sent first) */
	readonly header: Uint8Array;
	/** Seal a non-final chunk */
	sealChunk(chunk: Uint8Array): Promise<Uint8Array>;
	/** Seal the final chunk */
	sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array>;
	/** Create a response context after receiving the response nonce */
	createResponseContext(responseNonce: Uint8Array): Promise<ChunkedResponseContext>;
	/** @internal HPKE sender context for streaming transforms */
	readonly _senderContext: SenderContext;
	/** @internal Encapsulated secret for response key derivation */
	readonly _enc: Uint8Array;
}

/**
 * Context for streaming chunked responses (client-side decryption)
 */
export interface ChunkedResponseContext {
	/** Open a non-final chunk */
	openChunk(ciphertext: Uint8Array): Promise<Uint8Array>;
	/** Open the final chunk */
	openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array>;
}

/**
 * Result of encapsulating a chunked HTTP request (Request/Response API)
 *
 * The `init` object is a valid `RequestInit` containing:
 * - method: "POST"
 * - headers: { "Content-Type": "message/ohttp-chunked-req" }
 * - body: ReadableStream (streaming encapsulated request)
 * - duplex: "half" (required for streaming bodies in Node.js/Workers)
 *
 * Usage: `fetch(relayUrl, init)` or `new Request(relayUrl, init)`
 */
export interface EncapsulatedChunkedRequestInit {
	/** RequestInit for fetch() - POST with streaming body and Content-Type: message/ohttp-chunked-req */
	readonly init: RequestInit & { duplex: "half" };
	/** Context needed to decrypt the chunked response */
	readonly context: ChunkedHttpClientContext;
}

/**
 * Client context for decrypting chunked responses (Request/Response API)
 */
export interface ChunkedHttpClientContext {
	/** Decrypt a chunked encapsulated response and decode to HTTP Response */
	decapsulateResponse(response: Response): Promise<Response>;
}

/**
 * OHTTP Client for encapsulating requests
 */
export class OHTTPClient {
	private readonly suite: CipherSuite;
	private readonly keyConfig: KeyConfig;
	private readonly kdfId: KdfId;
	private readonly aeadId: AeadId;
	private readonly requestLabel: string;
	private readonly responseLabel: string;

	/**
	 * Create an OHTTP client
	 *
	 * @param suite - The HPKE cipher suite to use
	 * @param keyConfig - The server's public key configuration
	 * @param options - Optional configuration
	 */
	constructor(suite: CipherSuite, keyConfig: KeyConfig, options: OHTTPClientOptions = {}) {
		this.suite = suite;
		this.keyConfig = keyConfig;
		this.requestLabel = options.requestLabel ?? DEFAULT_REQUEST_LABEL;
		this.responseLabel = options.responseLabel ?? DEFAULT_RESPONSE_LABEL;

		// Validate and extract cipher suite IDs
		const rawKdfId = suite.KDF.id;
		const rawAeadId = suite.AEAD.id;

		if (!isValidKdfId(rawKdfId) || !isValidAeadId(rawAeadId)) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		// Find the first matching symmetric algorithm
		const matchingAlgo = keyConfig.symmetricAlgorithms.find(
			(a) => a.kdfId === rawKdfId && a.aeadId === rawAeadId,
		);

		if (matchingAlgo === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		this.kdfId = rawKdfId;
		this.aeadId = rawAeadId;
	}

	/**
	 * Encapsulate a binary HTTP request (low-level API)
	 *
	 * @param request - The binary HTTP request bytes to encapsulate
	 * @returns The encapsulated request bytes and context for decrypting the response
	 */
	async encapsulate(request: Uint8Array): Promise<EncapsulatedRequest> {
		// Deserialize the public key
		const publicKey = await this.suite.DeserializePublicKey(this.keyConfig.publicKey);

		// Encapsulate the request
		const ctx = await encapsulateRequest(
			this.suite,
			publicKey,
			this.keyConfig,
			this.kdfId,
			this.aeadId,
			request,
			this.requestLabel,
		);

		// Create client context
		const responseLabel = this.responseLabel;
		const context: ClientContext = {
			async decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array> {
				return decapsulateResponse(ctx, encapsulatedResponse, responseLabel);
			},
		};

		return {
			encapsulatedRequest: ctx.encapsulatedRequest,
			context,
		};
	}

	/**
	 * Encapsulate an HTTP Request (high-level API)
	 *
	 * Encodes the request using Binary HTTP (RFC 9292), then encapsulates with OHTTP.
	 * Returns a RequestInit ready to use with fetch() or new Request().
	 *
	 * @param request - The HTTP Request to encapsulate
	 * @returns A RequestInit for the relay and context for decapsulating the response
	 *
	 * @example
	 * ```typescript
	 * const { init, context } = await client.encapsulateRequest(request);
	 * const response = await fetch(relayUrl, init);
	 * const innerResponse = await context.decapsulateResponse(response);
	 * ```
	 */
	async encapsulateRequest(request: Request): Promise<EncapsulatedRequestInit> {
		// Encode request to Binary HTTP
		let binaryRequest: Uint8Array;
		try {
			binaryRequest = await bhttp.encoder.encodeRequest(request);
		} catch {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Encapsulate
		const { encapsulatedRequest, context: bytesContext } = await this.encapsulate(binaryRequest);

		// Create HTTP context
		const context: HttpClientContext = {
			async decapsulateResponse(response: Response): Promise<Response> {
				// Validate content type
				const contentType = response.headers.get("content-type");
				if (contentType !== MediaType.RESPONSE) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Read and decrypt
				const encapsulatedResponse = new Uint8Array(await response.arrayBuffer());
				let binaryResponse: Uint8Array;
				try {
					binaryResponse = await bytesContext.decryptResponse(encapsulatedResponse);
				} catch {
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}

				// Decode Binary HTTP to Response
				try {
					return bhttp.decoder.decodeResponse(binaryResponse);
				} catch {
					// Wrap bhttp errors as opaque DecryptionFailed to prevent info leak
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}
			},
		};

		// Build RequestInit for relay
		const init: RequestInit = {
			method: "POST",
			headers: {
				"Content-Type": MediaType.REQUEST,
			},
			body: toArrayBuffer(encapsulatedRequest),
		};

		return { init, context };
	}
}

/**
 * Chunked OHTTP Client for streaming requests/responses (draft-ietf-ohai-chunked-ohttp-08)
 */
export class ChunkedOHTTPClient {
	private readonly suite: CipherSuite;
	private readonly keyConfig: KeyConfig;
	private readonly kdfId: KdfId;
	private readonly aeadId: AeadId;
	private readonly requestLabel: string;
	private readonly responseLabel: string;
	readonly maxChunkSize: number;

	/**
	 * Create a chunked OHTTP client
	 *
	 * @param suite - The HPKE cipher suite to use
	 * @param keyConfig - The server's public key configuration
	 * @param options - Optional configuration
	 */
	constructor(suite: CipherSuite, keyConfig: KeyConfig, options: ChunkedOHTTPClientOptions = {}) {
		this.suite = suite;
		this.keyConfig = keyConfig;
		this.requestLabel = options.requestLabel ?? CHUNKED_REQUEST_LABEL;
		this.responseLabel = options.responseLabel ?? CHUNKED_RESPONSE_LABEL;
		this.maxChunkSize = options.maxChunkSize ?? DEFAULT_MAX_CHUNK_SIZE;

		// Validate and extract cipher suite IDs
		const rawKdfId = suite.KDF.id;
		const rawAeadId = suite.AEAD.id;

		if (!isValidKdfId(rawKdfId) || !isValidAeadId(rawAeadId)) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		// Find the first matching symmetric algorithm
		const matchingAlgo = keyConfig.symmetricAlgorithms.find(
			(a) => a.kdfId === rawKdfId && a.aeadId === rawAeadId,
		);

		if (matchingAlgo === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		this.kdfId = rawKdfId;
		this.aeadId = rawAeadId;
	}

	/**
	 * Create a streaming request context
	 *
	 * Use this for incremental request construction:
	 * 1. Send ctx.header first
	 * 2. For each chunk: frameChunk(await ctx.sealChunk(data), false)
	 * 3. For final chunk: frameChunk(await ctx.sealFinalChunk(data), true)
	 */
	async createRequestContext(): Promise<ChunkedRequestContext> {
		// Deserialize the public key
		const publicKey = await this.suite.DeserializePublicKey(this.keyConfig.publicKey);

		// Build info string
		const info = buildRequestInfo(
			this.keyConfig.keyId,
			this.keyConfig.kemId,
			this.kdfId,
			this.aeadId,
			this.requestLabel,
		);

		// Setup sender context
		const { encapsulatedSecret: enc, ctx: senderContext } = await this.suite.SetupSender(
			publicKey,
			{
				info,
			},
		);

		// Build header
		const hdr = buildRequestHeader(
			this.keyConfig.keyId,
			this.keyConfig.kemId,
			this.kdfId,
			this.aeadId,
		);
		const header = concat(hdr, enc);

		const suite = this.suite;
		const responseLabel = this.responseLabel;

		return {
			header,
			_senderContext: senderContext,
			_enc: enc,

			async sealChunk(chunk: Uint8Array): Promise<Uint8Array> {
				// Non-final: empty AAD
				return senderContext.Seal(chunk);
			},

			async sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array> {
				// Final: AAD = "final"
				return senderContext.Seal(chunk, FINAL_CHUNK_AAD);
			},

			async createResponseContext(responseNonce: Uint8Array): Promise<ChunkedResponseContext> {
				const { aeadKey, aeadNonce } = await deriveChunkedResponseKeys(
					suite,
					senderContext,
					enc,
					responseNonce,
					responseLabel,
				);

				let counter = 0;
				// Max chunks: 2^32 per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
				const maxChunks = 2 ** 32;

				return {
					async openChunk(ciphertext: Uint8Array): Promise<Uint8Array> {
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						const pt = await openResponseChunk(
							suite,
							aeadKey,
							aeadNonce,
							counter,
							ciphertext,
							false,
						);
						counter++;
						return pt;
					},

					async openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array> {
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						return openResponseChunk(suite, aeadKey, aeadNonce, counter, ciphertext, true);
					},
				};
			},
		};
	}

	/**
	 * Encapsulate a complete request as chunked
	 *
	 * Convenience method that splits the request into chunks.
	 * Returns the full encapsulated message and a function to create response context.
	 */
	async encapsulate(request: Uint8Array): Promise<{
		encapsulatedRequest: Uint8Array;
		responseNonceLength: number;
		createResponseContext: (responseNonce: Uint8Array) => Promise<ChunkedResponseContext>;
	}> {
		const ctx = await this.createRequestContext();

		const chunks: Uint8Array[] = [ctx.header];

		// Split request into chunks
		let offset = 0;
		while (offset < request.length) {
			const remaining = request.length - offset;
			const isLast = remaining <= this.maxChunkSize;
			const chunkSize = Math.min(remaining, this.maxChunkSize);
			const chunk = request.slice(offset, offset + chunkSize);
			offset += chunkSize;

			if (isLast) {
				const sealed = await ctx.sealFinalChunk(chunk);
				chunks.push(frameChunk(sealed, true));
			} else {
				const sealed = await ctx.sealChunk(chunk);
				chunks.push(frameChunk(sealed, false));
			}
		}

		// Handle empty request
		if (request.length === 0) {
			const sealed = await ctx.sealFinalChunk(new Uint8Array(0));
			chunks.push(frameChunk(sealed, true));
		}

		return {
			encapsulatedRequest: concat(...chunks),
			responseNonceLength: getResponseNonceLength(this.suite),
			createResponseContext: (nonce) => ctx.createResponseContext(nonce),
		};
	}

	/**
	 * Decapsulate a complete chunked response
	 *
	 * Convenience method that parses and decrypts all response chunks.
	 */
	async decapsulateResponse(
		createResponseContext: (responseNonce: Uint8Array) => Promise<ChunkedResponseContext>,
		encapsulatedResponse: Uint8Array,
	): Promise<Uint8Array> {
		const nonceLength = getResponseNonceLength(this.suite);
		if (encapsulatedResponse.length < nonceLength) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Extract response nonce
		const responseNonce = encapsulatedResponse.slice(0, nonceLength);
		const ctx = await createResponseContext(responseNonce);

		// Parse and decrypt chunks
		const responseChunks: Uint8Array[] = [];
		let data = encapsulatedResponse.slice(nonceLength);

		while (data.length > 0) {
			const parsed = parseFramedChunk(data);
			if (parsed === undefined) {
				throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
			}

			if (parsed.isFinal) {
				const chunk = await ctx.openFinalChunk(parsed.ciphertext);
				responseChunks.push(chunk);
				break;
			}

			const chunk = await ctx.openChunk(parsed.ciphertext);
			responseChunks.push(chunk);
			data = data.slice(parsed.bytesConsumed);
		}

		return concat(...responseChunks);
	}

	/**
	 * Encapsulate an HTTP Request as chunked OHTTP (high-level streaming API)
	 *
	 * Encodes the request using streaming Binary HTTP (RFC 9292 indeterminate-length),
	 * then encapsulates with chunked OHTTP. The request body streams through without
	 * full buffering.
	 *
	 * @param request - The HTTP Request to encapsulate
	 * @returns A RequestInit for the relay (with streaming body) and context for decapsulating the response
	 *
	 * @example
	 * ```typescript
	 * const { init, context } = await client.encapsulateRequest(request);
	 * const response = await fetch(relayUrl, init);
	 * const innerResponse = await context.decapsulateResponse(response);
	 * ```
	 */
	async encapsulateRequest(request: Request): Promise<EncapsulatedChunkedRequestInit> {
		const requestCtx = await this.createRequestContext();
		const suite = this.suite;
		const maxChunkSize = this.maxChunkSize;
		const responseLabel = this.responseLabel;

		// Get the HPKE sender context for creating the encrypt transform
		// We need to access it through the request context internals
		// For now, we'll build the pipeline manually

		// Encode request to BHTTP stream
		const bhttpStream = encodeBHttpRequestStream(request);

		// Create the encryption pipeline:
		// BHTTP bytes → chunker → OHTTP encrypt → framed ciphertext
		const chunkerTransform = createChunkerTransform(maxChunkSize);
		const encryptTransform = createRequestEncryptTransform(requestCtx._senderContext);

		// Pipe through transforms
		const encryptedStream = bhttpStream.pipeThrough(chunkerTransform).pipeThrough(encryptTransform);

		// Create output stream that prepends header to encrypted chunks
		const header = requestCtx.header;
		const finalStream = new ReadableStream<Uint8Array>({
			async start(controller) {
				controller.enqueue(header);

				const reader = encryptedStream.getReader();
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

		// Create context for decapsulating response (streaming)
		const context: ChunkedHttpClientContext = {
			async decapsulateResponse(response: Response): Promise<Response> {
				// Validate content type
				const contentType = response.headers.get("content-type");
				if (contentType !== MediaType.CHUNKED_RESPONSE) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				const responseBody = response.body;
				if (responseBody === null) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Read response nonce first (need to buffer just enough)
				const nonceLength = getResponseNonceLength(suite);
				const reader = responseBody.getReader();
				let buffer = new Uint8Array(0);

				// Read until we have the nonce
				while (buffer.length < nonceLength) {
					const { done, value } = await reader.read();
					if (done) {
						throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
					}
					buffer = concat(buffer, value);
				}

				const responseNonce = buffer.slice(0, nonceLength);
				const remainder = buffer.slice(nonceLength);

				// Derive response keys
				const { aeadKey, aeadNonce } = await deriveChunkedResponseKeys(
					suite,
					requestCtx._senderContext,
					requestCtx._enc,
					responseNonce,
					responseLabel,
				);

				// Create decrypt transform
				const decryptTransform = createResponseDecryptTransform(suite, aeadKey, aeadNonce);

				// Create a stream from remainder + rest of response
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

				// Decode BHTTP response
				const decoded = await decodeBHttpResponseStream(plaintextStream);

				// Return Response with streaming body
				// Note: 204/304 responses must not have a body per HTTP semantics
				const bodylessStatus = decoded.status === 204 || decoded.status === 304;
				return new Response(bodylessStatus ? null : decoded.body, {
					status: decoded.status,
					headers: decoded.headers,
				});
			},
		};

		// Build RequestInit for relay with streaming body
		const init: RequestInit & { duplex: "half" } = {
			method: "POST",
			headers: {
				"Content-Type": MediaType.CHUNKED_REQUEST,
			},
			body: finalStream,
			duplex: "half",
		};

		return { init, context };
	}
}
