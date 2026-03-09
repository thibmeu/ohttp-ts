import type { CipherSuite, SenderContext } from "hpke";
import {
	type BHttpContentEvent,
	BHttpRequestStreamEncoder,
	type BHttpResponsePreambleEvent,
	BHttpStreamDecoder,
	MediaType,
	bhttp,
} from "./constants.js";
import {
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	type ClientEncapsulationContext,
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	FINAL_CHUNK_AAD,
	buildRequestHeader,
	buildRequestInfo,
	decapsulateResponse,
	deriveChunkedResponseKeys,
	encapsulateRequest,
	frameChunk,
	getResponseNonceLength,
	openResponseChunk,
	parseFramedChunk,
} from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import {
	type AeadId,
	type KdfId,
	type KeyConfig,
	isValidAeadId,
	isValidKdfId,
} from "./keyConfig.js";
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
 */
export interface EncapsulatedHttpRequest {
	/** The encapsulated request as a Request object (POST, Content-Type: message/ohttp-req) */
	readonly request: Request;
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
 */
export interface EncapsulatedChunkedHttpRequest {
	/** The encapsulated request as a Request object (POST, Content-Type: message/ohttp-chunked-req) */
	readonly request: Request;
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
	 * Returns a Request object ready to send to the relay.
	 *
	 * @param request - The HTTP Request to encapsulate
	 * @param relayUrl - The URL of the OHTTP relay
	 * @returns A Request for the relay and context for decapsulating the response
	 */
	async encapsulateRequest(request: Request, relayUrl: string): Promise<EncapsulatedHttpRequest> {
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

		// Build relay request
		const relayRequest = new Request(relayUrl, {
			method: "POST",
			headers: {
				"Content-Type": MediaType.REQUEST,
			},
			body: toArrayBuffer(encapsulatedRequest),
		});

		return { request: relayRequest, context };
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
	 * Encapsulate an HTTP Request as chunked OHTTP (high-level API)
	 *
	 * Encodes the request using streaming Binary HTTP (RFC 9292 indeterminate-length),
	 * then encapsulates with chunked OHTTP.
	 *
	 * @param request - The HTTP Request to encapsulate
	 * @param relayUrl - The URL of the OHTTP relay
	 * @returns A Request for the relay and context for decapsulating the response
	 */
	async encapsulateRequest(
		request: Request,
		relayUrl: string,
	): Promise<EncapsulatedChunkedHttpRequest> {
		const ctx = await this.createRequestContext();

		// Encode request preamble using streaming BHTTP
		const url = new URL(request.url);
		const bhttpEncoder = new BHttpRequestStreamEncoder();
		const preamble = bhttpEncoder.encodePreamble(
			request.method,
			url.protocol.replace(":", ""),
			url.host,
			url.pathname + url.search,
			request.headers,
		);

		// Build the encrypted stream
		const maxChunkSize = this.maxChunkSize;
		const encryptedChunks: Uint8Array[] = [ctx.header];

		// Encrypt preamble as first chunk(s)
		let pendingBytes = preamble;
		const body = request.body;

		if (body === null) {
			// No body - encode end and send as final chunk
			const endBytes = bhttpEncoder.encodeEnd();
			const finalData = concat(pendingBytes, endBytes);

			// Split into chunks if needed
			let offset = 0;
			while (offset < finalData.length) {
				const remaining = finalData.length - offset;
				const isLast = remaining <= maxChunkSize;
				const chunkSize = Math.min(remaining, maxChunkSize);
				const chunk = finalData.slice(offset, offset + chunkSize);
				offset += chunkSize;

				if (isLast) {
					const sealed = await ctx.sealFinalChunk(chunk);
					encryptedChunks.push(frameChunk(sealed, true));
				} else {
					const sealed = await ctx.sealChunk(chunk);
					encryptedChunks.push(frameChunk(sealed, false));
				}
			}
		} else {
			// Stream body chunks
			const reader = body.getReader();

			while (true) {
				const { done, value } = await reader.read();

				if (done) {
					// Encode end and send final chunk
					const endBytes = bhttpEncoder.encodeEnd();
					const finalData = concat(pendingBytes, endBytes);

					let offset = 0;
					while (offset < finalData.length) {
						const remaining = finalData.length - offset;
						const isLast = remaining <= maxChunkSize;
						const chunkSize = Math.min(remaining, maxChunkSize);
						const chunk = finalData.slice(offset, offset + chunkSize);
						offset += chunkSize;

						if (isLast) {
							const sealed = await ctx.sealFinalChunk(chunk);
							encryptedChunks.push(frameChunk(sealed, true));
						} else {
							const sealed = await ctx.sealChunk(chunk);
							encryptedChunks.push(frameChunk(sealed, false));
						}
					}
					break;
				}

				// Encode body chunk
				const bodyChunk = bhttpEncoder.encodeContentChunk(value);
				const combined = concat(pendingBytes, bodyChunk);
				pendingBytes = new Uint8Array(0);

				// Encrypt and frame
				let offset = 0;
				while (offset + maxChunkSize <= combined.length) {
					const chunk = combined.slice(offset, offset + maxChunkSize);
					const sealed = await ctx.sealChunk(chunk);
					encryptedChunks.push(frameChunk(sealed, false));
					offset += maxChunkSize;
				}

				// Keep remainder for next iteration
				if (offset < combined.length) {
					pendingBytes = combined.slice(offset);
				}
			}
		}

		const encapsulatedBody = concat(...encryptedChunks);
		const suite = this.suite;

		// Create context for decapsulating response
		const context: ChunkedHttpClientContext = {
			async decapsulateResponse(response: Response): Promise<Response> {
				// Validate content type
				const contentType = response.headers.get("content-type");
				if (contentType !== MediaType.CHUNKED_RESPONSE) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Read response body
				const responseBody = new Uint8Array(await response.arrayBuffer());
				const nonceLength = getResponseNonceLength(suite);
				if (responseBody.length < nonceLength) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Extract response nonce and create response context
				const responseNonce = responseBody.slice(0, nonceLength);
				const responseCtx = await ctx.createResponseContext(responseNonce);

				// Parse, decrypt, and decode BHTTP response
				const bhttpDecoder = new BHttpStreamDecoder();
				let data = responseBody.slice(nonceLength);

				let status = 0;
				let headers = new Headers();
				const bodyChunks: Uint8Array[] = [];

				while (data.length > 0) {
					const parsed = parseFramedChunk(data);
					if (parsed === undefined) {
						throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
					}

					let decrypted: Uint8Array;
					try {
						if (parsed.isFinal) {
							decrypted = await responseCtx.openFinalChunk(parsed.ciphertext);
						} else {
							decrypted = await responseCtx.openChunk(parsed.ciphertext);
						}
					} catch {
						throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
					}

					// Feed to BHTTP decoder
					const events = bhttpDecoder.push(decrypted);
					for (const event of events) {
						switch (event.type) {
							case "response-preamble":
								status = (event as BHttpResponsePreambleEvent).status;
								headers = (event as BHttpResponsePreambleEvent).headers;
								break;
							case "content":
								bodyChunks.push((event as BHttpContentEvent).data);
								break;
							// informational and trailers ignored for now
						}
					}

					if (parsed.isFinal) {
						break;
					}
					data = data.slice(parsed.bytesConsumed);
				}

				// Finalize decoder
				try {
					bhttpDecoder.end();
				} catch {
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}

				// Build Response
				const responseBodyData = concat(...bodyChunks);
				return new Response(responseBodyData.length > 0 ? toArrayBuffer(responseBodyData) : null, {
					status,
					headers,
				});
			},
		};

		// Build relay request
		const relayRequest = new Request(relayUrl, {
			method: "POST",
			headers: {
				"Content-Type": MediaType.CHUNKED_REQUEST,
			},
			body: toArrayBuffer(encapsulatedBody),
		});

		return { request: relayRequest, context };
	}
}
