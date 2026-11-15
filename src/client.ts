import { MessageLimitExceededError, type Padding } from "bhttp-ts";
import type { CipherSuite, Key, SenderContext } from "hpke";
import {
	bhttpDecoder,
	bhttpEncoder,
	DEFAULT_PADDING,
	mapBhttpEncodingError,
	resolvePadding,
} from "./bhttp.ts";
import {
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_MAX_FRAME_SIZE,
	DEFAULT_MAX_OHTTP_MESSAGE_SIZE,
	isMediaType,
	MediaType,
} from "./constants.ts";
import {
	AEAD_TAG_SIZE,
	assertResponseCrypto,
	buildRequestHeader,
	buildRequestInfo,
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	decapsulateResponse,
	deriveChunkedResponseKeys,
	encapsulateRequest,
	FINAL_CHUNK_AAD,
	getResponseNonceLength,
	openResponseChunk,
	type ResponseCrypto,
} from "./encapsulation.ts";
import { asInvalidMessage, OHTTPError, OHTTPErrorCode } from "./errors.ts";
import { INCREMENTAL_HEADER } from "./incremental.ts";
import {
	type AeadId,
	isValidAeadId,
	isValidKdfId,
	isValidKeyId,
	type KdfId,
	type KeyConfig,
	supportsKeyConfig,
} from "./keyConfig.ts";
import {
	collectStream,
	createChunkerTransform,
	createRequestEncryptTransform,
	createResponseDecryptTransform,
	mapStreamErrors,
	type StreamOperationOptions,
	streamFromReader,
	streamOfBytes,
} from "./streaming.ts";
import {
	asOwnedBytes,
	assertMessageSize,
	collectLimitedBody,
	concat,
	createChunkBudget,
	resolveMaxMessageSize,
} from "./utils.ts";

/**
 * Options for OHTTP client
 */
export interface OHTTPClientOptions {
	/**
	 * Outgoing BHTTP byte multiple (0 disables padding), or a nondecreasing function
	 * returning a safe integer >= the unpadded size. HTTP helpers only.
	 * @default max(1024, padme(size))
	 */
	readonly padding?: Padding;
	/** Custom request label (default: "message/bhttp request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp response") */
	readonly responseLabel?: string;
	/** Crypto factory overrides for response decryption (default: resolved from the suite) */
	readonly responseCrypto?: ResponseCrypto;
	/** Maximum Binary HTTP bytes in one request or response. @default 1048576 */
	readonly maxMessageSize?: number;
}

/**
 * Options for chunked OHTTP client
 */
export interface ChunkedOHTTPClientOptions {
	/**
	 * Outgoing BHTTP byte multiple (0 disables padding), or a nondecreasing function
	 * returning a safe integer >= the unpadded size. HTTP helpers only.
	 * @default max(1024, padme(size))
	 */
	readonly padding?: Padding;
	/** Custom request label (default: "message/bhttp chunked request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp chunked response") */
	readonly responseLabel?: string;
	/** Crypto factory overrides for response decryption (default: resolved from the suite) */
	readonly responseCrypto?: ResponseCrypto;
	/**
	 * Maximum total plaintext bytes protected in one request or response.
	 * @default 1073741824
	 */
	readonly maxMessageSize?: number;
}

/**
 * Result of encapsulating a request (bytes API)
 */
export interface EncapsulatedRequest {
	/** The encapsulated request bytes */
	readonly encapsulatedRequest: Uint8Array<ArrayBuffer>;
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
 * - signal (the request's), credentials: "omit", referrerPolicy: "no-referrer"
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
	decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
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
	readonly header: Uint8Array<ArrayBuffer>;
	/** Seal a non-final chunk */
	sealChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Seal the final chunk */
	sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Create a response context after receiving the response nonce */
	createResponseContext(responseNonce: Uint8Array): Promise<ChunkedResponseContext>;
}

/**
 * Context for streaming chunked responses (client-side decryption)
 */
export interface ChunkedResponseContext {
	/** Open a non-final chunk */
	openChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Open the final chunk */
	openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
}

/**
 * HPKE state behind each chunked request context, kept off the object so code
 * that logs or serializes a context cannot reach it. Not re-exported from the
 * package entry point.
 */
export const senderStates = new WeakMap<
	ChunkedRequestContext,
	{ readonly senderContext: SenderContext; readonly enc: Uint8Array }
>();

function senderState(ctx: ChunkedRequestContext) {
	return senderStates.get(ctx) as NonNullable<ReturnType<typeof senderStates.get>>;
}

/**
 * A `RequestInit` carrying the `duplex: "half"` that a streaming request body
 * requires. The DOM lib types have no `duplex`, so annotate the init with this
 * rather than suppressing the error it raises.
 */
export type StreamingRequestInit = RequestInit & { duplex: "half" };

/** Outer-request defaults: no ambient cookies, page referrer, or redirect away from the relay */
const RELAY_INIT = {
	method: "POST",
	credentials: "omit",
	referrerPolicy: "no-referrer",
	redirect: "manual",
} as const;

/**
 * Result of encapsulating a chunked HTTP request (Request/Response API)
 *
 * The `init` object is a valid `RequestInit` containing:
 * - method: "POST"
 * - headers: { "Content-Type": "message/ohttp-chunked-req", "Incremental": "?1" }
 * - body: ReadableStream (streaming encapsulated request)
 * - duplex: "half" (required for streaming bodies in Node.js/Workers)
 * - signal (the effective one), credentials: "omit", referrerPolicy: "no-referrer"
 *
 * Usage: `fetch(relayUrl, init)` or `new Request(relayUrl, init)`
 */
export interface EncapsulatedChunkedRequestInit {
	/** RequestInit for fetch() - POST with streaming body and Content-Type: message/ohttp-chunked-req */
	readonly init: StreamingRequestInit;
	/** Context needed to decrypt the chunked response */
	readonly context: ChunkedHttpClientContext;
}

/**
 * Client context for decrypting chunked responses (Request/Response API)
 */
export interface ChunkedHttpClientContext {
	/** Decrypt a chunked encapsulated response and decode to HTTP Response */
	decapsulateResponse(response: Response, options?: StreamOperationOptions): Promise<Response>;
}

/**
 * OHTTP Client for encapsulating requests
 */
export class OHTTPClient {
	readonly #suite: CipherSuite;
	readonly #keyConfig: KeyConfig;
	/** Imported once: `DeserializePublicKey` is a WebCrypto `importKey`, and the
	 * key config cannot change under a live client */
	#importedPublicKey: Promise<Key> | undefined;
	readonly #kdfId: KdfId;
	readonly #aeadId: AeadId;
	readonly #requestLabel: string;
	readonly #responseLabel: string;
	readonly #responseCrypto: ResponseCrypto | undefined;
	readonly maxMessageSize: number;
	readonly #padding: Padding;

	/**
	 * Create an OHTTP client
	 *
	 * @param suite - The HPKE cipher suite to use
	 * @param keyConfig - The server's public key configuration
	 * @param options - Optional configuration
	 */
	constructor(suite: CipherSuite, keyConfig: KeyConfig, options: OHTTPClientOptions = {}) {
		assertResponseCrypto([suite], options.responseCrypto);
		this.#suite = suite;
		// Own copy: the public key is imported once, keyId is read per request
		this.#keyConfig = { ...keyConfig, publicKey: new Uint8Array(keyConfig.publicKey) };
		this.#requestLabel = options.requestLabel ?? DEFAULT_REQUEST_LABEL;
		this.#responseLabel = options.responseLabel ?? DEFAULT_RESPONSE_LABEL;
		this.#responseCrypto = options.responseCrypto;
		this.maxMessageSize = resolveMaxMessageSize(
			options.maxMessageSize ?? DEFAULT_MAX_OHTTP_MESSAGE_SIZE,
		);
		this.#padding = resolvePadding(options.padding ?? DEFAULT_PADDING, this.maxMessageSize);

		// Validate and extract cipher suite IDs
		const rawKdfId = suite.KDF.id;
		const rawAeadId = suite.AEAD.id;

		// The wire gives keyId one byte: anything else would be silently truncated
		if (!isValidKeyId(keyConfig.keyId)) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}
		if (
			!isValidKdfId(rawKdfId) ||
			!isValidAeadId(rawAeadId) ||
			!supportsKeyConfig(suite, keyConfig)
		) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		this.#kdfId = rawKdfId;
		this.#aeadId = rawAeadId;
	}

	/**
	 * Encapsulate a binary HTTP request (low-level API)
	 *
	 * @param request - The binary HTTP request bytes to encapsulate
	 * @returns The encapsulated request bytes and context for decrypting the response
	 */
	async encapsulate(request: Uint8Array): Promise<EncapsulatedRequest> {
		assertMessageSize(request, this.maxMessageSize);
		this.#importedPublicKey ??= this.#suite
			.DeserializePublicKey(this.#keyConfig.publicKey)
			.catch((err: unknown) => {
				// Only success is worth keeping: caching the rejection would poison
				// the client for the rest of its life over one failed import.
				this.#importedPublicKey = undefined;
				throw err;
			});
		const publicKey = await this.#importedPublicKey;

		// Encapsulate the request
		const { encapsulatedRequest, senderContext, enc, suite } = await encapsulateRequest(
			this.#suite,
			publicKey,
			this.#keyConfig,
			this.#kdfId,
			this.#aeadId,
			request,
			this.#requestLabel,
		);

		// Keep only what the response needs, not the request bytes
		const responseState = { senderContext, enc, suite };
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;
		const maxMessageSize = this.maxMessageSize;
		const maxEncapsulatedResponseSize =
			maxMessageSize + getResponseNonceLength(this.#suite) + AEAD_TAG_SIZE;
		const context: ClientContext = {
			async decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				if (encapsulatedResponse.length > maxEncapsulatedResponseSize) {
					throw new OHTTPError(OHTTPErrorCode.MessageTooLarge);
				}
				const response = await decapsulateResponse(
					responseState,
					encapsulatedResponse,
					responseLabel,
					responseCrypto,
				);
				assertMessageSize(response, maxMessageSize);
				return response;
			},
		};

		return { encapsulatedRequest, context };
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
			binaryRequest = await bhttpEncoder().encodeRequest(request, {
				maxMessageSize: this.maxMessageSize,
				padding: this.#padding,
			});
		} catch (error) {
			if (error instanceof MessageLimitExceededError) {
				throw new OHTTPError(OHTTPErrorCode.MessageTooLarge);
			}
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Encapsulate
		const { encapsulatedRequest, context: bytesContext } = await this.encapsulate(binaryRequest);

		// Create HTTP context
		const maxEncapsulatedResponseSize =
			this.maxMessageSize + getResponseNonceLength(this.#suite) + AEAD_TAG_SIZE;
		const context: HttpClientContext = {
			async decapsulateResponse(response: Response): Promise<Response> {
				// Validate content type
				const contentType = response.headers.get("content-type");
				if (!isMediaType(contentType, MediaType.RESPONSE)) {
					void response.body?.cancel().catch(() => {});
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Read and decrypt
				const encapsulatedResponse = await collectLimitedBody(
					response,
					maxEncapsulatedResponseSize,
				);
				let binaryResponse: Uint8Array;
				try {
					binaryResponse = await bytesContext.decryptResponse(encapsulatedResponse);
				} catch (error) {
					if (error instanceof OHTTPError && error.code === OHTTPErrorCode.MessageTooLarge) {
						throw error;
					}
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}

				// Decode Binary HTTP to Response
				try {
					return bhttpDecoder().decodeResponse(binaryResponse);
				} catch {
					// Decryption already succeeded, so this is the gateway's framing bug.
					// Matches the streaming path, which reports InvalidMessage.
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}
			},
		};

		// Build RequestInit for relay
		const init: RequestInit = {
			...RELAY_INIT,
			signal: request.signal,
			headers: {
				"Content-Type": MediaType.REQUEST,
			},
			body: encapsulatedRequest,
		};

		return { init, context };
	}
}

/**
 * Chunked OHTTP Client for streaming requests/responses (draft-ietf-ohai-chunked-ohttp-08)
 */
export class ChunkedOHTTPClient {
	readonly #suite: CipherSuite;
	readonly #keyConfig: KeyConfig;
	/** Imported once: `DeserializePublicKey` is a WebCrypto `importKey`, and the
	 * key config cannot change under a live client */
	#importedPublicKey: Promise<Key> | undefined;
	readonly #kdfId: KdfId;
	readonly #aeadId: AeadId;
	readonly #requestLabel: string;
	readonly #responseLabel: string;
	readonly #responseCrypto: ResponseCrypto | undefined;
	readonly maxMessageSize: number;
	readonly #padding: Padding;

	/**
	 * Create a chunked OHTTP client
	 *
	 * @param suite - The HPKE cipher suite to use
	 * @param keyConfig - The server's public key configuration
	 * @param options - Optional configuration
	 */
	constructor(suite: CipherSuite, keyConfig: KeyConfig, options: ChunkedOHTTPClientOptions = {}) {
		assertResponseCrypto([suite], options.responseCrypto);
		this.#suite = suite;
		// Own copy: the public key is imported once, keyId is read per request
		this.#keyConfig = { ...keyConfig, publicKey: new Uint8Array(keyConfig.publicKey) };
		this.#requestLabel = options.requestLabel ?? CHUNKED_REQUEST_LABEL;
		this.#responseLabel = options.responseLabel ?? CHUNKED_RESPONSE_LABEL;
		this.#responseCrypto = options.responseCrypto;
		this.maxMessageSize = resolveMaxMessageSize(options.maxMessageSize);
		this.#padding = resolvePadding(options.padding ?? DEFAULT_PADDING, this.maxMessageSize);

		// Validate and extract cipher suite IDs
		const rawKdfId = suite.KDF.id;
		const rawAeadId = suite.AEAD.id;

		// The wire gives keyId one byte: anything else would be silently truncated
		if (!isValidKeyId(keyConfig.keyId)) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}
		if (
			!isValidKdfId(rawKdfId) ||
			!isValidAeadId(rawAeadId) ||
			!supportsKeyConfig(suite, keyConfig)
		) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		this.#kdfId = rawKdfId;
		this.#aeadId = rawAeadId;
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
		this.#importedPublicKey ??= this.#suite
			.DeserializePublicKey(this.#keyConfig.publicKey)
			.catch((err: unknown) => {
				// Only success is worth keeping: caching the rejection would poison
				// the client for the rest of its life over one failed import.
				this.#importedPublicKey = undefined;
				throw err;
			});
		const publicKey = await this.#importedPublicKey;

		// Build info string
		const info = buildRequestInfo(
			this.#keyConfig.keyId,
			this.#keyConfig.kemId,
			this.#kdfId,
			this.#aeadId,
			this.#requestLabel,
		);

		// Setup sender context
		const { encapsulatedSecret: enc, ctx: senderContext } = await this.#suite.SetupSender(
			publicKey,
			{
				info,
			},
		);

		// Build header
		const hdr = buildRequestHeader(
			this.#keyConfig.keyId,
			this.#keyConfig.kemId,
			this.#kdfId,
			this.#aeadId,
		);
		const header = concat(hdr, enc);

		const suite = this.#suite;
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;

		let requestFinished = false;
		const claimRequest = createChunkBudget(this.maxMessageSize);
		const maxMessageSize = this.maxMessageSize;

		const requestContext: ChunkedRequestContext = {
			header,

			async sealChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				if (requestFinished) {
					throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
				}
				claimRequest(chunk.length, false);
				// Non-final: empty AAD
				return asOwnedBytes(await senderContext.Seal(chunk));
			},

			async sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				if (requestFinished) {
					throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
				}
				claimRequest(chunk.length, true);
				requestFinished = true;
				// Final: AAD = "final"
				return asOwnedBytes(await senderContext.Seal(chunk, FINAL_CHUNK_AAD));
			},

			async createResponseContext(responseNonce: Uint8Array): Promise<ChunkedResponseContext> {
				if (responseNonce.length !== getResponseNonceLength(suite)) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}
				const { aeadKey, aeadNonce, aead } = await deriveChunkedResponseKeys(
					suite,
					senderContext,
					enc,
					responseNonce,
					responseLabel,
					responseCrypto,
				);

				// Counter and finished flag are claimed synchronously at call time: a
				// caller may issue several opens before the first resolves, and each
				// chunk needs its own counter-derived nonce.
				let counter = 0;
				let responseFinished = false;
				const claimResponse = createChunkBudget(maxMessageSize);
				// Max chunks: 2^32 per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
				const maxChunks = 2 ** 32;
				let opened = Promise.resolve(true);
				// Start crypto immediately; release plaintext only after earlier opens succeed.
				const open = (ciphertext: Uint8Array, isFinal: boolean) => {
					const result = Promise.all([
						opened,
						openResponseChunk(aead, aeadKey, aeadNonce, counter++, ciphertext, isFinal),
					]).then(([previousSucceeded, plaintext]) => {
						if (!previousSucceeded) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						return plaintext;
					});
					opened = result.then(
						() => true,
						() => {
							responseFinished = true;
							return false;
						},
					);
					return result;
				};

				return {
					async openChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
						if (responseFinished) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						if (ciphertext.length < AEAD_TAG_SIZE) {
							throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
						}
						if (ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						claimResponse(ciphertext.length - AEAD_TAG_SIZE, false);
						return open(ciphertext, false);
					},

					async openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
						if (responseFinished) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						if (ciphertext.length < AEAD_TAG_SIZE) {
							throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
						}
						if (ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						claimResponse(ciphertext.length - AEAD_TAG_SIZE, true);
						responseFinished = true;
						return open(ciphertext, true);
					},
				};
			},
		};
		senderStates.set(requestContext, { senderContext, enc });
		return requestContext;
	}

	/**
	 * Encapsulate a complete request as chunked
	 *
	 * Convenience method that splits the request into chunks. The returned
	 * context decrypts the complete chunked response, as {@link OHTTPClient.encapsulate}.
	 */
	async encapsulate(request: Uint8Array): Promise<EncapsulatedRequest> {
		assertMessageSize(request, this.maxMessageSize);
		const ctx = await this.createRequestContext();
		const { senderContext, enc } = senderState(ctx);

		// Chunk + seal through the same pipelined transforms as the streaming API
		// (the seals run in a concurrent window), then prepend the header.
		const encapsulatedRequest = await collectStream(
			streamOfBytes(request)
				.pipeThrough(createChunkerTransform(DEFAULT_MAX_CHUNK_SIZE))
				.pipeThrough(createRequestEncryptTransform(senderContext, this.maxMessageSize)),
			ctx.header,
		);

		const suite = this.#suite;
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;
		const maxMessageSize = this.maxMessageSize;
		const context: ClientContext = {
			async decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				const nonceLength = getResponseNonceLength(suite);
				if (encapsulatedResponse.length < nonceLength) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}
				const { aead, aeadKey, aeadNonce } = await deriveChunkedResponseKeys(
					suite,
					senderContext,
					enc,
					encapsulatedResponse.subarray(0, nonceLength),
					responseLabel,
					responseCrypto,
				);
				return collectStream(
					streamOfBytes(encapsulatedResponse.subarray(nonceLength)).pipeThrough(
						createResponseDecryptTransform(aead, aeadKey, aeadNonce, maxMessageSize),
					),
				);
			},
		};

		return { encapsulatedRequest, context };
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
	async encapsulateRequest(
		request: Request,
		options: StreamOperationOptions = {},
	): Promise<EncapsulatedChunkedRequestInit> {
		const requestCtx = await this.createRequestContext();
		const { senderContext, enc } = senderState(requestCtx);
		const suite = this.#suite;
		const maxMessageSize = this.maxMessageSize;
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;

		// Encode request to BHTTP stream
		const bhttpStream = bhttpEncoder().encodeRequestStream(request, {
			padding: this.#padding,
			maxMessageSize,
		});

		// Create the encryption pipeline:
		// BHTTP bytes → chunker → OHTTP encrypt → framed ciphertext
		const chunkerTransform = createChunkerTransform(DEFAULT_MAX_CHUNK_SIZE);
		const encryptTransform = createRequestEncryptTransform(senderContext, maxMessageSize);

		// Pipe through transforms
		const signal = options.signal ?? request.signal;
		const encryptedStream = bhttpStream
			.pipeThrough(chunkerTransform)
			.pipeThrough(encryptTransform, { signal });

		// Create output stream that prepends header to encrypted chunks
		const header = requestCtx.header;
		const finalStream = streamFromReader(encryptedStream.getReader(), header, undefined, (error) =>
			signal.aborted && error === signal.reason ? error : mapBhttpEncodingError(error),
		);

		// Create context for decapsulating response (streaming)
		const context: ChunkedHttpClientContext = {
			async decapsulateResponse(
				response: Response,
				options: StreamOperationOptions = {},
			): Promise<Response> {
				// Validate content type
				const contentType = response.headers.get("content-type");
				if (!isMediaType(contentType, MediaType.CHUNKED_RESPONSE)) {
					void response.body?.cancel().catch(() => {});
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				const responseBody = response.body;
				if (responseBody === null) {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Read response nonce first (need to buffer just enough)
				const nonceLength = getResponseNonceLength(suite);
				const reader = responseBody.getReader();
				const signal = options.signal;
				const abort = () => void reader.cancel(signal?.reason).catch(() => {});
				if (signal?.aborted) abort();
				else signal?.addEventListener("abort", abort, { once: true });
				let buffer = new Uint8Array(0);
				let ciphertextStream: ReadableStream<Uint8Array>;
				let decryptTransform: ReturnType<typeof createResponseDecryptTransform>;

				try {
					// Read until we have the nonce
					while (buffer.length < nonceLength) {
						const { done, value } = await reader.read();
						if (done) {
							if (signal?.aborted) throw signal.reason;
							throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
						}
						buffer = concat(buffer, value);
					}

					const responseNonce = buffer.subarray(0, nonceLength);
					const remainder = buffer.subarray(nonceLength);

					// Derive response keys
					const { aeadKey, aeadNonce, aead } = await deriveChunkedResponseKeys(
						suite,
						senderContext,
						enc,
						responseNonce,
						responseLabel,
						responseCrypto,
					);

					// Create decrypt transform
					decryptTransform = createResponseDecryptTransform(
						aead,
						aeadKey,
						aeadNonce,
						maxMessageSize,
					);

					// Create a stream from remainder + rest of response
					ciphertextStream = streamFromReader(reader, remainder, signal);
				} catch (error) {
					try {
						await reader.cancel(error);
					} catch {}
					reader.releaseLock();
					throw error;
				} finally {
					signal?.removeEventListener("abort", abort);
				}

				// Decrypt stream
				const plaintextStream = ciphertextStream.pipeThrough(decryptTransform);

				let decoded: Response;
				try {
					decoded = await bhttpDecoder().decodeResponseStream(plaintextStream);
				} catch (error) {
					if (signal?.aborted) throw signal.reason;
					throw asInvalidMessage(error);
				}
				if (decoded.body === null) return decoded;
				return new Response(
					mapStreamErrors(decoded.body, (error) =>
						signal?.aborted ? signal.reason : asInvalidMessage(error),
					),
					decoded,
				);
			},
		};

		// Build RequestInit for relay with streaming body
		const init: StreamingRequestInit = {
			...RELAY_INIT,
			signal,
			// draft-08 Section 4: ask relays to forward each chunk as it arrives
			headers: {
				"Content-Type": MediaType.CHUNKED_REQUEST,
				[INCREMENTAL_HEADER]: "?1",
			},
			body: finalStream,
			duplex: "half",
		};

		return { init, context };
	}
}
