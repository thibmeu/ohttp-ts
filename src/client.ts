import { MessageLimitExceededError } from "bhttp-ts";
import type { AEAD as AeadImpl, CipherSuite, Key, SenderContext } from "hpke";
import { bhttpDecoder, bhttpEncoder } from "./bhttp.ts";
import {
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_MAX_FRAME_SIZE,
	DEFAULT_MAX_OHTTP_MESSAGE_SIZE,
	kAead,
	kAeadKey,
	kAeadNonce,
	kEnc,
	kSenderContext,
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
import { OHTTPError, OHTTPErrorCode } from "./errors.ts";
import {
	type AeadId,
	isValidAeadId,
	isValidKdfId,
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
	/** HPKE sender context for streaming transforms */
	readonly [kSenderContext]: SenderContext;
	/** Encapsulated secret for response key derivation */
	readonly [kEnc]: Uint8Array;
}

/**
 * Context for streaming chunked responses (client-side decryption)
 */
export interface ChunkedResponseContext {
	/** Open a non-final chunk */
	openChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Open the final chunk */
	openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Derived response AEAD (for the pipelined buffer path) */
	readonly [kAead]: AeadImpl;
	/** Derived response AEAD key */
	readonly [kAeadKey]: Uint8Array;
	/** Derived response AEAD base nonce */
	readonly [kAeadNonce]: Uint8Array;
}

/**
 * A `RequestInit` carrying the `duplex: "half"` that a streaming request body
 * requires. The DOM lib types have no `duplex`, so annotate the init with this
 * rather than suppressing the error it raises.
 */
export type StreamingRequestInit = RequestInit & { duplex: "half" };

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
		this.#keyConfig = keyConfig;
		this.#requestLabel = options.requestLabel ?? DEFAULT_REQUEST_LABEL;
		this.#responseLabel = options.responseLabel ?? DEFAULT_RESPONSE_LABEL;
		this.#responseCrypto = options.responseCrypto;
		this.maxMessageSize = resolveMaxMessageSize(
			options.maxMessageSize ?? DEFAULT_MAX_OHTTP_MESSAGE_SIZE,
		);

		// Validate and extract cipher suite IDs
		const rawKdfId = suite.KDF.id;
		const rawAeadId = suite.AEAD.id;

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
		const ctx = await encapsulateRequest(
			this.#suite,
			publicKey,
			this.#keyConfig,
			this.#kdfId,
			this.#aeadId,
			request,
			this.#requestLabel,
		);

		// Create client context
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;
		const maxMessageSize = this.maxMessageSize;
		const context: ClientContext = {
			async decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				const response = await decapsulateResponse(
					ctx,
					encapsulatedResponse,
					responseLabel,
					responseCrypto,
				);
				assertMessageSize(response, maxMessageSize);
				return response;
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
			binaryRequest = await bhttpEncoder().encodeRequest(request, {
				maxMessageSize: this.maxMessageSize,
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
				if (contentType !== MediaType.RESPONSE) {
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
			method: "POST",
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
		this.#keyConfig = keyConfig;
		this.#requestLabel = options.requestLabel ?? CHUNKED_REQUEST_LABEL;
		this.#responseLabel = options.responseLabel ?? CHUNKED_RESPONSE_LABEL;
		this.#responseCrypto = options.responseCrypto;
		this.maxMessageSize = resolveMaxMessageSize(options.maxMessageSize);

		// Validate and extract cipher suite IDs
		const rawKdfId = suite.KDF.id;
		const rawAeadId = suite.AEAD.id;

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

		return {
			header,
			[kSenderContext]: senderContext,
			[kEnc]: enc,

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

				return {
					[kAead]: aead,
					[kAeadKey]: aeadKey,
					[kAeadNonce]: aeadNonce,

					async openChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
						if (responseFinished) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						if (ciphertext.length < AEAD_TAG_SIZE || ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						claimResponse(ciphertext.length - AEAD_TAG_SIZE, false);
						return openResponseChunk(aead, aeadKey, aeadNonce, counter++, ciphertext, false);
					},

					async openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
						if (responseFinished) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						if (ciphertext.length < AEAD_TAG_SIZE || ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						claimResponse(ciphertext.length - AEAD_TAG_SIZE, true);
						responseFinished = true;
						return openResponseChunk(aead, aeadKey, aeadNonce, counter, ciphertext, true);
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
	async encapsulate(request: Uint8Array) {
		const ctx = await this.createRequestContext();

		// Chunk + seal through the same pipelined transforms as the streaming API
		// (the seals run in a concurrent window), then prepend the header.
		const encapsulatedRequest = await collectStream(
			streamOfBytes(request)
				.pipeThrough(createChunkerTransform(DEFAULT_MAX_CHUNK_SIZE))
				.pipeThrough(createRequestEncryptTransform(ctx[kSenderContext], this.maxMessageSize)),
			ctx.header,
		);

		return {
			encapsulatedRequest,
			responseNonceLength: getResponseNonceLength(this.#suite),
			createResponseContext: (nonce: Uint8Array) => ctx.createResponseContext(nonce),
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
	): Promise<Uint8Array<ArrayBuffer>> {
		const nonceLength = getResponseNonceLength(this.#suite);
		if (encapsulatedResponse.length < nonceLength) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Extract response nonce
		const responseNonce = encapsulatedResponse.subarray(0, nonceLength);
		const ctx = await createResponseContext(responseNonce);

		// Decrypt the framed body through the pipelined response transform
		// (opens run in a concurrent window; counters are claimed synchronously).
		return collectStream(
			streamOfBytes(encapsulatedResponse.subarray(nonceLength)).pipeThrough(
				createResponseDecryptTransform(
					ctx[kAead],
					ctx[kAeadKey],
					ctx[kAeadNonce],
					DEFAULT_MAX_FRAME_SIZE,
					this.maxMessageSize,
				),
			),
		);
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
		const suite = this.#suite;
		const maxMessageSize = this.maxMessageSize;
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;

		// Get the HPKE sender context for creating the encrypt transform
		// We need to access it through the request context internals
		// For now, we'll build the pipeline manually

		// Encode request to BHTTP stream
		const bhttpStream = bhttpEncoder().encodeRequestStream(request);

		// Create the encryption pipeline:
		// BHTTP bytes → chunker → OHTTP encrypt → framed ciphertext
		const chunkerTransform = createChunkerTransform(DEFAULT_MAX_CHUNK_SIZE);
		const encryptTransform = createRequestEncryptTransform(
			requestCtx[kSenderContext],
			maxMessageSize,
		);

		// Pipe through transforms
		const signal = options.signal ?? request.signal;
		const encryptedStream = bhttpStream
			.pipeThrough(chunkerTransform)
			.pipeThrough(encryptTransform, { signal });

		// Create output stream that prepends header to encrypted chunks
		const header = requestCtx.header;
		const finalStream = streamFromReader(encryptedStream.getReader(), header);

		// Create context for decapsulating response (streaming)
		const context: ChunkedHttpClientContext = {
			async decapsulateResponse(
				response: Response,
				options: StreamOperationOptions = {},
			): Promise<Response> {
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
				const signal = options.signal;
				const abort = () => void reader.cancel(signal?.reason);
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
						requestCtx[kSenderContext],
						requestCtx[kEnc],
						responseNonce,
						responseLabel,
						responseCrypto,
					);

					// Create decrypt transform
					decryptTransform = createResponseDecryptTransform(
						aead,
						aeadKey,
						aeadNonce,
						DEFAULT_MAX_FRAME_SIZE,
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
				} catch {
					if (signal?.aborted) throw signal.reason;
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}
				if (decoded.body === null) return decoded;
				return new Response(
					mapStreamErrors(decoded.body, () =>
						signal?.aborted ? signal.reason : new OHTTPError(OHTTPErrorCode.InvalidMessage),
					),
					decoded,
				);
			},
		};

		// Build RequestInit for relay with streaming body
		const init: StreamingRequestInit = {
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
