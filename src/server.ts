import type { AEAD as AeadImpl, CipherSuite, RecipientContext } from "hpke";
import { bhttpDecoder, bhttpEncoder } from "./bhttp.js";
import type { StreamingRequestInit } from "./client.js";
import {
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_MAX_FRAME_SIZE,
	kAead,
	kAeadKey,
	kAeadNonce,
	kEnc,
	kRecipientContext,
	kSuite,
	MediaType,
} from "./constants.js";
import {
	AEAD_TAG_SIZE,
	assertResponseCrypto,
	buildRequestInfo,
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	decapsulateRequest,
	deriveChunkedResponseKeys,
	encapsulateResponse,
	FINAL_CHUNK_AAD,
	getEncLength,
	getResponseNonceLength,
	parseRequestHeader,
	type ResponseCrypto,
	sealResponseChunk,
} from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import {
	isValidKeyId,
	type KeyConfigWithPrivate,
	resolveSuites,
	sameAlgorithms,
	selectSuite,
	symmetricAlgorithmsOf,
} from "./keyConfig.js";
import {
	collectStream,
	createChunkerTransform,
	createRequestDecryptTransform,
	createResponseEncryptTransform,
	mapStreamErrors,
	type StreamOperationOptions,
	streamFromReader,
	streamOfBytes,
} from "./streaming.js";
import { asOwnedBytes, concat, createChunkBudget, resolveMaxMessageSize } from "./utils.js";

/**
 * Options for OHTTP server
 */
export interface OHTTPServerOptions {
	/** Custom request label (default: "message/bhttp request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp response") */
	readonly responseLabel?: string;
	/** Crypto factory overrides for response encryption (default: resolved from the suite) */
	readonly responseCrypto?: ResponseCrypto;
}

/**
 * Options for chunked OHTTP server
 */
export interface ChunkedOHTTPServerOptions {
	/** Custom request label (default: "message/bhttp chunked request") */
	readonly requestLabel?: string;
	/** Custom response label (default: "message/bhttp chunked response") */
	readonly responseLabel?: string;
	/** Crypto factory overrides for response encryption (default: resolved from the suite) */
	readonly responseCrypto?: ResponseCrypto;
	/**
	 * Maximum total plaintext bytes protected in one request or response.
	 * @default 1073741824
	 */
	readonly maxMessageSize?: number;
}

/**
 * Result of decapsulating a request (bytes API)
 */
export interface DecapsulatedRequest {
	/** The decrypted binary HTTP request */
	readonly request: Uint8Array<ArrayBuffer>;
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
	encryptResponse(response: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
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
	openChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Open the final chunk */
	openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Create a response context for encrypting the response */
	createResponseContext(): Promise<ChunkedServerResponseContext>;
	/** HPKE recipient context for streaming transforms */
	readonly [kRecipientContext]: RecipientContext;
	/** Encapsulated secret for response key derivation */
	readonly [kEnc]: Uint8Array;
	/** The suite the request header selected */
	readonly [kSuite]: CipherSuite;
}

/**
 * Context for streaming chunked responses (server-side encryption)
 */
export interface ChunkedServerResponseContext {
	/** The response nonce (must be sent first) */
	readonly responseNonce: Uint8Array<ArrayBuffer>;
	/** Seal a non-final chunk */
	sealChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Seal the final chunk */
	sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
	/** Derived response AEAD (for the pipelined buffer path) */
	readonly [kAead]: AeadImpl;
	/** Derived response AEAD key */
	readonly [kAeadKey]: Uint8Array;
	/** Derived response AEAD base nonce */
	readonly [kAeadNonce]: Uint8Array;
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
	encapsulateResponse(response: Response, options?: StreamOperationOptions): Promise<Response>;
}

/**
 * Reject a key config list a server cannot serve unambiguously
 *
 * Lookup is by key identifier alone, so a duplicate shadows every later config
 * sharing it, and a botched rotation should fail here rather than on live
 * requests. The KEM and algorithms are re-derived too, since a plain
 * `{ ...config, symmetricAlgorithms }` walks past the constructors. `publicKey`
 * is not checked against `keyPair`: that needs an await this does not have.
 *
 * Returns the configs to store, with their own suite lists.
 *
 * @throws OHTTPError InvalidKeyConfig, or UnsupportedCipherSuite when a suite
 * names an algorithm the wire format cannot carry
 */
function validateKeyConfigs(
	keyConfigs: readonly KeyConfigWithPrivate[],
): readonly KeyConfigWithPrivate[] {
	if (keyConfigs.length === 0) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	if (new Set(keyConfigs.map((k) => k.keyId)).size !== keyConfigs.length) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	return keyConfigs.map((config) => {
		const suites = resolveSuites(config.suites);
		if (
			!isValidKeyId(config.keyId) ||
			config.kemId !== suites[0].KEM.id ||
			!sameAlgorithms(config.symmetricAlgorithms, symmetricAlgorithmsOf(suites))
		) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}
		return { ...config, suites };
	});
}

/**
 * OHTTP Server (Gateway) for decapsulating requests
 */
export class OHTTPServer {
	readonly #keyConfigs: readonly KeyConfigWithPrivate[];
	readonly #requestLabel: string;
	readonly #responseLabel: string;
	readonly #responseCrypto: ResponseCrypto | undefined;

	/**
	 * Create an OHTTP server
	 *
	 * @param keyConfigs - Non-empty array of key configurations with private keys and distinct key identifiers
	 * @param options - Optional configuration
	 */
	constructor(keyConfigs: readonly KeyConfigWithPrivate[], options: OHTTPServerOptions = {}) {
		// Validation runs once, so the server keeps its own array and its own suite
		// lists rather than whatever the caller may change afterwards.
		this.#keyConfigs = validateKeyConfigs(keyConfigs);
		for (const config of this.#keyConfigs) {
			assertResponseCrypto(config.suites, options.responseCrypto);
		}
		this.#requestLabel = options.requestLabel ?? DEFAULT_REQUEST_LABEL;
		this.#responseLabel = options.responseLabel ?? DEFAULT_RESPONSE_LABEL;
		this.#responseCrypto = options.responseCrypto;
	}

	/**
	 * Decapsulate an encrypted request (low-level API)
	 *
	 * @param encapsulatedRequest - The encapsulated request bytes
	 * @returns The decrypted request bytes and context for encrypting the response
	 */
	async decapsulate(encapsulatedRequest: Uint8Array): Promise<DecapsulatedRequest> {
		const ctx = await decapsulateRequest(encapsulatedRequest, this.#keyConfigs, this.#requestLabel);

		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;
		const context: ServerContext = {
			async encryptResponse(response: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				// Generate random response nonce
				const nonceLength = getResponseNonceLength(ctx.suite);
				const responseNonce = crypto.getRandomValues(new Uint8Array(nonceLength));
				return encapsulateResponse(ctx, response, responseNonce, responseLabel, responseCrypto);
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
			innerRequest = bhttpDecoder().decodeRequest(binaryRequest);
		} catch {
			// Decryption already succeeded, so this is the client's framing bug, not
			// a crypto failure. Reporting DecryptionFailed here would make the real
			// ones unreadable in gateway logs, and the client learns nothing it did
			// not already know: it encoded the plaintext.
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}

		// Create HTTP context
		const context: HttpServerContext = {
			async encapsulateResponse(response: Response): Promise<Response> {
				// Encode response to Binary HTTP
				let binaryResponse: Uint8Array;
				try {
					binaryResponse = await bhttpEncoder().encodeResponse(response);
				} catch {
					throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
				}

				// Encrypt
				const encapsulatedResponse = await bytesContext.encryptResponse(binaryResponse);

				// Return as OHTTP response
				return new Response(encapsulatedResponse, {
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
	readonly #keyConfigs: readonly KeyConfigWithPrivate[];
	readonly #requestLabel: string;
	readonly #responseLabel: string;
	readonly #responseCrypto: ResponseCrypto | undefined;
	readonly maxMessageSize: number;

	/**
	 * Create a chunked OHTTP server
	 *
	 * @param keyConfigs - Non-empty array of key configurations with private keys and distinct key identifiers
	 * @param options - Optional configuration
	 */
	constructor(
		keyConfigs: readonly KeyConfigWithPrivate[],
		options: ChunkedOHTTPServerOptions = {},
	) {
		// Validation runs once, so the server keeps its own array and its own suite
		// lists rather than whatever the caller may change afterwards.
		this.#keyConfigs = validateKeyConfigs(keyConfigs);
		for (const config of this.#keyConfigs) {
			assertResponseCrypto(config.suites, options.responseCrypto);
		}
		this.#requestLabel = options.requestLabel ?? CHUNKED_REQUEST_LABEL;
		this.#responseLabel = options.responseLabel ?? CHUNKED_RESPONSE_LABEL;
		this.#responseCrypto = options.responseCrypto;
		this.maxMessageSize = resolveMaxMessageSize(options.maxMessageSize);
	}

	/**
	 * Create a streaming request context from the encapsulated header
	 *
	 * Use this for incremental request processing:
	 * 1. Parse header (first 7 + Nenc bytes)
	 * 2. For each chunk: await ctx.openChunk(ciphertext) or ctx.openFinalChunk(ciphertext)
	 */
	async createRequestContext(encapsulatedHeader: Uint8Array): Promise<ChunkedServerRequestContext> {
		// parseRequestHeader already rejects anything shorter than 7 + Nenc.
		const { header } = parseRequestHeader(encapsulatedHeader);

		// Find matching key config
		const keyConfig = this.#keyConfigs.find((k) => k.keyId === header.keyId);
		if (keyConfig === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnknownKeyId);
		}

		// Verify KEM matches
		if (keyConfig.kemId !== header.kemId) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		// Pick the suite the header names, as the buffered path does
		const suite = selectSuite(keyConfig, header.kdfId, header.aeadId);

		// Build info string
		const info = buildRequestInfo(
			header.keyId,
			header.kemId,
			header.kdfId,
			header.aeadId,
			this.#requestLabel,
		);

		// Setup recipient context
		let recipientContext: RecipientContext;
		try {
			recipientContext = await suite.SetupRecipient(keyConfig.keyPair, header.enc, {
				info,
			});
		} catch {
			throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
		}

		const enc = header.enc;
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;
		const maxMessageSize = this.maxMessageSize;

		let requestFinished = false;
		const claimRequest = createChunkBudget(maxMessageSize);

		return {
			keyConfig,
			[kRecipientContext]: recipientContext,
			[kEnc]: enc,
			[kSuite]: suite,

			async openChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				if (requestFinished) {
					throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
				}
				if (ciphertext.length < AEAD_TAG_SIZE || ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
					throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
				}
				claimRequest(ciphertext.length - AEAD_TAG_SIZE, false);
				try {
					return asOwnedBytes(await recipientContext.Open(ciphertext));
				} catch {
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}
			},

			async openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
				if (requestFinished) {
					throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
				}
				if (ciphertext.length < AEAD_TAG_SIZE || ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
					throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
				}
				claimRequest(ciphertext.length - AEAD_TAG_SIZE, true);
				try {
					// Unlike the response contexts, the flag is claimed after the await on
					// purpose: the HPKE context carries its own sequence number, so no two
					// opens can share a nonce, and a chunk that fails to decrypt should
					// leave the context usable rather than wedged as finished.
					const pt = asOwnedBytes(await recipientContext.Open(ciphertext, FINAL_CHUNK_AAD));
					requestFinished = true;
					return pt;
				} catch {
					throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
				}
			},

			async createResponseContext(): Promise<ChunkedServerResponseContext> {
				// Generate random response nonce
				const nonceLength = getResponseNonceLength(suite);
				const responseNonce = crypto.getRandomValues(new Uint8Array(nonceLength));

				// Derive key material
				const { aeadKey, aeadNonce, aead } = await deriveChunkedResponseKeys(
					suite,
					recipientContext,
					enc,
					responseNonce,
					responseLabel,
					responseCrypto,
				);

				// Counter and finished flag are claimed synchronously at call time: a
				// caller may issue several seals before the first resolves, and sealing
				// twice at one counter reuses an (AEAD key, nonce) pair.
				let counter = 0;
				let responseFinished = false;
				const claimResponse = createChunkBudget(maxMessageSize);
				// Max chunks: 2^32 per draft-ietf-ohai-chunked-ohttp-08 Section 7.3
				const maxChunks = 2 ** 32;

				return {
					responseNonce,
					[kAead]: aead,
					[kAeadKey]: aeadKey,
					[kAeadNonce]: aeadNonce,

					async sealChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
						if (responseFinished) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						claimResponse(chunk.length, false);
						return sealResponseChunk(aead, aeadKey, aeadNonce, counter++, chunk, false);
					},

					async sealFinalChunk(chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
						if (responseFinished) {
							throw new OHTTPError(OHTTPErrorCode.ChunkSequenceError);
						}
						if (counter >= maxChunks) {
							throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
						}
						claimResponse(chunk.length, true);
						responseFinished = true;
						return sealResponseChunk(aead, aeadKey, aeadNonce, counter, chunk, true);
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
	async decapsulate(encapsulatedRequest: Uint8Array) {
		// Parse header to get offset
		const { offset: headerOffset } = parseRequestHeader(encapsulatedRequest);
		const header = encapsulatedRequest.subarray(0, headerOffset);

		const ctx = await this.createRequestContext(header);

		// Decrypt the framed body through the request decrypt transform (opens run
		// in a concurrent window).
		const request = await collectStream(
			streamOfBytes(encapsulatedRequest.subarray(headerOffset)).pipeThrough(
				createRequestDecryptTransform(
					ctx[kRecipientContext],
					DEFAULT_MAX_FRAME_SIZE,
					this.maxMessageSize,
				),
			),
		);

		return {
			request,
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
	): Promise<Uint8Array<ArrayBuffer>> {
		// Chunk + seal through the pipelined response transform (seals run in a
		// concurrent window), prefixed with the response nonce.
		return collectStream(
			streamOfBytes(response)
				.pipeThrough(createChunkerTransform(DEFAULT_MAX_CHUNK_SIZE))
				.pipeThrough(
					createResponseEncryptTransform(
						responseContext[kAead],
						responseContext[kAeadKey],
						responseContext[kAeadNonce],
						this.maxMessageSize,
					),
				),
			responseContext.responseNonce,
		);
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
	async decapsulateRequest(
		request: Request,
		options: StreamOperationOptions = {},
	): Promise<DecapsulatedChunkedHttpRequest> {
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
		const signal = options.signal ?? request.signal;
		const abort = () => void reader.cancel(signal.reason);
		if (signal.aborted) abort();
		else signal.addEventListener("abort", abort, { once: true });
		let buffer = new Uint8Array(0);

		// Read until we have the header (7 bytes + Nenc)
		// We need at least 7 bytes to know the KEM ID, then we can compute header size
		while (buffer.length < 7) {
			const { done, value } = await reader.read();
			if (done) {
				if (signal.aborted) throw signal.reason;
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
				if (signal.aborted) throw signal.reason;
				throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
			}
			buffer = concat(buffer, value);
		}

		const headerBytes = buffer.subarray(0, headerSize);
		const remainder = buffer.subarray(headerSize);

		// Create request context from header
		const requestCtx = await this.createRequestContext(headerBytes);

		// Create decrypt transform
		const decryptTransform = createRequestDecryptTransform(
			requestCtx[kRecipientContext],
			DEFAULT_MAX_FRAME_SIZE,
			this.maxMessageSize,
		);

		// Create a stream from remainder + rest of request body
		signal.removeEventListener("abort", abort);
		const ciphertextStream = streamFromReader(reader, remainder, signal);

		// Decrypt stream
		const plaintextStream = ciphertextStream.pipeThrough(decryptTransform);

		let decoded: Request;
		try {
			decoded = await bhttpDecoder().decodeRequestStream(plaintextStream);
		} catch {
			if (signal.aborted) throw signal.reason;
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}
		const innerRequest =
			decoded.body === null
				? decoded
				: new Request(decoded, {
						body: mapStreamErrors(decoded.body, () =>
							signal.aborted ? signal.reason : new OHTTPError(OHTTPErrorCode.InvalidMessage),
						),
						duplex: "half",
					} as StreamingRequestInit);

		const suite = requestCtx[kSuite];
		const maxMessageSize = this.maxMessageSize;
		const responseLabel = this.#responseLabel;
		const responseCrypto = this.#responseCrypto;

		// Create context for encapsulating response (streaming)
		const context: ChunkedHttpServerContext = {
			async encapsulateResponse(
				response: Response,
				options: StreamOperationOptions = {},
			): Promise<Response> {
				// Generate response nonce
				const nonceLength = getResponseNonceLength(suite);
				const responseNonce = crypto.getRandomValues(new Uint8Array(nonceLength));

				// Derive response keys
				const { aeadKey, aeadNonce, aead } = await deriveChunkedResponseKeys(
					suite,
					requestCtx[kRecipientContext],
					requestCtx[kEnc],
					responseNonce,
					responseLabel,
					responseCrypto,
				);

				// Encode response to BHTTP stream
				const bhttpStream = bhttpEncoder().encodeResponseStream(response);

				// Create the encryption pipeline
				const chunkerTransform = createChunkerTransform(DEFAULT_MAX_CHUNK_SIZE);
				const encryptTransform = createResponseEncryptTransform(
					aead,
					aeadKey,
					aeadNonce,
					maxMessageSize,
				);

				// Pipe through transforms
				const signal = options.signal;
				const encryptedStream = bhttpStream
					.pipeThrough(chunkerTransform)
					.pipeThrough(encryptTransform, signal === undefined ? undefined : { signal });

				// Create output stream that prepends response nonce
				const finalStream = streamFromReader(encryptedStream.getReader(), responseNonce);

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
