import type { RecipientContext } from "hpke";
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
	getResponseNonceLength,
	parseFramedChunk,
	parseRequestHeader,
	sealResponseChunk,
} from "./encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import type { KeyConfigWithPrivate } from "./keyConfig.js";
import { concat } from "./utils.js";

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
 * Result of decapsulating a request
 */
export interface DecapsulatedRequest {
	/** The decrypted binary HTTP request */
	readonly request: Uint8Array;
	/** Context needed to encrypt the response */
	readonly context: ServerContext;
}

/**
 * Server context for encrypting responses
 */
export interface ServerContext {
	/** Encrypt a response */
	encryptResponse(response: Uint8Array): Promise<Uint8Array>;
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
	 * Decapsulate an encrypted request
	 *
	 * @param encapsulatedRequest - The encapsulated request bytes
	 * @returns The decrypted request and context for encrypting the response
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
}
