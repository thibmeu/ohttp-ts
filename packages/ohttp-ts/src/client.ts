import type { CipherSuite, SenderContext } from "hpke";
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
import type { AeadId, KdfId, KeyConfig } from "./keyConfig.js";
import { concat } from "./utils.js";

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
 * Result of encapsulating a request
 */
export interface EncapsulatedRequest {
	/** The encapsulated request bytes */
	readonly encapsulatedRequest: Uint8Array;
	/** Context needed to decrypt the response */
	readonly context: ClientContext;
}

/**
 * Client context for decrypting responses
 */
export interface ClientContext {
	/** Decrypt an encapsulated response */
	decryptResponse(encapsulatedResponse: Uint8Array): Promise<Uint8Array>;
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

		// Find the first matching symmetric algorithm
		const kdfId = suite.KDF.id as KdfId;
		const aeadId = suite.AEAD.id as AeadId;

		const matchingAlgo = keyConfig.symmetricAlgorithms.find(
			(a) => a.kdfId === kdfId && a.aeadId === aeadId,
		);

		if (matchingAlgo === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		this.kdfId = kdfId;
		this.aeadId = aeadId;
	}

	/**
	 * Encapsulate an HTTP request
	 *
	 * @param request - The binary HTTP request to encapsulate
	 * @returns The encapsulated request and context for decrypting the response
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

		// Find the first matching symmetric algorithm
		const kdfId = suite.KDF.id as KdfId;
		const aeadId = suite.AEAD.id as AeadId;

		const matchingAlgo = keyConfig.symmetricAlgorithms.find(
			(a) => a.kdfId === kdfId && a.aeadId === aeadId,
		);

		if (matchingAlgo === undefined) {
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
		}

		this.kdfId = kdfId;
		this.aeadId = aeadId;
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
		const { encapsulatedSecret: enc, ctx: senderContext } = await this.suite.SetupSender(publicKey, {
			info,
		});

		// Build header
		const hdr = buildRequestHeader(this.keyConfig.keyId, this.keyConfig.kemId, this.kdfId, this.aeadId);
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

				return {
					async openChunk(ciphertext: Uint8Array): Promise<Uint8Array> {
						const pt = await openResponseChunk(suite, aeadKey, aeadNonce, counter, ciphertext, false);
						counter++;
						return pt;
					},

					async openFinalChunk(ciphertext: Uint8Array): Promise<Uint8Array> {
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
}
