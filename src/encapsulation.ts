import {
	AEAD_AES_128_GCM,
	AEAD_AES_256_GCM,
	AEAD_ChaCha20Poly1305,
	type AEADFactory,
	type AEAD as AeadImpl,
	type CipherSuite,
	KDF_HKDF_SHA256,
	KDF_HKDF_SHA384,
	KDF_HKDF_SHA512,
	type KDFFactory,
	type KDF as KdfImpl,
	type Key,
	type RecipientContext,
	type SenderContext,
} from "hpke";
import { decode as decodeVarint, encode as encodeVarint } from "quicvarint";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import { AeadId, KdfId, KemId, type KeyConfig, type KeyConfigWithPrivate } from "./keyConfig.js";
import { concat } from "./utils.js";

/** Shared TextEncoder instance */
const textEncoder = new TextEncoder();

/** Encode ASCII string to bytes */
function encodeString(s: string): Uint8Array {
	return textEncoder.encode(s);
}

/**
 * Default labels for OHTTP request/response (RFC 9458 Section 4.3-4.4)
 */
export const DEFAULT_REQUEST_LABEL = "message/bhttp request";
export const DEFAULT_RESPONSE_LABEL = "message/bhttp response";

/**
 * Labels for chunked OHTTP (draft-ietf-ohai-chunked-ohttp-08 Section 6.1-6.2)
 */
export const CHUNKED_REQUEST_LABEL = "message/bhttp chunked request";
export const CHUNKED_RESPONSE_LABEL = "message/bhttp chunked response";

/**
 * Optional crypto factories for OHTTP response encryption (RFC 9458 Section 4.4).
 *
 * OHTTP responses are not HPKE: the response key is derived with HKDF over an
 * HPKE-exported secret and then used with a raw AEAD. The constructed
 * {@link CipherSuite} only exposes metadata for its KDF/AEAD, so the response
 * primitives are obtained by instantiating hpke factories instead.
 *
 * By default the factories are resolved from the suite's KDF/AEAD ids using
 * hpke's built-in (WebCrypto-backed) implementations. Override either field to
 * supply a non-WebCrypto implementation — for example
 * `@panva/hpke-noble`'s `AEAD_ChaCha20Poly1305` for ChaCha20 responses in
 * browsers and Cloudflare Workers, where WebCrypto lacks ChaCha20-Poly1305.
 *
 * An override may swap the implementation but not the algorithm: the factory
 * must produce the same KDF/AEAD the suite negotiated, otherwise resolution
 * throws {@link OHTTPErrorCode.UnsupportedCipherSuite}.
 */
export interface ResponseCrypto {
	/** KDF factory override (must match the suite's KDF; default: resolved from it) */
	readonly kdf?: KDFFactory;
	/** AEAD factory override (must match the suite's AEAD; default: resolved from it) */
	readonly aead?: AEADFactory;
}

const KDF_FACTORIES: Record<number, KDFFactory> = {
	[KdfId.HKDF_SHA256]: KDF_HKDF_SHA256,
	[KdfId.HKDF_SHA384]: KDF_HKDF_SHA384,
	[KdfId.HKDF_SHA512]: KDF_HKDF_SHA512,
};

const AEAD_FACTORIES: Record<number, AEADFactory> = {
	[AeadId.AES_128_GCM]: AEAD_AES_128_GCM,
	[AeadId.AES_256_GCM]: AEAD_AES_256_GCM,
	[AeadId.ChaCha20Poly1305]: AEAD_ChaCha20Poly1305,
};

/**
 * Resolve the KDF and AEAD implementations used for response encryption.
 *
 * Falls back to hpke's built-in factory for the suite's KDF/AEAD id when no
 * override is supplied. Throws {@link OHTTPErrorCode.UnsupportedCipherSuite}
 * when the suite uses an algorithm with no known factory, or when an override
 * resolves to a different algorithm than the suite negotiated (an override may
 * swap the implementation, not the algorithm).
 */
function resolveResponseCrypto(
	suite: CipherSuite,
	responseCrypto?: ResponseCrypto,
): { kdf: KdfImpl; aead: AeadImpl } {
	const kdfFactory = responseCrypto?.kdf ?? KDF_FACTORIES[suite.KDF.id];
	const aeadFactory = responseCrypto?.aead ?? AEAD_FACTORIES[suite.AEAD.id];
	if (!kdfFactory || !aeadFactory) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
	const kdf = kdfFactory();
	const aead = aeadFactory();
	if (kdf.id !== suite.KDF.id || aead.id !== suite.AEAD.id) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
	return { kdf, aead };
}

/**
 * Encapsulated request header structure (raw wire values)
 *
 * Note: kemId, kdfId, aeadId are raw numbers from the wire.
 * They must be validated against supported values before use.
 */
export interface EncapsulatedRequestHeader {
	readonly keyId: number;
	readonly kemId: number;
	readonly kdfId: number;
	readonly aeadId: number;
	readonly enc: Uint8Array;
}

/** Header size: keyId(1) + kemId(2) + kdfId(2) + aeadId(2) = 7 bytes */
const HEADER_SIZE = 7;

/**
 * Write request header fields into a buffer at the given offset
 * Returns bytes written (always 7)
 */
function writeHeader(
	view: DataView,
	offset: number,
	keyId: number,
	kemId: number,
	kdfId: number,
	aeadId: number,
): number {
	view.setUint8(offset, keyId);
	view.setUint16(offset + 1, kemId);
	view.setUint16(offset + 3, kdfId);
	view.setUint16(offset + 5, aeadId);
	return HEADER_SIZE;
}

/**
 * Build the HPKE info string for request encryption (RFC 9458 Section 4.3)
 *
 * info = concat(encode_str(label), encode(1, 0), hdr)
 * where hdr = concat(encode(1, key_id), encode(2, kem_id), encode(2, kdf_id), encode(2, aead_id))
 */
export function buildRequestInfo(
	keyId: number,
	kemId: number,
	kdfId: number,
	aeadId: number,
	label: string = DEFAULT_REQUEST_LABEL,
): Uint8Array {
	const labelBytes = encodeString(label);
	const result = new Uint8Array(labelBytes.length + 1 + HEADER_SIZE);
	const view = new DataView(result.buffer);

	result.set(labelBytes, 0);
	view.setUint8(labelBytes.length, 0); // separator byte
	writeHeader(view, labelBytes.length + 1, keyId, kemId, kdfId, aeadId);

	return result;
}

/**
 * Build the encapsulated request header (RFC 9458 Section 4.1)
 *
 * hdr = concat(encode(1, key_id), encode(2, kem_id), encode(2, kdf_id), encode(2, aead_id))
 */
export function buildRequestHeader(
	keyId: number,
	kemId: number,
	kdfId: number,
	aeadId: number,
): Uint8Array {
	const result = new Uint8Array(HEADER_SIZE);
	const view = new DataView(result.buffer);
	writeHeader(view, 0, keyId, kemId, kdfId, aeadId);
	return result;
}

/**
 * Get the encapsulated secret length for a KEM
 *
 * @param kemId - KEM identifier (validated internally)
 * @throws OHTTPError if kemId is not a supported KEM
 */
export function getEncLength(kemId: number): number {
	switch (kemId) {
		// Standard KEMs
		case KemId.X25519_HKDF_SHA256:
			return 32;
		case KemId.X448_HKDF_SHA512:
			return 56;
		case KemId.P256_HKDF_SHA256:
			return 65;
		case KemId.P384_HKDF_SHA384:
			return 97;
		case KemId.P521_HKDF_SHA512:
			return 133;
		// ML-KEM (ciphertext sizes from FIPS 203)
		case KemId.ML_KEM_512:
			return 768;
		case KemId.ML_KEM_768:
			return 1088;
		case KemId.ML_KEM_1024:
			return 1568;
		// Hybrid KEMs
		case KemId.MLKEM768_P256:
			return 1088 + 65; // ML-KEM-768 ct + P-256 point
		case KemId.MLKEM1024_P384:
			return 1568 + 97; // ML-KEM-1024 ct + P-384 point
		case KemId.MLKEM768_X25519:
			return 1088 + 32; // ML-KEM-768 ct + X25519
		default:
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
}

/**
 * Get response nonce length: max(Nn, Nk) (RFC 9458 Section 4.2)
 */
export function getResponseNonceLength(suite: CipherSuite): number {
	return Math.max(suite.AEAD.Nn, suite.AEAD.Nk);
}

/**
 * Parse an encapsulated request header
 *
 * Returns raw wire values. Caller must validate kemId/kdfId/aeadId
 * against supported values before use.
 */
export function parseRequestHeader(data: Uint8Array): {
	header: EncapsulatedRequestHeader;
	offset: number;
} {
	if (data.length < 7) {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	const keyId = data[0];
	if (keyId === undefined) {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	// Read raw wire values - validation happens in consumer
	const kemId = ((data[1] ?? 0) << 8) | (data[2] ?? 0);
	const kdfId = ((data[3] ?? 0) << 8) | (data[4] ?? 0);
	const aeadId = ((data[5] ?? 0) << 8) | (data[6] ?? 0);

	// getEncLength validates kemId is supported, throws if not
	const encLength = getEncLength(kemId);
	if (data.length < 7 + encLength) {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	const enc = data.slice(7, 7 + encLength);

	return {
		header: {
			keyId,
			kemId,
			kdfId,
			aeadId,
			enc,
		},
		offset: 7 + encLength,
	};
}

/**
 * Client context for encrypting requests and decrypting responses
 */
export interface ClientEncapsulationContext {
	/** The encapsulated request bytes (header + enc + ciphertext) */
	readonly encapsulatedRequest: Uint8Array;
	/** The HPKE sender context for exporting secrets */
	readonly senderContext: SenderContext;
	/** The encapsulated secret (enc) */
	readonly enc: Uint8Array;
	/** The cipher suite used */
	readonly suite: CipherSuite;
}

/**
 * Server context for decrypting requests and encrypting responses
 */
export interface ServerEncapsulationContext {
	/** The decrypted request */
	readonly request: Uint8Array;
	/** The HPKE recipient context for exporting secrets */
	readonly recipientContext: RecipientContext;
	/** The encapsulated secret (enc) */
	readonly enc: Uint8Array;
	/** The cipher suite used */
	readonly suite: CipherSuite;
	/** The key config that was used */
	readonly keyConfig: KeyConfigWithPrivate;
}

/**
 * Encapsulate a request using HPKE (RFC 9458 Section 4.3)
 */
export async function encapsulateRequest(
	suite: CipherSuite,
	publicKey: Key,
	keyConfig: KeyConfig,
	kdfId: KdfId,
	aeadId: AeadId,
	request: Uint8Array,
	label: string = DEFAULT_REQUEST_LABEL,
): Promise<ClientEncapsulationContext> {
	// Build info string
	const info = buildRequestInfo(keyConfig.keyId, keyConfig.kemId, kdfId, aeadId, label);

	// Setup sender context
	const { encapsulatedSecret: enc, ctx: senderContext } = await suite.SetupSender(publicKey, {
		info,
	});

	// Encrypt the request
	const ciphertext = await senderContext.Seal(request);

	// Build the encapsulated request
	const header = buildRequestHeader(keyConfig.keyId, keyConfig.kemId, kdfId, aeadId);
	const encapsulatedRequest = concat(header, enc, ciphertext);

	return {
		encapsulatedRequest,
		senderContext,
		enc,
		suite,
	};
}

/**
 * Decapsulate a request using HPKE (RFC 9458 Section 4.3)
 */
export async function decapsulateRequest(
	encapsulatedRequest: Uint8Array,
	keyConfigs: readonly KeyConfigWithPrivate[],
	label: string = DEFAULT_REQUEST_LABEL,
): Promise<ServerEncapsulationContext> {
	// Parse the header
	const { header, offset } = parseRequestHeader(encapsulatedRequest);

	// Find the matching key config
	const keyConfig = keyConfigs.find((k) => k.keyId === header.keyId);
	if (keyConfig === undefined) {
		throw new OHTTPError(OHTTPErrorCode.UnknownKeyId);
	}

	// Verify the KEM matches
	if (keyConfig.kemId !== header.kemId) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	// Verify we support the requested cipher suite
	const supportedAlgo = keyConfig.symmetricAlgorithms.find(
		(a) => a.kdfId === header.kdfId && a.aeadId === header.aeadId,
	);
	if (supportedAlgo === undefined) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	// Build info string
	const info = buildRequestInfo(header.keyId, header.kemId, header.kdfId, header.aeadId, label);

	// Extract ciphertext
	const ciphertext = encapsulatedRequest.slice(offset);

	// Setup recipient context
	let recipientContext: RecipientContext;
	try {
		recipientContext = await keyConfig.suite.SetupRecipient(keyConfig.keyPair, header.enc, {
			info,
		});
	} catch {
		throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
	}

	// Decrypt the request
	let request: Uint8Array;
	try {
		request = await recipientContext.Open(ciphertext);
	} catch {
		throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
	}

	return {
		request,
		recipientContext,
		enc: header.enc,
		suite: keyConfig.suite,
		keyConfig,
	};
}

/**
 * Encapsulate a response using HPKE-derived keys (RFC 9458 Section 4.4)
 */
export async function encapsulateResponse(
	serverContext: ServerEncapsulationContext,
	response: Uint8Array,
	responseNonce: Uint8Array,
	label: string = DEFAULT_RESPONSE_LABEL,
	responseCrypto?: ResponseCrypto,
): Promise<Uint8Array> {
	const { recipientContext, enc, suite } = serverContext;

	const nonceLength = getResponseNonceLength(suite);
	if (responseNonce.length !== nonceLength) {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	// Export secret from HPKE context
	const secret = await recipientContext.Export(encodeString(label), nonceLength);

	// Derive AEAD key and nonce using HKDF over the exported secret.
	// salt = concat(enc, response_nonce)
	// prk = Extract(salt, secret); aead_key = Expand(prk, "key", Nk); ...
	const salt = concat(enc, responseNonce);
	const { kdf, aead } = resolveResponseCrypto(suite, responseCrypto);
	const prk = await kdf.Extract(salt, secret);
	const aeadKey = await kdf.Expand(prk, encodeString("key"), suite.AEAD.Nk);
	const aeadNonce = await kdf.Expand(prk, encodeString("nonce"), suite.AEAD.Nn);

	// Encrypt response using raw AEAD
	const ct = await aead.Seal(aeadKey, aeadNonce, new Uint8Array(0), response);

	// Return nonce + ciphertext
	return concat(responseNonce, ct);
}

/**
 * Decapsulate a response using HPKE-derived keys (RFC 9458 Section 4.4)
 */
export async function decapsulateResponse(
	clientContext: ClientEncapsulationContext,
	encapsulatedResponse: Uint8Array,
	label: string = DEFAULT_RESPONSE_LABEL,
	responseCrypto?: ResponseCrypto,
): Promise<Uint8Array> {
	const { senderContext, enc, suite } = clientContext;

	const nonceLength = getResponseNonceLength(suite);
	if (encapsulatedResponse.length < nonceLength) {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	// Extract nonce and ciphertext
	const responseNonce = encapsulatedResponse.slice(0, nonceLength);
	const ciphertext = encapsulatedResponse.slice(nonceLength);

	// Export secret from HPKE context
	const secret = await senderContext.Export(encodeString(label), nonceLength);

	// Derive AEAD key and nonce
	const salt = concat(enc, responseNonce);
	const { kdf, aead } = resolveResponseCrypto(suite, responseCrypto);
	const prk = await kdf.Extract(salt, secret);
	const aeadKey = await kdf.Expand(prk, encodeString("key"), suite.AEAD.Nk);
	const aeadNonce = await kdf.Expand(prk, encodeString("nonce"), suite.AEAD.Nn);

	// Decrypt response
	try {
		return await aead.Open(aeadKey, aeadNonce, new Uint8Array(0), ciphertext);
	} catch {
		throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
	}
}

// ============================================================================
// Chunked OHTTP primitives (draft-ietf-ohai-chunked-ohttp-08)
// ============================================================================

/**
 * Default maximum chunk size (draft-08 Section 3)
 */
export const DEFAULT_MAX_CHUNK_SIZE = 16384;

/**
 * AAD for final chunk (draft-08 Section 6.1-6.2)
 */
export const FINAL_CHUNK_AAD = encodeString("final");

/**
 * Frame a chunk with varint length prefix
 *
 * Non-final chunks: length (varint) + ciphertext
 * Final chunk: 0 (varint) + ciphertext
 */
export function frameChunk(ciphertext: Uint8Array, isFinal: boolean): Uint8Array {
	const length = isFinal ? 0 : ciphertext.length;
	const lengthBytes = encodeVarint(length);
	return concat(lengthBytes, ciphertext);
}

/**
 * Result of parsing a framed chunk
 */
export interface ParsedChunk {
	readonly ciphertext: Uint8Array;
	readonly isFinal: boolean;
	readonly bytesConsumed: number;
}

/**
 * Parse a framed chunk, returning the ciphertext and whether it's final
 *
 * Returns undefined if not enough data available.
 * Throws OHTTPError if varint encoding is malformed.
 */
export function parseFramedChunk(data: Uint8Array): ParsedChunk | undefined {
	if (data.length === 0) {
		return undefined;
	}

	// Decode varint length - may throw on malformed input
	let length: number;
	let varintLength: number;
	try {
		const result = decodeVarint(data);
		length = result.value;
		varintLength = result.usize;
	} catch {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	if (length === 0) {
		// Final chunk - extends to end of stream
		return {
			ciphertext: data.slice(varintLength),
			isFinal: true,
			bytesConsumed: data.length,
		};
	}

	// Non-final chunk
	const totalLength = varintLength + length;
	if (data.length < totalLength) {
		// Not enough data
		return undefined;
	}

	return {
		ciphertext: data.slice(varintLength, totalLength),
		isFinal: false,
		bytesConsumed: totalLength,
	};
}

/**
 * Derive response AEAD key and base nonce for chunked responses (draft-08 Section 6.2)
 */
export async function deriveChunkedResponseKeys(
	suite: CipherSuite,
	context: SenderContext | RecipientContext,
	enc: Uint8Array,
	responseNonce: Uint8Array,
	label: string = CHUNKED_RESPONSE_LABEL,
	responseCrypto?: ResponseCrypto,
): Promise<{ aeadKey: Uint8Array; aeadNonce: Uint8Array; aead: AeadImpl }> {
	const nonceLength = getResponseNonceLength(suite);

	// Export secret from HPKE context
	const secret = await context.Export(encodeString(label), nonceLength);

	// salt = concat(enc, response_nonce)
	const salt = concat(enc, responseNonce);

	// Derive PRK and expand to key/nonce
	const { kdf, aead } = resolveResponseCrypto(suite, responseCrypto);
	const prk = await kdf.Extract(salt, secret);
	const aeadKey = await kdf.Expand(prk, encodeString("key"), suite.AEAD.Nk);
	const aeadNonce = await kdf.Expand(prk, encodeString("nonce"), suite.AEAD.Nn);

	return { aeadKey, aeadNonce, aead };
}

/**
 * Compute chunk nonce by XORing base nonce with counter (draft-08 Section 6.2)
 * Counter is encoded big-endian, right-aligned to nonce length
 */
export function computeChunkNonce(baseNonce: Uint8Array, counter: number): Uint8Array {
	// Copy base nonce first
	const result = new Uint8Array(baseNonce);
	// XOR counter bytes from the right
	let c = counter;
	for (let i = baseNonce.length - 1; i >= 0 && c > 0; i--) {
		const current = result[i];
		if (current !== undefined) {
			result[i] = current ^ (c & 0xff);
		}
		c = Math.floor(c / 256);
	}
	return result;
}

/**
 * Seal a chunk for response (server-side, draft-08 Section 6.2)
 */
export async function sealResponseChunk(
	aead: AeadImpl,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
	counter: number,
	chunk: Uint8Array,
	isFinal: boolean,
): Promise<Uint8Array> {
	const chunkNonce = computeChunkNonce(baseNonce, counter);
	const aad = isFinal ? FINAL_CHUNK_AAD : new Uint8Array(0);
	return aead.Seal(aeadKey, chunkNonce, aad, chunk);
}

/**
 * Open a chunk from response (client-side, draft-08 Section 6.2)
 */
export async function openResponseChunk(
	aead: AeadImpl,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
	counter: number,
	ciphertext: Uint8Array,
	isFinal: boolean,
): Promise<Uint8Array> {
	const chunkNonce = computeChunkNonce(baseNonce, counter);
	const aad = isFinal ? FINAL_CHUNK_AAD : new Uint8Array(0);
	try {
		return await aead.Open(aeadKey, chunkNonce, aad, ciphertext);
	} catch {
		throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
	}
}
