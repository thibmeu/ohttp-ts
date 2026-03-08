import type { CipherSuite, Key, RecipientContext, SenderContext } from "hpke";
import { encode as encodeVarint, decode as decodeVarint } from "quicvarint";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import { KemId, type AeadId, type KdfId, type KeyConfig, type KeyConfigWithPrivate } from "./keyConfig.js";
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
export function parseRequestHeader(
	data: Uint8Array,
): { header: EncapsulatedRequestHeader; offset: number } {
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
): Promise<Uint8Array> {
	const { recipientContext, enc, suite } = serverContext;

	const nonceLength = getResponseNonceLength(suite);
	if (responseNonce.length !== nonceLength) {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	// Export secret from HPKE context
	const secret = await recipientContext.Export(encodeString(label), nonceLength);

	// Derive AEAD key and nonce using HKDF
	// salt = concat(enc, response_nonce)
	const salt = concat(enc, responseNonce);

	// Use the KDF from the suite to derive key and nonce
	// prk = Extract(salt, secret)
	// aead_key = Expand(prk, "key", Nk)
	// aead_nonce = Expand(prk, "nonce", Nn)

	// We need to manually do HKDF here since we need raw AEAD operations
	// For now, we'll use the suite's internal KDF if available

	// Actually, we need to use raw AEAD. Let's compute the key material directly.
	// This requires access to the underlying KDF, which the hpke library exposes.

	// Get the HKDF functions from the suite
	const kdf = suite.KDF;

	// Extract PRK
	const labeledSecret = secret;
	const prk = await extractPrk(kdf, salt, labeledSecret);

	// Expand to get key and nonce
	const aeadKey = await expandPrk(kdf, prk, encodeString("key"), suite.AEAD.Nk);
	const aeadNonce = await expandPrk(kdf, prk, encodeString("nonce"), suite.AEAD.Nn);

	// Encrypt response using raw AEAD
	const aead = suite.AEAD;
	const ct = await sealWithRawAead(aead, aeadKey, aeadNonce, new Uint8Array(0), response);

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
	const kdf = suite.KDF;
	const prk = await extractPrk(kdf, salt, secret);
	const aeadKey = await expandPrk(kdf, prk, encodeString("key"), suite.AEAD.Nk);
	const aeadNonce = await expandPrk(kdf, prk, encodeString("nonce"), suite.AEAD.Nn);

	// Decrypt response
	const aead = suite.AEAD;
	try {
		return await openWithRawAead(aead, aeadKey, aeadNonce, new Uint8Array(0), ciphertext);
	} catch {
		throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
	}
}

// Helper functions for HKDF operations using the suite's KDF

/**
 * Convert Uint8Array to ArrayBuffer (handles SharedArrayBuffer case)
 */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
	// Create a new ArrayBuffer and copy the data
	const buffer = new ArrayBuffer(data.byteLength);
	new Uint8Array(buffer).set(data);
	return buffer;
}

async function extractPrk(
	kdf: CipherSuite["KDF"],
	salt: Uint8Array,
	ikm: Uint8Array,
): Promise<Uint8Array> {
	// HKDF-Extract using HMAC
	// We need to use SubtleCrypto directly since the hpke library's KDF interface
	// doesn't expose raw Extract/Expand directly in the way we need

	// For HKDF-SHA256, we use the Web Crypto API
	const algorithm = kdf.name.includes("256")
		? "SHA-256"
		: kdf.name.includes("384")
			? "SHA-384"
			: "SHA-512";

	// Convert to ArrayBuffer for WebCrypto compatibility
	const saltBuffer = toArrayBuffer(salt);
	const ikmBuffer = toArrayBuffer(ikm);

	const key = await crypto.subtle.importKey("raw", saltBuffer, { name: "HMAC", hash: algorithm }, false, [
		"sign",
	]);

	const prk = await crypto.subtle.sign("HMAC", key, ikmBuffer);
	return new Uint8Array(prk);
}

async function expandPrk(
	kdf: CipherSuite["KDF"],
	prk: Uint8Array,
	info: Uint8Array,
	length: number,
): Promise<Uint8Array> {
	const algorithm = kdf.name.includes("256")
		? "SHA-256"
		: kdf.name.includes("384")
			? "SHA-384"
			: "SHA-512";

	const hashLen = kdf.Nh;
	const n = Math.ceil(length / hashLen);
	const okm = new Uint8Array(n * hashLen);

	// Convert to ArrayBuffer for WebCrypto compatibility
	const prkBuffer = toArrayBuffer(prk);

	const key = await crypto.subtle.importKey("raw", prkBuffer, { name: "HMAC", hash: algorithm }, false, [
		"sign",
	]);

	let t = new Uint8Array(0);
	for (let i = 1; i <= n; i++) {
		const input = concat(t, info, new Uint8Array([i]));
		const inputBuffer = toArrayBuffer(input);
		const block = await crypto.subtle.sign("HMAC", key, inputBuffer);
		t = new Uint8Array(block);
		okm.set(t, (i - 1) * hashLen);
	}

	return okm.slice(0, length);
}

async function sealWithRawAead(
	aead: CipherSuite["AEAD"],
	key: Uint8Array,
	nonce: Uint8Array,
	aad: Uint8Array,
	plaintext: Uint8Array,
): Promise<Uint8Array> {
	const algorithm = aead.name.includes("AES") ? "AES-GCM" : "ChaCha20-Poly1305";

	if (algorithm === "AES-GCM") {
		// Convert to ArrayBuffer for WebCrypto compatibility
		const keyBuffer = toArrayBuffer(key);
		const nonceBuffer = toArrayBuffer(nonce);
		const aadBuffer = toArrayBuffer(aad);
		const plaintextBuffer = toArrayBuffer(plaintext);

		const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM" }, false, [
			"encrypt",
		]);
		const ct = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: nonceBuffer, additionalData: aadBuffer },
			cryptoKey,
			plaintextBuffer,
		);
		return new Uint8Array(ct);
	}
	// ChaCha20-Poly1305 not supported: WebCrypto lacks native support
	throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
}

async function openWithRawAead(
	aead: CipherSuite["AEAD"],
	key: Uint8Array,
	nonce: Uint8Array,
	aad: Uint8Array,
	ciphertext: Uint8Array,
): Promise<Uint8Array> {
	const algorithm = aead.name.includes("AES") ? "AES-GCM" : "ChaCha20-Poly1305";

	if (algorithm === "AES-GCM") {
		// Convert to ArrayBuffer for WebCrypto compatibility
		const keyBuffer = toArrayBuffer(key);
		const nonceBuffer = toArrayBuffer(nonce);
		const aadBuffer = toArrayBuffer(aad);
		const ciphertextBuffer = toArrayBuffer(ciphertext);

		const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM" }, false, [
			"decrypt",
		]);
		const pt = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: nonceBuffer, additionalData: aadBuffer },
			cryptoKey,
			ciphertextBuffer,
		);
		return new Uint8Array(pt);
	}
	// ChaCha20-Poly1305 not supported: WebCrypto lacks native support
	throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
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
): Promise<{ aeadKey: Uint8Array; aeadNonce: Uint8Array }> {
	const nonceLength = getResponseNonceLength(suite);

	// Export secret from HPKE context
	const secret = await context.Export(encodeString(label), nonceLength);

	// salt = concat(enc, response_nonce)
	const salt = concat(enc, responseNonce);

	// Derive PRK and expand to key/nonce
	const kdf = suite.KDF;
	const prk = await extractPrk(kdf, salt, secret);
	const aeadKey = await expandPrk(kdf, prk, encodeString("key"), suite.AEAD.Nk);
	const aeadNonce = await expandPrk(kdf, prk, encodeString("nonce"), suite.AEAD.Nn);

	return { aeadKey, aeadNonce };
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
	suite: CipherSuite,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
	counter: number,
	chunk: Uint8Array,
	isFinal: boolean,
): Promise<Uint8Array> {
	const chunkNonce = computeChunkNonce(baseNonce, counter);
	const aad = isFinal ? FINAL_CHUNK_AAD : new Uint8Array(0);
	return sealWithRawAead(suite.AEAD, aeadKey, chunkNonce, aad, chunk);
}

/**
 * Open a chunk from response (client-side, draft-08 Section 6.2)
 */
export async function openResponseChunk(
	suite: CipherSuite,
	aeadKey: Uint8Array,
	baseNonce: Uint8Array,
	counter: number,
	ciphertext: Uint8Array,
	isFinal: boolean,
): Promise<Uint8Array> {
	const chunkNonce = computeChunkNonce(baseNonce, counter);
	const aad = isFinal ? FINAL_CHUNK_AAD : new Uint8Array(0);
	try {
		return await openWithRawAead(suite.AEAD, aeadKey, chunkNonce, aad, ciphertext);
	} catch {
		throw new OHTTPError(OHTTPErrorCode.DecryptionFailed);
	}
}
