import type { CipherSuite, KeyPair } from "hpke";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";

/**
 * HPKE KEM identifiers (RFC 9458 Section 3.1)
 *
 * Includes post-quantum ML-KEM variants from @panva/hpke-noble
 */
export const KemId = {
	// Standard KEMs (RFC 9180)
	P256_HKDF_SHA256: 0x0010,
	P384_HKDF_SHA384: 0x0011,
	P521_HKDF_SHA512: 0x0012,
	X25519_HKDF_SHA256: 0x0020,
	X448_HKDF_SHA512: 0x0021,
	// Post-quantum KEMs (ML-KEM, FIPS 203)
	ML_KEM_512: 0x0040,
	ML_KEM_768: 0x0041,
	ML_KEM_1024: 0x0042,
	// Hybrid KEMs
	MLKEM768_P256: 0x0050,
	MLKEM1024_P384: 0x0051,
	MLKEM768_X25519: 0x647a,
} as const;

export type KemId = (typeof KemId)[keyof typeof KemId];

/**
 * HPKE KDF identifiers (RFC 9458 Section 3.1)
 */
export const KdfId = {
	HKDF_SHA256: 0x0001,
	HKDF_SHA384: 0x0002,
	HKDF_SHA512: 0x0003,
} as const;

export type KdfId = (typeof KdfId)[keyof typeof KdfId];

/**
 * HPKE AEAD identifiers (RFC 9458 Section 3.1)
 *
 * Note: ChaCha20Poly1305 is defined for KeyConfig parsing but not implemented
 * for encryption. WebCrypto doesn't support ChaCha20-Poly1305 natively.
 * Use AES_128_GCM or AES_256_GCM for actual operations.
 */
export const AeadId = {
	AES_128_GCM: 0x0001,
	AES_256_GCM: 0x0002,
	/** Defined for parsing; not implemented for encryption (use AES-GCM) */
	ChaCha20Poly1305: 0x0003,
} as const;

export type AeadId = (typeof AeadId)[keyof typeof AeadId];

/**
 * Type guard for valid KEM IDs
 */
export function isValidKemId(id: number): id is KemId {
	return (
		// Standard KEMs
		id === KemId.P256_HKDF_SHA256 ||
		id === KemId.P384_HKDF_SHA384 ||
		id === KemId.P521_HKDF_SHA512 ||
		id === KemId.X25519_HKDF_SHA256 ||
		id === KemId.X448_HKDF_SHA512 ||
		// Post-quantum KEMs
		id === KemId.ML_KEM_512 ||
		id === KemId.ML_KEM_768 ||
		id === KemId.ML_KEM_1024 ||
		// Hybrid KEMs
		id === KemId.MLKEM768_P256 ||
		id === KemId.MLKEM1024_P384 ||
		id === KemId.MLKEM768_X25519
	);
}

/**
 * Type guard for valid KDF IDs
 */
export function isValidKdfId(id: number): id is KdfId {
	return id === KdfId.HKDF_SHA256 || id === KdfId.HKDF_SHA384 || id === KdfId.HKDF_SHA512;
}

/**
 * Type guard for valid AEAD IDs
 */
export function isValidAeadId(id: number): id is AeadId {
	return id === AeadId.AES_128_GCM || id === AeadId.AES_256_GCM || id === AeadId.ChaCha20Poly1305;
}

/**
 * A symmetric algorithm pair (KDF + AEAD)
 */
export interface SymmetricAlgorithm {
	readonly kdfId: KdfId;
	readonly aeadId: AeadId;
}

/**
 * Key configuration for OHTTP (RFC 9458 Section 3.1)
 */
export interface KeyConfig {
	/** Key identifier (0-255) */
	readonly keyId: number;
	/** KEM identifier */
	readonly kemId: KemId;
	/** Public key bytes */
	readonly publicKey: Uint8Array;
	/** Supported symmetric algorithms */
	readonly symmetricAlgorithms: readonly SymmetricAlgorithm[];
}

/**
 * Key configuration with private key for server use
 */
export interface KeyConfigWithPrivate extends KeyConfig {
	/** HPKE key pair */
	readonly keyPair: KeyPair;
	/** HPKE cipher suite */
	readonly suite: CipherSuite;
}

/**
 * Get public key length for a KEM
 */
export function getPublicKeyLength(kemId: KemId): number {
	switch (kemId) {
		// Standard KEMs
		case KemId.X25519_HKDF_SHA256:
			return 32;
		case KemId.X448_HKDF_SHA512:
			return 56;
		case KemId.P256_HKDF_SHA256:
			return 65; // Uncompressed point
		case KemId.P384_HKDF_SHA384:
			return 97;
		case KemId.P521_HKDF_SHA512:
			return 133;
		// ML-KEM (FIPS 203)
		case KemId.ML_KEM_512:
			return 800;
		case KemId.ML_KEM_768:
			return 1184;
		case KemId.ML_KEM_1024:
			return 1568;
		// Hybrid KEMs (ML-KEM + ECDH)
		case KemId.MLKEM768_P256:
			return 1184 + 65; // ML-KEM-768 + P-256 uncompressed
		case KemId.MLKEM1024_P384:
			return 1568 + 97; // ML-KEM-1024 + P-384 uncompressed
		case KemId.MLKEM768_X25519:
			return 1184 + 32; // ML-KEM-768 + X25519
		default:
			throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
}

/**
 * Serialize a KeyConfig to bytes (RFC 9458 Section 3.1)
 *
 * Format:
 * - Key Identifier (1 byte)
 * - HPKE KEM ID (2 bytes)
 * - HPKE Public Key (Npk bytes)
 * - Symmetric Algorithms Length (2 bytes)
 * - Symmetric Algorithms (4 bytes each: KDF ID + AEAD ID)
 */
export function serializeKeyConfig(config: KeyConfig): Uint8Array {
	const symAlgosLen = config.symmetricAlgorithms.length * 4;
	// keyId(1) + kemId(2) + publicKey + symAlgosLen(2) + symAlgos
	const totalLen = 1 + 2 + config.publicKey.length + 2 + symAlgosLen;
	const result = new Uint8Array(totalLen);
	const view = new DataView(result.buffer);

	let offset = 0;
	view.setUint8(offset, config.keyId);
	offset += 1;
	view.setUint16(offset, config.kemId);
	offset += 2;
	result.set(config.publicKey, offset);
	offset += config.publicKey.length;
	view.setUint16(offset, symAlgosLen);
	offset += 2;

	for (const algo of config.symmetricAlgorithms) {
		view.setUint16(offset, algo.kdfId);
		view.setUint16(offset + 2, algo.aeadId);
		offset += 4;
	}

	return result;
}

/**
 * Parse a KeyConfig from bytes (RFC 9458 Section 3.1)
 */
export function parseKeyConfig(data: Uint8Array): KeyConfig {
	if (data.length < 7) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let offset = 0;

	// Key Identifier (1 byte)
	const keyId = view.getUint8(offset);
	offset += 1;

	// KEM ID (2 bytes)
	const kemIdRaw = view.getUint16(offset);
	if (!isValidKemId(kemIdRaw)) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	const kemId = kemIdRaw;
	offset += 2;

	// Public key (Npk bytes based on KEM)
	const publicKeyLength = getPublicKeyLength(kemId);
	if (offset + publicKeyLength > data.length) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	const publicKey = data.slice(offset, offset + publicKeyLength);
	offset += publicKeyLength;

	// Symmetric Algorithms Length (2 bytes)
	if (offset + 2 > data.length) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	const symmetricAlgorithmsLength = view.getUint16(offset);
	offset += 2;

	// Symmetric algorithms must be multiple of 4 bytes
	if (symmetricAlgorithmsLength % 4 !== 0) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	if (offset + symmetricAlgorithmsLength > data.length) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	const symmetricAlgorithms: SymmetricAlgorithm[] = [];
	const endOffset = offset + symmetricAlgorithmsLength;
	while (offset < endOffset) {
		const kdfIdRaw = view.getUint16(offset);
		const aeadIdRaw = view.getUint16(offset + 2);
		if (!isValidKdfId(kdfIdRaw) || !isValidAeadId(aeadIdRaw)) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}
		symmetricAlgorithms.push({ kdfId: kdfIdRaw, aeadId: aeadIdRaw });
		offset += 4;
	}

	if (symmetricAlgorithms.length === 0) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	// Validate no trailing data
	if (offset !== data.length) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	return {
		keyId,
		kemId,
		publicKey,
		symmetricAlgorithms,
	};
}

/**
 * Serialize key configurations to application/ohttp-keys format (RFC 9458 Section 3.2)
 *
 * Format: For each config: 2-byte length prefix + serialized KeyConfig
 */
export function serializeKeyConfigs(configs: readonly KeyConfig[]): Uint8Array {
	// First pass: serialize all configs and calculate total size
	const serialized: Uint8Array[] = [];
	let totalLen = 0;
	for (const config of configs) {
		const s = serializeKeyConfig(config);
		serialized.push(s);
		totalLen += 2 + s.length; // 2-byte length prefix + config
	}

	// Second pass: write to result buffer
	const result = new Uint8Array(totalLen);
	const view = new DataView(result.buffer);
	let offset = 0;
	for (const s of serialized) {
		view.setUint16(offset, s.length);
		offset += 2;
		result.set(s, offset);
		offset += s.length;
	}

	return result;
}

/**
 * Parse application/ohttp-keys format to KeyConfig array (RFC 9458 Section 3.2)
 */
export function parseKeyConfigs(data: Uint8Array): KeyConfig[] {
	const configs: KeyConfig[] = [];
	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let offset = 0;

	while (offset < data.length) {
		if (offset + 2 > data.length) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}

		const length = view.getUint16(offset);
		offset += 2;

		if (offset + length > data.length) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}

		const configBytes = data.slice(offset, offset + length);
		configs.push(parseKeyConfig(configBytes));
		offset += length;
	}

	return configs;
}

/**
 * Generate a KeyConfig with a new random key pair
 */
export async function generateKeyConfig(
	suite: CipherSuite,
	keyId: number,
	symmetricAlgorithms: readonly SymmetricAlgorithm[],
): Promise<KeyConfigWithPrivate> {
	if (keyId < 0 || keyId > 255) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	// Validate KEM ID
	const kemId = suite.KEM.id;
	if (!isValidKemId(kemId)) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	const keyPair = await suite.GenerateKeyPair(true);
	const publicKey = await suite.SerializePublicKey(keyPair.publicKey);

	return {
		keyId,
		kemId,
		publicKey,
		symmetricAlgorithms,
		keyPair,
		suite,
	};
}

/**
 * Derive a deterministic KeyConfig from a seed (for testing)
 *
 * Uses HPKE's DeriveKeyPair(ikm) for deterministic key generation.
 */
export async function deriveKeyConfig(
	suite: CipherSuite,
	seed: Uint8Array,
	keyId: number,
	symmetricAlgorithms: readonly SymmetricAlgorithm[],
): Promise<KeyConfigWithPrivate> {
	if (keyId < 0 || keyId > 255) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	if (seed.length < suite.KEM.Nsk) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	// Validate KEM ID
	const kemId = suite.KEM.id;
	if (!isValidKemId(kemId)) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	const keyPair = await suite.DeriveKeyPair(seed, true);
	const publicKey = await suite.SerializePublicKey(keyPair.publicKey);

	return {
		keyId,
		kemId,
		publicKey,
		symmetricAlgorithms,
		keyPair,
		suite,
	};
}

/**
 * Import a key pair to create a KeyConfigWithPrivate
 *
 * Both public and private key bytes are required since deriving the public key
 * from the private key is KEM-specific and not exposed by the hpke library.
 *
 * @param suite - HPKE cipher suite
 * @param keyId - Key identifier (0-255)
 * @param publicKeyBytes - Serialized public key
 * @param privateKeyBytes - Serialized private key
 * @param symmetricAlgorithms - Supported symmetric algorithms
 */
export async function importKeyConfig(
	suite: CipherSuite,
	keyId: number,
	publicKeyBytes: Uint8Array,
	privateKeyBytes: Uint8Array,
	symmetricAlgorithms: readonly SymmetricAlgorithm[],
): Promise<KeyConfigWithPrivate> {
	if (keyId < 0 || keyId > 255) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	// Validate KEM ID
	const kemId = suite.KEM.id;
	if (!isValidKemId(kemId)) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	const publicKey = await suite.DeserializePublicKey(publicKeyBytes);
	const privateKey = await suite.DeserializePrivateKey(privateKeyBytes, true);

	const keyPair: KeyPair = { publicKey, privateKey };

	return {
		keyId,
		kemId,
		publicKey: publicKeyBytes,
		symmetricAlgorithms,
		keyPair,
		suite,
	};
}
