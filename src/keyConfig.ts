import type { CipherSuite, KeyPair } from "hpke";
import { isOHTTPError, OHTTPError, OHTTPErrorCode } from "./errors.js";

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
 * Note: ChaCha20Poly1305 response encryption requires a runtime with
 * ChaCha20-Poly1305 support (e.g. Node.js 24+). In browsers and Cloudflare
 * Workers, where WebCrypto lacks it, pass a non-WebCrypto AEAD factory via the
 * `responseCrypto` option (e.g. `@panva/hpke-noble`'s `AEAD_ChaCha20Poly1305`).
 */
export const AeadId = {
	AES_128_GCM: 0x0001,
	AES_256_GCM: 0x0002,
	ChaCha20Poly1305: 0x0003,
} as const;

export type AeadId = (typeof AeadId)[keyof typeof AeadId];

/**
 * Wire sizes per KEM: `npk` is the serialized public key, `nenc` the
 * encapsulated key (RFC 9180 Section 7.1, FIPS 203 for ML-KEM).
 *
 * `Record<KemId, ...>` makes adding a KEM to {@link KemId} without its sizes a
 * compile error.
 */
const KEM_SIZES: Record<KemId, { readonly npk: number; readonly nenc: number }> = {
	// Standard KEMs (RFC 9180)
	[KemId.P256_HKDF_SHA256]: { npk: 65, nenc: 65 }, // uncompressed point
	[KemId.P384_HKDF_SHA384]: { npk: 97, nenc: 97 },
	[KemId.P521_HKDF_SHA512]: { npk: 133, nenc: 133 },
	[KemId.X25519_HKDF_SHA256]: { npk: 32, nenc: 32 },
	[KemId.X448_HKDF_SHA512]: { npk: 56, nenc: 56 },
	// Post-quantum KEMs (FIPS 203)
	[KemId.ML_KEM_512]: { npk: 800, nenc: 768 },
	[KemId.ML_KEM_768]: { npk: 1184, nenc: 1088 },
	[KemId.ML_KEM_1024]: { npk: 1568, nenc: 1568 },
	// Hybrid KEMs (ML-KEM + ECDH)
	[KemId.MLKEM768_P256]: { npk: 1184 + 65, nenc: 1088 + 65 },
	[KemId.MLKEM1024_P384]: { npk: 1568 + 97, nenc: 1568 + 97 },
	[KemId.MLKEM768_X25519]: { npk: 1184 + 32, nenc: 1088 + 32 },
};

/**
 * Type guard for valid KEM IDs
 */
export function isValidKemId(id: number): id is KemId {
	return Object.hasOwn(KEM_SIZES, id);
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
 * Get the serialized public key length (Npk) for a KEM
 *
 * @throws OHTTPError if kemId is not a supported KEM
 */
export function getPublicKeyLength(kemId: KemId): number {
	const sizes = KEM_SIZES[kemId];
	if (sizes === undefined) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
	return sizes.npk;
}

/**
 * Get the encapsulated key length (Nenc) for a KEM
 *
 * @param kemId - KEM identifier, validated here
 * @throws OHTTPError if kemId is not a supported KEM
 */
export function getEncLength(kemId: number): number {
	const sizes = KEM_SIZES[kemId as KemId];
	if (sizes === undefined) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
	return sizes.nenc;
}

/**
 * The only symmetric algorithm list a key configuration can honestly advertise
 *
 * A {@link KeyConfigWithPrivate} decrypts every request with its one `suite`,
 * so an extra (KDF, AEAD) pair names a suite the gateway accepts in the header
 * and then fails to open. `symmetricAlgorithms` is therefore optional, and a
 * supplied list must be exactly the suite's own pair.
 *
 * @throws OHTTPError InvalidKeyConfig if the list is anything else,
 * UnsupportedCipherSuite if the suite names a KDF or AEAD this library cannot
 * serialize
 */
function resolveSymmetricAlgorithms(
	suite: CipherSuite,
	provided: readonly SymmetricAlgorithm[] | undefined,
): readonly SymmetricAlgorithm[] {
	const kdfId = suite.KDF.id;
	const aeadId = suite.AEAD.id;
	if (!isValidKdfId(kdfId) || !isValidAeadId(aeadId)) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
	if (provided !== undefined) {
		const only = provided[0];
		if (
			provided.length !== 1 ||
			only === undefined ||
			only.kdfId !== kdfId ||
			only.aeadId !== aeadId
		) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}
	}
	return [{ kdfId, aeadId }];
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
export function serializeKeyConfig(config: KeyConfig): Uint8Array<ArrayBuffer> {
	if (!Number.isInteger(config.keyId) || config.keyId < 0 || config.keyId > 255) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	if (config.publicKey.length !== getPublicKeyLength(config.kemId)) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	// A config with no pairs, or one naming an algorithm this library does not
	// implement, is bytes its own parser refuses.
	if (config.symmetricAlgorithms.length === 0) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	for (const algo of config.symmetricAlgorithms) {
		if (!isValidKdfId(algo.kdfId) || !isValidAeadId(algo.aeadId)) {
			throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		}
	}
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
 *
 * Rejects with {@link OHTTPErrorCode.InvalidKeyConfig} for structural damage
 * and {@link OHTTPErrorCode.UnsupportedCipherSuite} for a KEM this library does
 * not implement, or a config whose every symmetric algorithm is unimplemented.
 * Unimplemented (KDF, AEAD) pairs alongside implemented ones are dropped, per
 * RFC 9458 Section 3.1. Only the latter code is safe for a list to skip.
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
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
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
		if (isValidKdfId(kdfIdRaw) && isValidAeadId(aeadIdRaw)) {
			symmetricAlgorithms.push({ kdfId: kdfIdRaw, aeadId: aeadIdRaw });
		}
		offset += 4;
	}

	// Structural checks come first: parseKeyConfigs skips an UnsupportedCipherSuite
	// but rethrows InvalidKeyConfig, so reporting "unsupported" for bytes that are
	// also malformed would silently drop a damaged config instead of rejecting it.
	if (offset !== data.length) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}
	if (symmetricAlgorithmsLength === 0) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	if (symmetricAlgorithms.length === 0) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
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
export function serializeKeyConfigs(configs: readonly KeyConfig[]): Uint8Array<ArrayBuffer> {
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
 *
 * Configs naming algorithms this library does not implement are skipped, so the
 * result may be empty. Use {@link selectKeyConfig} to pick a usable one rather
 * than reaching for `configs[0]`.
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
		offset += length;

		// Skip configs naming algorithms we lack, so a gateway adding one does not
		// take down the entries we can still use. Structural errors still reject.
		try {
			configs.push(parseKeyConfig(configBytes));
		} catch (err) {
			if (isOHTTPError(err) && err.code === OHTTPErrorCode.UnsupportedCipherSuite) {
				continue;
			}
			throw err;
		}
	}

	return configs;
}

/**
 * Whether `suite` can encapsulate to `config`: same KEM, and a (KDF, AEAD) pair
 * in common (RFC 9458 Section 4.1)
 *
 * The KEM half is easy to forget - a mismatch there produces a client that
 * either fails deep inside HPKE key deserialization or, when the two KEMs
 * happen to share a public key length, silently sends a header advertising a
 * KEM it did not use.
 */
export function supportsKeyConfig(suite: CipherSuite, config: KeyConfig): boolean {
	return (
		config.kemId === suite.KEM.id &&
		config.symmetricAlgorithms.some(
			(algo) => algo.kdfId === suite.KDF.id && algo.aeadId === suite.AEAD.id,
		)
	);
}

/**
 * Pick the first config a `suite` can actually use (RFC 9458 Section 4.1)
 *
 * Throws {@link OHTTPErrorCode.UnsupportedCipherSuite} when none match, so a
 * gateway rotating to a KEM this client lacks fails here rather than at
 * encapsulation. That code from this function means exactly "no offered config
 * matches this suite", which is the case worth catching: re-fetch the key
 * configuration, try another suite, or fall back to a direct request.
 *
 * First match means the gateway's order decides. Where it lists two keys this
 * suite can use, the earlier one wins.
 */
export function selectKeyConfig(suite: CipherSuite, configs: readonly KeyConfig[]): KeyConfig {
	const selected = configs.find((config) => supportsKeyConfig(suite, config));
	if (selected === undefined) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}
	return selected;
}

/**
 * Generate a KeyConfig with a new random key pair
 */
export async function generateKeyConfig(
	suite: CipherSuite,
	keyId: number,
	symmetricAlgorithms?: readonly SymmetricAlgorithm[],
): Promise<KeyConfigWithPrivate> {
	if (keyId < 0 || keyId > 255) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	// Validate KEM ID
	const kemId = suite.KEM.id;
	if (!isValidKemId(kemId)) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	const algorithms = resolveSymmetricAlgorithms(suite, symmetricAlgorithms);

	const keyPair = await suite.GenerateKeyPair(true);
	const publicKey = await suite.SerializePublicKey(keyPair.publicKey);

	return {
		keyId,
		kemId,
		publicKey,
		symmetricAlgorithms: algorithms,
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
	symmetricAlgorithms?: readonly SymmetricAlgorithm[],
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

	const algorithms = resolveSymmetricAlgorithms(suite, symmetricAlgorithms);

	const keyPair = await suite.DeriveKeyPair(seed, true);
	const publicKey = await suite.SerializePublicKey(keyPair.publicKey);

	return {
		keyId,
		kemId,
		publicKey,
		symmetricAlgorithms: algorithms,
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
	symmetricAlgorithms?: readonly SymmetricAlgorithm[],
): Promise<KeyConfigWithPrivate> {
	if (keyId < 0 || keyId > 255) {
		throw new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
	}

	// Validate KEM ID
	const kemId = suite.KEM.id;
	if (!isValidKemId(kemId)) {
		throw new OHTTPError(OHTTPErrorCode.UnsupportedCipherSuite);
	}

	const algorithms = resolveSymmetricAlgorithms(suite, symmetricAlgorithms);

	const publicKey = await suite.DeserializePublicKey(publicKeyBytes);
	const privateKey = await suite.DeserializePrivateKey(privateKeyBytes, true);

	const keyPair: KeyPair = { publicKey, privateKey };

	return {
		keyId,
		kemId,
		publicKey: publicKeyBytes,
		symmetricAlgorithms: algorithms,
		keyPair,
		suite,
	};
}
