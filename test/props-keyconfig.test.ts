/**
 * Property tests for the key configuration wire format (RFC 9458 Sections 3.1
 * and 3.2): `serializeKeyConfig`/`parseKeyConfig` and the `application/
 * ohttp-keys` list format `serializeKeyConfigs`/`parseKeyConfigs`, plus the
 * KEM/KDF/AEAD id tables that back them.
 */

import fc from "fast-check";
import type { KEMFactory } from "hpke";
import {
	KEM_DHKEM_P256_HKDF_SHA256,
	KEM_DHKEM_P384_HKDF_SHA384,
	KEM_DHKEM_P521_HKDF_SHA512,
	KEM_DHKEM_X448_HKDF_SHA512,
	KEM_DHKEM_X25519_HKDF_SHA256,
	KEM_ML_KEM_512,
	KEM_ML_KEM_768,
	KEM_ML_KEM_1024,
	KEM_MLKEM768_P256,
	KEM_MLKEM768_X25519,
	KEM_MLKEM1024_P384,
} from "hpke";
import { describe, expect, it } from "vitest";
import { isOHTTPError, OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	getEncLength,
	getPublicKeyLength,
	isValidAeadId,
	isValidKdfId,
	isValidKemId,
	KdfId,
	KemId,
	type KeyConfig,
	parseKeyConfig,
	parseKeyConfigs,
	type SymmetricAlgorithm,
	serializeKeyConfig,
	serializeKeyConfigs,
} from "../src/keyConfig.js";
import { bytesArb, bytesOfLengthArb } from "./props-helpers.js";

/**
 * Maps every `KemId` to the `hpke` factory implementing it. Declaring this as
 * `Record<KemId, KEMFactory>` makes a `KemId` added without a matching entry
 * here a compile error, the same trick `src/keyConfig.ts` uses for
 * `KEM_SIZES`.
 */
const KEM_FACTORIES: Record<KemId, KEMFactory> = {
	[KemId.P256_HKDF_SHA256]: KEM_DHKEM_P256_HKDF_SHA256,
	[KemId.P384_HKDF_SHA384]: KEM_DHKEM_P384_HKDF_SHA384,
	[KemId.P521_HKDF_SHA512]: KEM_DHKEM_P521_HKDF_SHA512,
	[KemId.X25519_HKDF_SHA256]: KEM_DHKEM_X25519_HKDF_SHA256,
	[KemId.X448_HKDF_SHA512]: KEM_DHKEM_X448_HKDF_SHA512,
	[KemId.ML_KEM_512]: KEM_ML_KEM_512,
	[KemId.ML_KEM_768]: KEM_ML_KEM_768,
	[KemId.ML_KEM_1024]: KEM_ML_KEM_1024,
	[KemId.MLKEM768_P256]: KEM_MLKEM768_P256,
	[KemId.MLKEM1024_P384]: KEM_MLKEM1024_P384,
	[KemId.MLKEM768_X25519]: KEM_MLKEM768_X25519,
};

const kemIdArb: fc.Arbitrary<KemId> = fc.constantFrom(...Object.values(KemId));

const symmetricAlgorithmArb: fc.Arbitrary<SymmetricAlgorithm> = fc.record({
	kdfId: fc.constantFrom(...Object.values(KdfId)),
	aeadId: fc.constantFrom(...Object.values(AeadId)),
});

/** A structurally valid `KeyConfig`: public key length always matches its KEM. */
const configArb: fc.Arbitrary<KeyConfig> = kemIdArb.chain((kemId) =>
	fc.record({
		keyId: fc.integer({ min: 0, max: 255 }),
		kemId: fc.constant(kemId),
		publicKey: bytesOfLengthArb(getPublicKeyLength(kemId)),
		symmetricAlgorithms: fc.array(symmetricAlgorithmArb, { minLength: 1, maxLength: 8 }),
	}),
);

/**
 * Type-only escape hatch used solely to exercise `getPublicKeyLength`'s
 * runtime guard with ids `isValidKemId` rejects. `getPublicKeyLength`'s
 * parameter type is `KemId`, so calling it with an arbitrary rejected id
 * needs the type system to accept a value it would otherwise never admit;
 * this asserts that intent without an `as` cast, mirroring how `isValidKemId`
 * narrows in the other direction.
 */
function assertIsKemId(id: number): asserts id is KemId {}

/** Asserts `parseKeyConfig` either rejects with `OHTTPError`/`InvalidKeyConfig`, or its result re-serializes to exactly `bytes`. */
function assertConfigCanonicalOrRejects(bytes: Uint8Array): void {
	let parsed: KeyConfig;
	try {
		parsed = parseKeyConfig(bytes);
	} catch (err) {
		expect(isOHTTPError(err)).toBe(true);
		if (isOHTTPError(err)) {
			expect(err.code).toBe(OHTTPErrorCode.InvalidKeyConfig);
		}
		return;
	}
	expect(serializeKeyConfig(parsed)).toEqual(bytes);
}

/** Asserts `parseKeyConfigs` either rejects with `OHTTPError`/`InvalidKeyConfig`, or its result re-serializes to exactly `bytes`. */
function assertListCanonicalOrRejects(bytes: Uint8Array): void {
	let parsed: KeyConfig[];
	try {
		parsed = parseKeyConfigs(bytes);
	} catch (err) {
		expect(isOHTTPError(err)).toBe(true);
		if (isOHTTPError(err)) {
			expect(err.code).toBe(OHTTPErrorCode.InvalidKeyConfig);
		}
		return;
	}
	expect(serializeKeyConfigs(parsed)).toEqual(bytes);
}

/** Field offsets within a serialized `KeyConfig`, derived from the config itself rather than by re-parsing. */
function fieldOffsets(config: KeyConfig): { symLenOffset: number; algosOffset: number } {
	const symLenOffset = 3 + config.publicKey.length;
	return { symLenOffset, algosOffset: symLenOffset + 2 };
}

describe("KEM sizes vs. hpke", () => {
	it("getPublicKeyLength/getEncLength match hpke's own Npk/Nenc for every KemId", () => {
		for (const kemId of Object.values(KemId)) {
			const kem = KEM_FACTORIES[kemId]();
			expect(kem.id).toBe(kemId);
			expect(getPublicKeyLength(kemId)).toBe(kem.Npk);
			expect(getEncLength(kemId)).toBe(kem.Nenc);
		}
	});
});

describe("KEM/KDF/AEAD id guards", () => {
	it("isValidKemId/isValidKdfId/isValidAeadId agree with the tables for arbitrary 16-bit ids", () => {
		const kemIds: readonly number[] = Object.values(KemId);
		const kdfIds: readonly number[] = Object.values(KdfId);
		const aeadIds: readonly number[] = Object.values(AeadId);
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 0xffff }), (id) => {
				expect(isValidKemId(id)).toBe(kemIds.includes(id));
				expect(isValidKdfId(id)).toBe(kdfIds.includes(id));
				expect(isValidAeadId(id)).toBe(aeadIds.includes(id));
			}),
		);
	});

	it("getPublicKeyLength/getEncLength throw UnsupportedCipherSuite for every id isValidKemId rejects", () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 0xffff }), (id) => {
				if (isValidKemId(id)) {
					return;
				}
				assertIsKemId(id);
				for (const thunk of [() => getPublicKeyLength(id), () => getEncLength(id)]) {
					expect(thunk).toThrow(OHTTPError);
					try {
						thunk();
					} catch (err) {
						expect(isOHTTPError(err)).toBe(true);
						if (isOHTTPError(err)) {
							expect(err.code).toBe(OHTTPErrorCode.UnsupportedCipherSuite);
						}
					}
				}
			}),
		);
	});
});

describe("KeyConfig round-trip", () => {
	it("serializeKeyConfig -> parseKeyConfig round-trips structurally valid configs", () => {
		fc.assert(
			fc.property(configArb, (config) => {
				const parsed = parseKeyConfig(serializeKeyConfig(config));
				expect(parsed).toEqual(config);
			}),
		);
	});

	it("serializeKeyConfigs -> parseKeyConfigs round-trips lists of 0..4 configs, mixing KEMs", () => {
		fc.assert(
			fc.property(fc.array(configArb, { minLength: 0, maxLength: 4 }), (configs) => {
				const parsed = parseKeyConfigs(serializeKeyConfigs(configs));
				expect(parsed).toEqual(configs);
			}),
		);
	});
});

describe("offset safety", () => {
	it("parsing a KeyConfig embedded at a non-zero byteOffset matches parsing a standalone copy", () => {
		fc.assert(
			fc.property(
				configArb,
				fc.nat({ max: 16 }),
				fc.nat({ max: 16 }),
				(config, prefixLen, suffixLen) => {
					const inner = serializeKeyConfig(config);
					const buffer = new Uint8Array(prefixLen + inner.length + suffixLen);
					buffer.set(inner, prefixLen);
					const embedded = buffer.subarray(prefixLen, prefixLen + inner.length);
					expect(parseKeyConfig(embedded)).toEqual(parseKeyConfig(inner.slice()));
				},
			),
		);
	});

	it("parsing a config list embedded at a non-zero byteOffset matches parsing a standalone copy", () => {
		fc.assert(
			fc.property(
				fc.array(configArb, { minLength: 0, maxLength: 4 }),
				fc.nat({ max: 16 }),
				fc.nat({ max: 16 }),
				(configs, prefixLen, suffixLen) => {
					const inner = serializeKeyConfigs(configs);
					const buffer = new Uint8Array(prefixLen + inner.length + suffixLen);
					buffer.set(inner, prefixLen);
					const embedded = buffer.subarray(prefixLen, prefixLen + inner.length);
					expect(parseKeyConfigs(embedded)).toEqual(parseKeyConfigs(inner.slice()));
				},
			),
		);
	});
});

describe("canonical acceptance: parseKeyConfig", () => {
	/**
	 * Mostly-valid configs with exactly one field perturbed, plus plain random
	 * bytes. `fc.uint8Array` alone essentially never lands on a parseable
	 * shape, so each mutation starts from a real serialized config and
	 * corrupts one part of it.
	 */
	const mutatedConfigBytesArb: fc.Arbitrary<Uint8Array> = fc.oneof(
		// Unknown KEM id.
		fc
			.tuple(
				configArb,
				fc.integer({ min: 0, max: 0xffff }).filter((id) => !isValidKemId(id)),
			)
			.map(([config, badKemId]) => {
				const bytes = serializeKeyConfig(config);
				new DataView(bytes.buffer).setUint16(1, badKemId);
				return bytes;
			}),
		// symAlgosLength not a multiple of 4, shrunk so it still fits within the
		// remaining bytes: this must be rejected on misalignment alone, not on
		// the separate past-the-end bounds check.
		fc.tuple(configArb, fc.integer({ min: 1, max: 3 })).map(([config, delta]) => {
			const bytes = serializeKeyConfig(config);
			const view = new DataView(bytes.buffer);
			const { symLenOffset } = fieldOffsets(config);
			view.setUint16(symLenOffset, view.getUint16(symLenOffset) - delta);
			return bytes;
		}),
		// symAlgosLength not a multiple of 4, grown past the end of the buffer.
		fc.tuple(configArb, fc.integer({ min: 1, max: 3 })).map(([config, delta]) => {
			const bytes = serializeKeyConfig(config);
			const view = new DataView(bytes.buffer);
			const { symLenOffset } = fieldOffsets(config);
			view.setUint16(symLenOffset, (view.getUint16(symLenOffset) + delta) & 0xffff);
			return bytes;
		}),
		// symAlgosLength a multiple of 4 but past the end of the buffer.
		fc.tuple(configArb, fc.integer({ min: 1, max: 16 })).map(([config, extraWords]) => {
			const bytes = serializeKeyConfig(config);
			const view = new DataView(bytes.buffer);
			const { symLenOffset } = fieldOffsets(config);
			view.setUint16(symLenOffset, view.getUint16(symLenOffset) + extraWords * 4);
			return bytes;
		}),
		// Truncated by a random amount (may cut into the public key or the algorithms).
		fc.tuple(configArb, fc.integer({ min: 1, max: 200 })).map(([config, cutSeed]) => {
			const bytes = serializeKeyConfig(config);
			const cut = 1 + (cutSeed % (bytes.length - 1));
			return bytes.slice(0, bytes.length - cut);
		}),
		// Trailing bytes appended after an otherwise valid config.
		fc.tuple(configArb, fc.uint8Array({ minLength: 1, maxLength: 4 })).map(([config, extra]) => {
			const bytes = serializeKeyConfig(config);
			const out = new Uint8Array(bytes.length + extra.length);
			out.set(bytes, 0);
			out.set(extra, bytes.length);
			return out;
		}),
		// Zero declared symmetric algorithms (serializeKeyConfig itself does not reject this).
		configArb.map((config) => serializeKeyConfig({ ...config, symmetricAlgorithms: [] })),
		// Unknown kdfId in the first algorithm slot.
		fc
			.tuple(
				configArb,
				fc.integer({ min: 0, max: 0xffff }).filter((id) => !isValidKdfId(id)),
			)
			.map(([config, badKdfId]) => {
				const bytes = serializeKeyConfig(config);
				const { algosOffset } = fieldOffsets(config);
				new DataView(bytes.buffer).setUint16(algosOffset, badKdfId);
				return bytes;
			}),
		// Unknown aeadId in the first algorithm slot.
		fc
			.tuple(
				configArb,
				fc.integer({ min: 0, max: 0xffff }).filter((id) => !isValidAeadId(id)),
			)
			.map(([config, badAeadId]) => {
				const bytes = serializeKeyConfig(config);
				const { algosOffset } = fieldOffsets(config);
				new DataView(bytes.buffer).setUint16(algosOffset + 2, badAeadId);
				return bytes;
			}),
		// kemId swapped to a (possibly same) KEM, mismatching the actual public key length.
		fc.tuple(configArb, kemIdArb).map(([config, otherKemId]) => {
			const bytes = serializeKeyConfig(config);
			new DataView(bytes.buffer).setUint16(1, otherKemId);
			return bytes;
		}),
		// Unstructured random bytes.
		bytesArb({ maxLength: 300 }),
	);

	it("parseKeyConfig either rejects with InvalidKeyConfig or round-trips exactly", () => {
		fc.assert(
			fc.property(mutatedConfigBytesArb, (bytes) => {
				assertConfigCanonicalOrRejects(bytes);
			}),
		);
	});
});

describe("canonical acceptance: parseKeyConfigs", () => {
	const mutatedListBytesArb: fc.Arbitrary<Uint8Array> = fc.oneof(
		// Valid lists.
		fc.array(configArb, { minLength: 0, maxLength: 4 }).map(serializeKeyConfigs),
		// Length prefix corrupted by a small delta (covers both short and long).
		fc
			.tuple(
				configArb,
				fc.integer({ min: -2, max: 2 }).filter((delta) => delta !== 0),
			)
			.map(([config, delta]) => {
				const inner = serializeKeyConfig(config);
				const blob = new Uint8Array(2 + inner.length);
				new DataView(blob.buffer).setUint16(0, inner.length + delta);
				blob.set(inner, 2);
				return blob;
			}),
		// Trailing bytes appended after an otherwise valid list.
		fc
			.tuple(
				fc.array(configArb, { minLength: 0, maxLength: 3 }),
				fc.uint8Array({ minLength: 1, maxLength: 3 }),
			)
			.map(([configs, extra]) => {
				const bytes = serializeKeyConfigs(configs);
				const out = new Uint8Array(bytes.length + extra.length);
				out.set(bytes, 0);
				out.set(extra, bytes.length);
				return out;
			}),
		// A single byte, too short even for one length prefix.
		fc.uint8Array({ minLength: 1, maxLength: 1 }),
		// Unstructured random bytes.
		bytesArb({ maxLength: 300 }),
	);

	it("parseKeyConfigs either rejects with InvalidKeyConfig or round-trips exactly", () => {
		fc.assert(
			fc.property(mutatedListBytesArb, (bytes) => {
				assertListCanonicalOrRejects(bytes);
			}),
		);
	});
});
