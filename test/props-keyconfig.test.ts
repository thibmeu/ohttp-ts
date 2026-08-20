/**
 * Property tests for the key configuration wire format (RFC 9458 Sections 3.1
 * and 3.2): `serializeKeyConfig`/`parseKeyConfig` and the `application/
 * ohttp-keys` list format `serializeKeyConfigs`/`parseKeyConfigs`, plus the
 * KEM/KDF/AEAD id tables that back them.
 */

import { fc, it } from "@fast-check/vitest";
import type { KEMFactory } from "hpke";
import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
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
import { describe, expect } from "vitest";
import { ChunkedOHTTPClient, OHTTPClient } from "../src/client.js";
import { isOHTTPError, OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	generateKeyConfig,
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
	selectKeyConfig,
	serializeKeyConfig,
	serializeKeyConfigs,
} from "../src/keyConfig.js";
import { OHTTPServer } from "../src/server.js";
import { bytesArb, bytesOfLengthArb } from "./props-helpers.js";
import { toHex } from "./test-utils.js";

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

const idArb = fc.integer({ min: 0, max: 0xffff });

/** 16-bit ids the KEM table does not know about. */
const unknownKemIdArb = idArb.filter((id) => !isValidKemId(id));

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

const configListArb = fc.array(configArb, { minLength: 0, maxLength: 4 });

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
	it.prop([idArb])(
		"isValidKemId/isValidKdfId/isValidAeadId agree with the tables for arbitrary 16-bit ids",
		(id) => {
			const kemIds: readonly number[] = Object.values(KemId);
			const kdfIds: readonly number[] = Object.values(KdfId);
			const aeadIds: readonly number[] = Object.values(AeadId);
			expect(isValidKemId(id)).toBe(kemIds.includes(id));
			expect(isValidKdfId(id)).toBe(kdfIds.includes(id));
			expect(isValidAeadId(id)).toBe(aeadIds.includes(id));
		},
	);

	it.prop([unknownKemIdArb])(
		"getPublicKeyLength/getEncLength throw UnsupportedCipherSuite for every id isValidKemId rejects",
		(id) => {
			assertIsKemId(id);
			for (const thunk of [() => getPublicKeyLength(id), () => getEncLength(id)]) {
				expect(thunk).toThrow(OHTTPError);
				expect(catchOHTTPError(thunk).code).toBe(OHTTPErrorCode.UnsupportedCipherSuite);
			}
		},
	);
});

describe("KeyConfig round-trip", () => {
	it.prop([configArb])(
		"serializeKeyConfig -> parseKeyConfig round-trips structurally valid configs",
		(config) => {
			expect(parseKeyConfig(serializeKeyConfig(config))).toEqual(config);
		},
	);

	it.prop([configListArb])(
		"serializeKeyConfigs -> parseKeyConfigs round-trips lists of 0..4 configs, mixing KEMs",
		(configs) => {
			expect(parseKeyConfigs(serializeKeyConfigs(configs))).toEqual(configs);
		},
	);
});

describe("offset safety", () => {
	it.prop([configArb, fc.nat({ max: 16 }), fc.nat({ max: 16 })])(
		"parsing a KeyConfig embedded at a non-zero byteOffset matches parsing a standalone copy",
		(config, prefixLen, suffixLen) => {
			const inner = serializeKeyConfig(config);
			const embedded = embedAt(inner, prefixLen, suffixLen);
			expect(parseKeyConfig(embedded)).toEqual(parseKeyConfig(inner.slice()));
		},
	);

	it.prop([configListArb, fc.nat({ max: 16 }), fc.nat({ max: 16 })])(
		"parsing a config list embedded at a non-zero byteOffset matches parsing a standalone copy",
		(configs, prefixLen, suffixLen) => {
			const inner = serializeKeyConfigs(configs);
			const embedded = embedAt(inner, prefixLen, suffixLen);
			expect(parseKeyConfigs(embedded)).toEqual(parseKeyConfigs(inner.slice()));
		},
	);
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
		fc.tuple(configArb, unknownKemIdArb).map(([config, badKemId]) => {
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
		fc
			.tuple(configArb, fc.uint8Array({ minLength: 1, maxLength: 4 }))
			.map(([config, extra]) => appendBytes(serializeKeyConfig(config), extra)),
		// Zero declared symmetric algorithms (serializeKeyConfig itself does not reject this).
		configArb.map((config) => serializeKeyConfig({ ...config, symmetricAlgorithms: [] })),
		// Unknown kdfId in the first algorithm slot.
		fc
			.tuple(
				configArb,
				idArb.filter((id) => !isValidKdfId(id)),
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
				idArb.filter((id) => !isValidAeadId(id)),
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

	it.prop([mutatedConfigBytesArb])(
		"parseKeyConfig either rejects or round-trips exactly, minus unimplemented pairs",
		(bytes) => {
			assertCanonicalOrRejects(bytes);
		},
	);
});

describe("canonical acceptance: parseKeyConfigs", () => {
	const mutatedListBytesArb: fc.Arbitrary<Uint8Array> = fc.oneof(
		// Valid lists.
		configListArb.map(serializeKeyConfigs),
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
			.map(([configs, extra]) => appendBytes(serializeKeyConfigs(configs), extra)),
		// A single byte, too short even for one length prefix.
		fc.uint8Array({ minLength: 1, maxLength: 1 }),
		// Unstructured random bytes.
		bytesArb({ maxLength: 300 }),
	);

	it.prop([mutatedListBytesArb])(
		"parseKeyConfigs either rejects or returns configs that are byte-exact slices of the input",
		(bytes) => {
			assertSubsequenceOrRejects(bytes);
		},
	);
});

describe("list tolerance", () => {
	const suite = () =>
		new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

	/** A usable config, plus the same bytes with the KEM id set to one we lack. */
	async function pair() {
		const priv = await generateKeyConfig(suite(), 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		const good = serializeKeyConfig(priv);
		const other = new Uint8Array(good);
		new DataView(other.buffer).setUint16(1, 0xffff);
		return { good, other };
	}

	function list(...configs: Uint8Array[]): Uint8Array {
		const total = configs.reduce((n, c) => n + 2 + c.length, 0);
		const out = new Uint8Array(total);
		const view = new DataView(out.buffer);
		let offset = 0;
		for (const c of configs) {
			view.setUint16(offset, c.length);
			out.set(c, offset + 2);
			offset += 2 + c.length;
		}
		return out;
	}

	// Forward compatibility: a gateway that adds a KEM we do not implement must
	// not take down the entry we can still use.
	it("skips a config naming an unimplemented KEM and keeps the rest", async () => {
		const { good, other } = await pair();

		expect(parseKeyConfigs(list(other, good))).toHaveLength(1);
		expect(parseKeyConfigs(list(good, other))).toHaveLength(1);
		const [survivor] = parseKeyConfigs(list(other, good));
		expect(survivor).toBeDefined();
		if (survivor === undefined) throw new Error("unreachable");
		expect(serializeKeyConfig(survivor)).toEqual(good);
	});

	// RFC 9458 Section 3.1 has the client pick a mutually supported pair from the
	// list, so an unimplemented pair costs its own slot, not the whole config.
	it("drops an unimplemented pair but keeps the config's usable ones", async () => {
		const priv = await generateKeyConfig(suite(), 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.ChaCha20Poly1305 },
		]);
		const bytes = serializeKeyConfig(priv);
		new DataView(bytes.buffer).setUint16(bytes.length - 2, 0xffff);

		expect(parseKeyConfig(bytes).symmetricAlgorithms).toEqual([
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
	});

	it("skips a config whose every pair is unimplemented", async () => {
		const priv = await generateKeyConfig(suite(), 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		const good = serializeKeyConfig(priv);
		const other = new Uint8Array(good);
		new DataView(other.buffer).setUint16(other.length - 2, 0xffff);

		expect(parseKeyConfigs(list(other, good))).toHaveLength(1);
	});

	// Malformed bytes are a tampering signal, not registry evolution, so they
	// must not be quietly skipped the way an unknown algorithm is.
	it("rejects the whole list when a record is structurally damaged", async () => {
		const { good } = await pair();
		const truncated = good.subarray(0, good.length - 1);

		expect(() => parseKeyConfigs(list(truncated, good))).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
	});

	it("returns an empty list when nothing is usable, as it does for empty input", async () => {
		const { other } = await pair();

		expect(parseKeyConfigs(list(other, other))).toEqual([]);
		expect(parseKeyConfigs(new Uint8Array(0))).toEqual([]);
	});
});

describe("selectKeyConfig", () => {
	const suite = () =>
		new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

	// Spoofing `kemId` leaves a 32-byte X25519 public key where ML-KEM-768 wants
	// 1184, which is the point: a length-compatible mismatch is the case that
	// slips past HPKE deserialization and onto the wire.
	async function config(keyId: number, algos: readonly SymmetricAlgorithm[], kemId?: KemId) {
		const priv = await generateKeyConfig(suite(), keyId, algos);
		return kemId === undefined ? priv : { ...priv, kemId };
	}

	it("skips a config the suite's KEM cannot use", async () => {
		const mlKem = await config(
			1,
			[{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }],
			0x0041,
		);
		const usable = await config(2, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]);

		expect(selectKeyConfig(suite(), [mlKem, usable]).keyId).toBe(2);
	});

	it("skips a config with no mutually supported symmetric algorithm", async () => {
		const chachaOnly = await config(1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.ChaCha20Poly1305 },
		]);
		const usable = await config(2, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]);

		expect(selectKeyConfig(suite(), [chachaOnly, usable]).keyId).toBe(2);
	});

	it("keeps the gateway's order among usable configs", async () => {
		const first = await config(1, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]);
		const second = await config(2, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]);

		expect(selectKeyConfig(suite(), [first, second]).keyId).toBe(1);
	});

	it("throws UnsupportedCipherSuite when nothing matches", async () => {
		const mlKem = await config(
			1,
			[{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }],
			0x0041,
		);

		expect(() => selectKeyConfig(suite(), [mlKem])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.UnsupportedCipherSuite }),
		);
		expect(() => selectKeyConfig(suite(), [])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.UnsupportedCipherSuite }),
		);
	});

	// The pairing that matters: parse tolerates, select decides.
	it("picks the survivor of a list whose first record names an unimplemented KEM", async () => {
		const usable = await config(7, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]);
		const good = serializeKeyConfig(usable);
		const other = new Uint8Array(good);
		new DataView(other.buffer).setUint16(1, 0xffff);
		const blob = new Uint8Array(4 + other.length + good.length);
		const view = new DataView(blob.buffer);
		view.setUint16(0, other.length);
		blob.set(other, 2);
		view.setUint16(2 + other.length, good.length);
		blob.set(good, 4 + other.length);

		expect(selectKeyConfig(suite(), parseKeyConfigs(blob)).keyId).toBe(7);
	});

	// The contract is "fails here rather than at encapsulation", which only holds
	// if what select returns is exactly what the client accepts.
	it("returns a config the client accepts and can round-trip", async () => {
		const usable = await config(3, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]);
		const selected = selectKeyConfig(suite(), [usable]);

		const client = new OHTTPClient(suite(), selected);
		const server = new OHTTPServer([usable]);
		const payload = new Uint8Array([0x00, 0x03, 0x47, 0x45, 0x54]);

		const { encapsulatedRequest } = await client.encapsulate(payload);
		const { request } = await server.decapsulate(encapsulatedRequest);

		expect(request).toEqual(payload);
	});

	// Both clients used to check the KDF and AEAD but not the KEM, so a config
	// select rejects would construct, then either fail deep inside HPKE or send a
	// header naming a KEM it never used.
	it.each([
		["OHTTPClient", (c: KeyConfig) => new OHTTPClient(suite(), c)],
		["ChunkedOHTTPClient", (c: KeyConfig) => new ChunkedOHTTPClient(suite(), c)],
	])("%s rejects a config select would skip for its KEM", async (_name, construct) => {
		const mlKem = await config(
			1,
			[{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }],
			KemId.ML_KEM_768,
		);

		expect(() => construct(mlKem)).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.UnsupportedCipherSuite }),
		);
	});
});

// Helpers

/**
 * Type-only escape hatch used solely to exercise `getPublicKeyLength`'s
 * runtime guard with ids `isValidKemId` rejects. `getPublicKeyLength`'s
 * parameter type is `KemId`, so calling it with an arbitrary rejected id
 * needs the type system to accept a value it would otherwise never admit;
 * this asserts that intent without an `as` cast, mirroring how `isValidKemId`
 * narrows in the other direction.
 */
function assertIsKemId(id: number): asserts id is KemId {}

/** Run `fn`, returning the OHTTPError it threw. Fails the test if it throws anything else, or nothing. */
function catchOHTTPError(fn: () => unknown): OHTTPError {
	try {
		fn();
	} catch (err) {
		if (isOHTTPError(err)) {
			return err;
		}
		throw err;
	}
	throw new Error("expected an OHTTPError to be thrown");
}

/**
 * Asserts `parseKeyConfig` either rejects `bytes`, or produces something that
 * re-encodes to exactly `bytes` minus the (KDF, AEAD) pairs it is allowed to
 * drop - so no input is accepted into a value that would re-encode differently.
 */
function assertCanonicalOrRejects(bytes: Uint8Array): void {
	let parsed: KeyConfig;
	try {
		parsed = parseKeyConfig(bytes);
	} catch (err) {
		assertRejection(bytes, err);
		return;
	}
	expect(toHex(serializeKeyConfig(parsed))).toBe(toHex(dropUnknownPairs(bytes, parsed)));
}

/**
 * Structural damage must never be skippable, so `UnsupportedCipherSuite` is
 * reserved for a record that is intact apart from naming algorithms we lack.
 */
function assertRejection(bytes: Uint8Array, err: unknown): void {
	expect(isOHTTPError(err)).toBe(true);
	if (!isOHTTPError(err)) return;
	if (err.code !== OHTTPErrorCode.UnsupportedCipherSuite) {
		expect(err.code).toBe(OHTTPErrorCode.InvalidKeyConfig);
		return;
	}
	expect(onlyAlgorithmsUnsupported(bytes), `${toHex(bytes)} is not merely unimplemented`).toBe(
		true,
	);
}

/**
 * The list parser is deliberately lossy, so it cannot round-trip. What must
 * still hold is that it never invents or rewrites a config: each one it returns
 * re-encodes to one of the input's records, minus droppable pairs, in order.
 */
function assertSubsequenceOrRejects(bytes: Uint8Array): void {
	let parsed: KeyConfig[];
	try {
		parsed = parseKeyConfigs(bytes);
	} catch (err) {
		expect(isOHTTPError(err)).toBe(true);
		if (isOHTTPError(err)) expect(err.code).toBe(OHTTPErrorCode.InvalidKeyConfig);
		return;
	}

	const records = splitRecords(bytes);
	let at = 0;
	for (const config of parsed) {
		const encoded = toHex(serializeKeyConfig(config));
		const found = records.findIndex(
			(record, i) => i >= at && toHex(dropUnknownPairs(record, config)) === encoded,
		);
		expect(
			found,
			`config ${encoded} is not a record of the input at or after ${at}`,
		).toBeGreaterThan(-1);
		at = found + 1;
	}
}

/** `record` re-encoded with its unimplemented (KDF, AEAD) pairs removed. */
function dropUnknownPairs(record: Uint8Array, parsed: KeyConfig): Uint8Array {
	const symLenOffset = 3 + parsed.publicKey.length;
	if (symLenOffset + 2 > record.length) return record;

	const view = new DataView(record.buffer, record.byteOffset, record.byteLength);
	const end = Math.min(symLenOffset + 2 + view.getUint16(symLenOffset), record.length);
	const kept: number[] = [];
	for (let offset = symLenOffset + 2; offset + 4 <= end; offset += 4) {
		const kdfId = view.getUint16(offset);
		const aeadId = view.getUint16(offset + 2);
		if (isValidKdfId(kdfId) && isValidAeadId(aeadId)) kept.push(kdfId, aeadId);
	}

	const out = new Uint8Array(symLenOffset + 2 + kept.length * 2);
	out.set(record.subarray(0, symLenOffset + 2));
	const outView = new DataView(out.buffer);
	outView.setUint16(symLenOffset, kept.length * 2);
	for (const [i, id] of kept.entries()) {
		outView.setUint16(symLenOffset + 2 + i * 2, id);
	}
	return out;
}

/** True when `bytes` is a structurally intact record naming only algorithms we lack. */
function onlyAlgorithmsUnsupported(bytes: Uint8Array): boolean {
	if (bytes.length < 7) return false;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

	const kemId = view.getUint16(1);
	if (!isValidKemId(kemId)) return true;

	const symLenOffset = 3 + getPublicKeyLength(kemId);
	if (symLenOffset + 2 > bytes.length) return false;
	const symLen = view.getUint16(symLenOffset);
	if (symLen === 0 || symLen % 4 !== 0 || symLenOffset + 2 + symLen !== bytes.length) return false;

	for (let offset = symLenOffset + 2; offset < bytes.length; offset += 4) {
		if (isValidKdfId(view.getUint16(offset)) && isValidAeadId(view.getUint16(offset + 2))) {
			return false;
		}
	}
	return true;
}

/** Split an `application/ohttp-keys` blob into its length-prefixed records. */
function splitRecords(bytes: Uint8Array): Uint8Array[] {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const records: Uint8Array[] = [];
	let offset = 0;
	while (offset + 2 <= bytes.length) {
		const length = view.getUint16(offset);
		offset += 2;
		if (offset + length > bytes.length) break;
		records.push(bytes.slice(offset, offset + length));
		offset += length;
	}
	return records;
}

/** Field offsets within a serialized `KeyConfig`, derived from the config itself rather than by re-parsing. */
function fieldOffsets(config: KeyConfig): { symLenOffset: number; algosOffset: number } {
	const symLenOffset = 3 + config.publicKey.length;
	return { symLenOffset, algosOffset: symLenOffset + 2 };
}

/** `inner` placed inside a larger buffer, returned as a non-zero-offset view of it. */
function embedAt(inner: Uint8Array, prefixLen: number, suffixLen: number): Uint8Array {
	const buffer = new Uint8Array(prefixLen + inner.length + suffixLen);
	buffer.set(inner, prefixLen);
	return buffer.subarray(prefixLen, prefixLen + inner.length);
}

/** `bytes` with `extra` appended. */
function appendBytes(bytes: Uint8Array, extra: Uint8Array): Uint8Array {
	const out = new Uint8Array(bytes.length + extra.length);
	out.set(bytes, 0);
	out.set(extra, bytes.length);
	return out;
}
