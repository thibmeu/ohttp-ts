import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { describe, expect, it } from "vitest";
import { OHTTPError } from "../src/errors.js";
import {
	AeadId,
	KdfId,
	KemId,
	deriveKeyConfig,
	generateKeyConfig,
	parseKeyConfig,
	parseKeyConfigs,
	serializeKeyConfig,
	serializeKeyConfigs,
} from "../src/keyConfig.js";
import { fromHex, toHex } from "./test-utils.js";
import rfc9458Vectors from "./vectors/rfc9458.json";

describe("KeyConfig serialization", () => {
	it("round-trips a KeyConfig", () => {
		const config = {
			keyId: 1,
			kemId: KemId.X25519_HKDF_SHA256,
			publicKey: new Uint8Array(32).fill(0xab),
			symmetricAlgorithms: [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }],
		};

		const serialized = serializeKeyConfig(config);
		const parsed = parseKeyConfig(serialized);

		expect(parsed.keyId).toBe(config.keyId);
		expect(parsed.kemId).toBe(config.kemId);
		expect(parsed.publicKey).toEqual(config.publicKey);
		expect(parsed.symmetricAlgorithms).toEqual(config.symmetricAlgorithms);
	});

	it("handles multiple symmetric algorithms", () => {
		const config = {
			keyId: 42,
			kemId: KemId.X25519_HKDF_SHA256,
			publicKey: new Uint8Array(32).fill(0xcd),
			symmetricAlgorithms: [
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.ChaCha20Poly1305 },
			],
		};

		const serialized = serializeKeyConfig(config);
		const parsed = parseKeyConfig(serialized);

		expect(parsed.symmetricAlgorithms.length).toBe(2);
		expect(parsed.symmetricAlgorithms[0]).toEqual({
			kdfId: KdfId.HKDF_SHA256,
			aeadId: AeadId.AES_128_GCM,
		});
		expect(parsed.symmetricAlgorithms[1]).toEqual({
			kdfId: KdfId.HKDF_SHA256,
			aeadId: AeadId.ChaCha20Poly1305,
		});
	});

	it("rejects truncated data", () => {
		const config = {
			keyId: 1,
			kemId: KemId.X25519_HKDF_SHA256,
			publicKey: new Uint8Array(32).fill(0xab),
			symmetricAlgorithms: [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }],
		};

		const serialized = serializeKeyConfig(config);

		// Truncate at various points
		expect(() => parseKeyConfig(serialized.slice(0, 3))).toThrow(OHTTPError);
		expect(() => parseKeyConfig(serialized.slice(0, 10))).toThrow(OHTTPError);
		expect(() => parseKeyConfig(serialized.slice(0, 35))).toThrow(OHTTPError);
	});

	it("rejects empty symmetric algorithms", () => {
		// Manually construct invalid data with 0 symmetric algorithms length
		const data = new Uint8Array([
			0x01, // keyId
			0x00,
			0x20, // kemId (X25519)
			...new Array(32).fill(0xab), // publicKey
			0x00,
			0x00, // symmetric algorithms length = 0
		]);

		expect(() => parseKeyConfig(data)).toThrow(OHTTPError);
	});
});

describe("KeyConfigs (application/ohttp-keys)", () => {
	it("round-trips multiple KeyConfigs", () => {
		const configs = [
			{
				keyId: 1,
				kemId: KemId.X25519_HKDF_SHA256,
				publicKey: new Uint8Array(32).fill(0x11),
				symmetricAlgorithms: [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }],
			},
			{
				keyId: 2,
				kemId: KemId.X25519_HKDF_SHA256,
				publicKey: new Uint8Array(32).fill(0x22),
				symmetricAlgorithms: [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.ChaCha20Poly1305 }],
			},
		];

		const serialized = serializeKeyConfigs(configs);
		const parsed = parseKeyConfigs(serialized);

		expect(parsed.length).toBe(2);
		expect(parsed[0]?.keyId).toBe(1);
		expect(parsed[1]?.keyId).toBe(2);
	});

	it("handles empty configs", () => {
		const serialized = serializeKeyConfigs([]);
		const parsed = parseKeyConfigs(serialized);
		expect(parsed.length).toBe(0);
	});
});

describe("KeyConfig generation", () => {
	it("generates a valid KeyConfig", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const config = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		expect(config.keyId).toBe(1);
		expect(config.kemId).toBe(KemId.X25519_HKDF_SHA256);
		expect(config.publicKey.length).toBe(32);
		expect(config.keyPair).toBeDefined();
		expect(config.suite).toBe(suite);
	});

	it("rejects invalid keyId", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		await expect(
			generateKeyConfig(suite, 256, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]),
		).rejects.toThrow(OHTTPError);

		await expect(
			generateKeyConfig(suite, -1, [{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM }]),
		).rejects.toThrow(OHTTPError);
	});
});

describe("KeyConfig derivation (deterministic)", () => {
	it("derives deterministic keys from seed", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const seed = new Uint8Array(32).fill(0x42);

		const config1 = await deriveKeyConfig(suite, seed, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const config2 = await deriveKeyConfig(suite, seed, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Same seed should produce same public key
		expect(config1.publicKey).toEqual(config2.publicKey);
	});

	it("different seeds produce different keys", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const seed1 = new Uint8Array(32).fill(0x42);
		const seed2 = new Uint8Array(32).fill(0x43);

		const config1 = await deriveKeyConfig(suite, seed1, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const config2 = await deriveKeyConfig(suite, seed2, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		expect(config1.publicKey).not.toEqual(config2.publicKey);
	});

	it("rejects seed that is too short", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const shortSeed = new Uint8Array(16);

		await expect(
			deriveKeyConfig(suite, shortSeed, 1, [
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
			]),
		).rejects.toThrow(OHTTPError);
	});
});

describe("RFC 9458 Appendix A key config", () => {
	const vector = rfc9458Vectors.vectors[0];
	if (vector === undefined) {
		throw new Error("No test vector found");
	}

	it("parses the RFC test vector key config", () => {
		const data = fromHex(vector.keyConfig);
		if (data === undefined) {
			throw new Error("Invalid hex");
		}

		const config = parseKeyConfig(data);

		expect(config.keyId).toBe(vector.keyId);
		expect(config.kemId).toBe(vector.kemId);
		expect(config.publicKey.length).toBe(32);
		expect(toHex(config.publicKey)).toBe(vector.publicKey);
		expect(config.symmetricAlgorithms.length).toBe(vector.symmetricAlgorithms.length);
		expect(config.symmetricAlgorithms[0]).toEqual(vector.symmetricAlgorithms[0]);
		expect(config.symmetricAlgorithms[1]).toEqual(vector.symmetricAlgorithms[1]);
	});

	it("re-serializes the RFC test vector correctly", () => {
		const data = fromHex(vector.keyConfig);
		if (data === undefined) {
			throw new Error("Invalid hex");
		}

		const config = parseKeyConfig(data);
		const reserialized = serializeKeyConfig(config);

		expect(toHex(reserialized)).toBe(vector.keyConfig);
	});
});
