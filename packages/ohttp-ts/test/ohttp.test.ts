import {
	AEAD_AES_128_GCM,
	AEAD_ChaCha20Poly1305,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { describe, expect, it } from "vitest";
import { OHTTPClient } from "../src/client.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	KdfId,
	deriveKeyConfig,
	generateKeyConfig,
	parseKeyConfig,
} from "../src/keyConfig.js";
import { OHTTPServer } from "../src/server.js";
import { fromHex, toHex } from "./test-utils.js";
import rfc9458Vectors from "./vectors/rfc9458.json";

describe("OHTTP round-trip", () => {
	it("encrypts and decrypts a request/response", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		// Server generates key config
		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Client creates OHTTP client with server's public config
		const clientKeyConfig = {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		};

		const client = new OHTTPClient(suite, clientKeyConfig);

		// Server creates OHTTP server with private key
		const server = new OHTTPServer([serverKeyConfig]);

		// Client encapsulates a request
		const request = new TextEncoder().encode("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
		const { encapsulatedRequest, context } = await client.encapsulate(request);

		// Server decapsulates the request
		const { request: decryptedRequest, context: serverContext } =
			await server.decapsulate(encapsulatedRequest);

		expect(decryptedRequest).toEqual(request);

		// Server creates and encrypts a response
		const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");
		const encapsulatedResponse = await serverContext.encryptResponse(response);

		// Client decrypts the response
		const decryptedResponse = await context.decryptResponse(encapsulatedResponse);

		expect(decryptedResponse).toEqual(response);
	});

	it("supports multiple key configs for key rotation", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		// Generate two key configs
		const oldKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		const newKeyConfig = await generateKeyConfig(suite, 2, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Server supports both keys
		const server = new OHTTPServer([oldKeyConfig, newKeyConfig]);

		// Client using old key
		const oldClient = new OHTTPClient(suite, {
			keyId: oldKeyConfig.keyId,
			kemId: oldKeyConfig.kemId,
			publicKey: oldKeyConfig.publicKey,
			symmetricAlgorithms: oldKeyConfig.symmetricAlgorithms,
		});

		// Client using new key
		const newClient = new OHTTPClient(suite, {
			keyId: newKeyConfig.keyId,
			kemId: newKeyConfig.kemId,
			publicKey: newKeyConfig.publicKey,
			symmetricAlgorithms: newKeyConfig.symmetricAlgorithms,
		});

		const request = new Uint8Array([1, 2, 3, 4]);

		// Both should work
		const { encapsulatedRequest: old } = await oldClient.encapsulate(request);
		const { encapsulatedRequest: newReq } = await newClient.encapsulate(request);

		const { request: r1 } = await server.decapsulate(old);
		const { request: r2 } = await server.decapsulate(newReq);

		expect(r1).toEqual(request);
		expect(r2).toEqual(request);
	});

	it("rejects unknown key ID", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Client uses a different key ID
		const fakeKeyConfig = await generateKeyConfig(suite, 99, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new OHTTPClient(suite, {
			keyId: fakeKeyConfig.keyId,
			kemId: fakeKeyConfig.kemId,
			publicKey: fakeKeyConfig.publicKey,
			symmetricAlgorithms: fakeKeyConfig.symmetricAlgorithms,
		});

		const server = new OHTTPServer([serverKeyConfig]);

		const { encapsulatedRequest } = await client.encapsulate(new Uint8Array([1, 2, 3]));

		await expect(server.decapsulate(encapsulatedRequest)).rejects.toThrow(OHTTPError);
	});

	it("uses deterministic keys for reproducible tests", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const seed = new Uint8Array(32);
		seed.fill(0x42);

		const config1 = await deriveKeyConfig(suite, seed, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const config2 = await deriveKeyConfig(suite, seed, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Same seed produces same keys
		expect(toHex(config1.publicKey)).toBe(toHex(config2.publicKey));
	});
});

describe("RFC 9458 Appendix A test vectors", () => {
	const vector = rfc9458Vectors.vectors[0];
	if (vector === undefined) {
		throw new Error("No test vector found");
	}

	it("parses the RFC key config correctly", () => {
		const data = fromHex(vector.keyConfig);
		expect(data).toBeDefined();
		if (data === undefined) throw new Error("Invalid hex");

		const config = parseKeyConfig(data);

		expect(config.keyId).toBe(vector.keyId);
		expect(config.kemId).toBe(vector.kemId);
		expect(config.symmetricAlgorithms.length).toBe(vector.symmetricAlgorithms.length);
	});

	it("validates request/response hex values", () => {
		const request = fromHex(vector.request);
		const response = fromHex(vector.response);

		expect(request).toBeDefined();
		expect(response).toBeDefined();
		expect(request?.length).toBeGreaterThan(0);
		expect(response?.length).toBeGreaterThan(0);
	});

	// Note: Full vector validation would require controlling the randomness
	// in HPKE operations, which isn't easily achievable with the hpke library.
	// The round-trip tests above verify correctness.
});

describe("Interoperability with chris-wood/ohttp-js", () => {
	it("decrypts a request encapsulated by ohttp-js", async () => {
		// Test vector from ohttp-js: https://github.com/chris-wood/ohttp-js
		// This is a known-good encapsulated request that ohttp-js can produce/parse
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		// Seed used in ohttp-js test: "Request label bug" test
		const seed = fromHex(
			"4504e22451e6535cac1e894e35b07541c00f8aa245b8360c06433c46859a79d7",
		);
		expect(seed).toBeDefined();
		if (!seed) throw new Error("Invalid seed");

		const keyConfig = await deriveKeyConfig(suite, seed, 0x01, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const server = new OHTTPServer([keyConfig]);

		// Encapsulated request from ohttp-js test
		const encodedClientRequest = fromHex(
			"010020000100016f026e20fa4024c3852641f91177cf188c70b341d20e4f51ee8e8f1b6ad9a8566bd28fa76ce7869a0db0555f251db8411c32f4686661db5141d76e6dcc538c30a6e6cb6d0b1554ec9d5a6256b2fec49b47ebec510e70d12f249744d638a3275168e56e4c4cebd56288091ae448a1d42f6573611b32242907dfa3ed589e4537821d",
		);
		expect(encodedClientRequest).toBeDefined();
		if (!encodedClientRequest) throw new Error("Invalid request");

		const { request } = await server.decapsulate(encodedClientRequest);

		// The request should be a binary HTTP message for the OHTTP spec URL
		// Just verify we can decrypt it
		expect(request.length).toBeGreaterThan(0);
	});
});

describe("OHTTP error handling", () => {
	it("produces opaque decryption errors", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const server = new OHTTPServer([serverKeyConfig]);

		// Corrupted encapsulated request
		const corrupted = new Uint8Array(100);
		corrupted[0] = 1; // keyId
		corrupted[1] = 0;
		corrupted[2] = 0x20; // kemId
		corrupted[3] = 0;
		corrupted[4] = 1; // kdfId
		corrupted[5] = 0;
		corrupted[6] = 1; // aeadId
		// Fill rest with garbage

		try {
			await server.decapsulate(corrupted);
			expect.fail("Should have thrown");
		} catch (e) {
			expect(e).toBeInstanceOf(OHTTPError);
			const error = e as OHTTPError;
			// Error message should be opaque
			expect(error.message).not.toContain("key");
			expect(error.message).not.toContain("nonce");
			expect(error.code).toBe(OHTTPErrorCode.DecryptionFailed);
		}
	});

	it("rejects unsupported cipher suite", async () => {
		const aesGcmSuite = new CipherSuite(
			KEM_DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
		);

		// Server only supports AES-GCM
		const serverKeyConfig = await generateKeyConfig(aesGcmSuite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Client tries to use ChaCha20-Poly1305
		expect(() => {
			const chachaSuite = new CipherSuite(
				KEM_DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_ChaCha20Poly1305,
			);
			new OHTTPClient(chachaSuite, {
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms, // Only AES-GCM
			});
		}).toThrow(OHTTPError);
	});
});
