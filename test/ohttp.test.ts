import {
	AEAD_AES_128_GCM as NobleAEAD_AES_128_GCM,
	AEAD_ChaCha20Poly1305 as NobleAEAD_ChaCha20Poly1305,
	KDF_HKDF_SHA256 as NobleKDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256 as NobleKEM_X25519,
} from "@panva/hpke-noble";
import {
	AEAD_AES_128_GCM,
	AEAD_AES_256_GCM,
	AEAD_ChaCha20Poly1305,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_P256_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { describe, expect, it } from "vitest";
import { OHTTPClient } from "../src/client.js";
import { MediaType } from "../src/constants.js";
import {
	decapsulateRequest,
	encapsulateResponse,
	getResponseNonceLength,
} from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	deriveKeyConfig,
	generateKeyConfig,
	importKeyConfig,
	KdfId,
	KemId,
	parseKeyConfig,
	serializeKeyConfig,
} from "../src/keyConfig.js";
import { ChunkedOHTTPServer, OHTTPServer } from "../src/server.js";
import { fromHex, hex, supportsChaCha20Poly1305, toHex } from "./test-utils.js";
import ohttpJsVectors from "./vectors/ohttp-js.json";
import rfc9458Vectors from "./vectors/rfc9458.json";

describe("OHTTP round-trip", () => {
	it("encrypts and decrypts a request/response", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		// Server generates key config
		const serverKeyConfig = await generateKeyConfig(suite, 1);

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

	it.skipIf(!supportsChaCha20Poly1305)(
		"encrypts and decrypts a ChaCha20-Poly1305 response (default factory)",
		async () => {
			// Response crypto is resolved from the suite's AEAD id, so ChaCha20 works
			// without any override on runtimes with ChaCha20-Poly1305 (e.g. Node 24+).
			const suite = new CipherSuite(
				KEM_DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_ChaCha20Poly1305,
			);

			const serverKeyConfig = await generateKeyConfig(suite, 1);

			const client = new OHTTPClient(suite, {
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
			});
			const server = new OHTTPServer([serverKeyConfig]);

			const request = new TextEncoder().encode("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
			const { encapsulatedRequest, context } = await client.encapsulate(request);
			const { context: serverContext } = await server.decapsulate(encapsulatedRequest);

			const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello over ChaCha20");
			const encapsulatedResponse = await serverContext.encryptResponse(response);

			await expect(context.decryptResponse(encapsulatedResponse)).resolves.toEqual(response);
		},
	);

	it.skipIf(!supportsChaCha20Poly1305)(
		"uses a responseCrypto override for response encryption",
		async () => {
			// Supplying a non-WebCrypto AEAD factory is how browsers / Workers obtain
			// ChaCha20-Poly1305 responses. Here we verify the override is honored by
			// routing response crypto through @panva/hpke-noble.
			const suite = new CipherSuite(
				KEM_DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_ChaCha20Poly1305,
			);

			const serverKeyConfig = await generateKeyConfig(suite, 1);

			const responseCrypto = { kdf: NobleKDF_HKDF_SHA256, aead: NobleAEAD_ChaCha20Poly1305 };
			const client = new OHTTPClient(
				suite,
				{
					keyId: serverKeyConfig.keyId,
					kemId: serverKeyConfig.kemId,
					publicKey: serverKeyConfig.publicKey,
					symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
				},
				{ responseCrypto },
			);
			const server = new OHTTPServer([serverKeyConfig], { responseCrypto });

			const request = new TextEncoder().encode("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
			const { encapsulatedRequest, context } = await client.encapsulate(request);
			const { context: serverContext } = await server.decapsulate(encapsulatedRequest);

			const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello from noble");
			const encapsulatedResponse = await serverContext.encryptResponse(response);

			await expect(context.decryptResponse(encapsulatedResponse)).resolves.toEqual(response);
		},
	);

	it("interops: WebCrypto-default server with a noble-override client", async () => {
		// The override must produce byte-identical output to the default factory,
		// otherwise a default server and an overridden client could not interop.
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const client = new OHTTPClient(
			suite,
			{
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
			},
			{ responseCrypto: { kdf: NobleKDF_HKDF_SHA256, aead: NobleAEAD_AES_128_GCM } },
		);
		// Server uses the default (WebCrypto) factories.
		const server = new OHTTPServer([serverKeyConfig]);

		const request = new TextEncoder().encode("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
		const { encapsulatedRequest, context } = await client.encapsulate(request);
		const { context: serverContext } = await server.decapsulate(encapsulatedRequest);

		const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");
		const encapsulatedResponse = await serverContext.encryptResponse(response);

		await expect(context.decryptResponse(encapsulatedResponse)).resolves.toEqual(response);
	});

	it("rejects a responseCrypto override whose algorithm differs from the suite", async () => {
		// An override may swap the implementation, not the algorithm. Here the
		// suite negotiated AES-128-GCM but the override AEAD is AES-256-GCM, and
		// both sides know that before a single request goes out.
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 1);
		const responseCrypto = { aead: AEAD_AES_256_GCM };

		expect(() => new OHTTPServer([serverKeyConfig], { responseCrypto })).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.UnsupportedCipherSuite }),
		);
		expect(
			() =>
				new OHTTPClient(
					suite,
					{
						keyId: serverKeyConfig.keyId,
						kemId: serverKeyConfig.kemId,
						publicKey: serverKeyConfig.publicKey,
						symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
					},
					{ responseCrypto },
				),
		).toThrow(expect.objectContaining({ code: OHTTPErrorCode.UnsupportedCipherSuite }));
	});

	it("supports multiple key configs for key rotation", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		// Generate two key configs
		const oldKeyConfig = await generateKeyConfig(suite, 1);
		const newKeyConfig = await generateKeyConfig(suite, 2);

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

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		// Client uses a different key ID
		const fakeKeyConfig = await generateKeyConfig(suite, 99);

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

		const config1 = await deriveKeyConfig(suite, seed, 1);

		const config2 = await deriveKeyConfig(suite, seed, 1);

		// Same seed produces same keys
		expect(toHex(config1.publicKey)).toBe(toHex(config2.publicKey));
	});
});

describe("RFC 9458 Appendix A test vectors", () => {
	const vector = rfc9458Vectors.vectors[0];
	if (vector === undefined) {
		throw new Error("No test vector found");
	}

	/** Server side of the RFC's exchange, rebuilt from the gateway private key. */
	async function rfcServer() {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const keyConfig = await importKeyConfig(
			suite,
			vector.keyId,
			hex(vector.publicKey),
			hex(vector.privateKey),
		);
		return { suite, keyConfig };
	}

	it("parses the RFC key config correctly", () => {
		const config = parseKeyConfig(hex(vector.keyConfig));

		expect(config.keyId).toBe(vector.keyId);
		expect(config.kemId).toBe(vector.kemId);
		expect(config.symmetricAlgorithms).toEqual(vector.symmetricAlgorithms);
		// Canonical: what we parsed re-encodes to exactly the RFC's bytes.
		expect(toHex(serializeKeyConfig(config))).toBe(vector.keyConfig);
	});

	// The gateway direction is fully deterministic from the private key - no
	// randomness to control - so it pins the request key schedule against bytes
	// this library did not generate.
	it("decapsulates the RFC's encapsulated request", async () => {
		const { keyConfig } = await rfcServer();
		const server = new OHTTPServer([keyConfig]);

		const { request } = await server.decapsulate(hex(vector.encapsulatedRequest));

		expect(toHex(request)).toBe(vector.request);
	});

	// Response encryption takes the nonce as an argument, so feeding the RFC's
	// nonce back in makes this leg deterministic too. This is the test that
	// catches a broken response key schedule: a round-trip cannot, because it
	// would derive the same wrong key on both sides.
	it("reproduces the RFC's encapsulated response byte for byte", async () => {
		const { keyConfig } = await rfcServer();
		const ctx = await decapsulateRequest(hex(vector.encapsulatedRequest), [keyConfig]);

		const encapsulatedResponse = await encapsulateResponse(
			ctx,
			hex(vector.response),
			hex(vector.responseNonce),
		);

		expect(toHex(encapsulatedResponse)).toBe(vector.encapsulatedResponse);
	});

	it("uses max(Nn, Nk) for the response nonce, as the RFC's vector does", async () => {
		const { suite } = await rfcServer();
		expect(getResponseNonceLength(suite)).toBe(hex(vector.responseNonce).length);
	});
});

describe("Interoperability with chris-wood/ohttp-js", () => {
	const vector = ohttpJsVectors.vectors[0];
	if (!vector) throw new Error("No ohttp-js test vector found");

	it("decrypts a request encapsulated by ohttp-js", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const seed = fromHex(vector.seed);
		if (!seed) throw new Error("Invalid seed");

		const keyConfig = await deriveKeyConfig(suite, seed, vector.keyId);

		const server = new OHTTPServer([keyConfig]);

		const encodedClientRequest = fromHex(vector.encapsulatedRequest);
		if (!encodedClientRequest) throw new Error("Invalid request");

		const { request } = await server.decapsulate(encodedClientRequest);
		expect(request.length).toBeGreaterThan(0);
	});
});

describe("OHTTP error handling", () => {
	it("produces opaque decryption errors", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

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
		const serverKeyConfig = await generateKeyConfig(aesGcmSuite, 1);

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

	it("rejects request with truncated header", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const server = new OHTTPServer([serverKeyConfig]);

		// Truncated request - only keyId + kemId (3 bytes), missing rest of header
		const truncated = new Uint8Array([1, 0, 0x20]);

		await expect(server.decapsulate(truncated)).rejects.toThrow(OHTTPError);
	});

	it("rejects response with wrong nonce length", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const client = new OHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const request = new Uint8Array([1, 2, 3]);
		const { context } = await client.encapsulate(request);

		// Response nonce should be 16 bytes for AES-128-GCM (max(Nn=12, Nk=16))
		// Send a truncated response with only 8 bytes of nonce
		const badResponse = new Uint8Array(8 + 16 + 16); // 8-byte nonce + fake ciphertext

		await expect(context.decryptResponse(badResponse)).rejects.toThrow();
	});
});

describe("OHTTP Request/Response API", () => {
	it("round-trips HTTP Request/Response", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const client = new OHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const server = new OHTTPServer([serverKeyConfig]);

		// Client creates and encapsulates HTTP Request
		const httpRequest = new Request("https://target.example.com/api/data", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ query: "test" }),
		});

		const { init, context: clientContext } = await client.encapsulateRequest(httpRequest);

		// Verify init format
		expect(init.method).toBe("POST");
		expect((init.headers as Record<string, string>)["Content-Type"]).toBe(MediaType.REQUEST);

		// Server decapsulates
		const relayRequest = new Request("https://relay.example.com/ohttp", init);
		const { request: innerRequest, context: serverContext } =
			await server.decapsulateRequest(relayRequest);

		// Verify inner request
		expect(innerRequest.url).toBe("https://target.example.com/api/data");
		expect(innerRequest.method).toBe("POST");
		expect(innerRequest.headers.get("content-type")).toBe("application/json");
		const body = await innerRequest.json();
		expect(body).toEqual({ query: "test" });

		// Server creates and encapsulates response
		const httpResponse = new Response(JSON.stringify({ result: "success" }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});

		const encapsulatedResponse = await serverContext.encapsulateResponse(httpResponse);

		// Verify encapsulated response format
		expect(encapsulatedResponse.status).toBe(200);
		expect(encapsulatedResponse.headers.get("content-type")).toBe(MediaType.RESPONSE);

		// Client decapsulates response
		const innerResponse = await clientContext.decapsulateResponse(encapsulatedResponse);

		// Verify inner response
		expect(innerResponse.status).toBe(200);
		expect(innerResponse.headers.get("content-type")).toBe("application/json");
		const responseBody = await innerResponse.json();
		expect(responseBody).toEqual({ result: "success" });
	});

	it("rejects request with wrong content-type", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const server = new OHTTPServer([serverKeyConfig]);

		// Request with wrong content-type
		const badRequest = new Request("https://relay.example.com/ohttp", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "{}",
		});

		await expect(server.decapsulateRequest(badRequest)).rejects.toThrow(OHTTPError);
	});

	it("rejects response with wrong content-type", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const client = new OHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const httpRequest = new Request("https://target.example.com/", { method: "GET" });
		const { context } = await client.encapsulateRequest(httpRequest);

		// Response with wrong content-type
		const badResponse = new Response("data", {
			headers: { "Content-Type": "text/plain" },
		});

		await expect(context.decapsulateResponse(badResponse)).rejects.toThrow(OHTTPError);
	});

	it("reports malformed inner bhttp as InvalidMessage", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1);

		const server = new OHTTPServer([serverKeyConfig]);
		const client = new OHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		// Create valid OHTTP encapsulation but with invalid binary HTTP inside
		const invalidBinaryHttp = new Uint8Array([0xff, 0xff, 0xff]); // Invalid binary HTTP
		const { encapsulatedRequest } = await client.encapsulate(invalidBinaryHttp);

		// Server decrypts successfully but bhttp decode fails, which is a framing
		// error rather than a crypto one
		try {
			// Build a proper OHTTP request
			const ohttpRequest = new Request("https://relay.example.com/", {
				method: "POST",
				headers: { "Content-Type": MediaType.REQUEST },
				body: new Uint8Array(encapsulatedRequest).buffer as ArrayBuffer,
			});
			await server.decapsulateRequest(ohttpRequest);
			expect.fail("Should have thrown");
		} catch (e) {
			expect(e).toBeInstanceOf(OHTTPError);
			expect((e as OHTTPError).code).toBe(OHTTPErrorCode.InvalidMessage);
		}
	});
});

describe("multi-suite key configs (RFC 9458 Appendix A)", () => {
	const kdf = KDF_HKDF_SHA256;
	const aes128 = () => new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, kdf, AEAD_AES_128_GCM);
	const aes256 = () => new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, kdf, AEAD_AES_256_GCM);

	it("serves two AEADs under one key identifier", async () => {
		const keyConfig = await generateKeyConfig([aes128(), aes256()], 1);

		expect(keyConfig.symmetricAlgorithms).toEqual([
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_256_GCM },
		]);

		const server = new OHTTPServer([keyConfig]);
		// What the gateway publishes: one config, both pairs.
		const published = parseKeyConfig(serializeKeyConfig(keyConfig));
		const request = new TextEncoder().encode("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
		const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");

		// Each client picks a different pair from the same published config, and
		// the gateway follows the request header to the matching suite.
		for (const suite of [aes128(), aes256()]) {
			const client = new OHTTPClient(suite, published);
			const { encapsulatedRequest, context } = await client.encapsulate(request);
			const { request: decrypted, context: serverContext } =
				await server.decapsulate(encapsulatedRequest);

			expect(decrypted).toEqual(request);
			await expect(
				context.decryptResponse(await serverContext.encryptResponse(response)),
			).resolves.toEqual(response);
		}
	});

	it("rejects suites that disagree on the KEM or repeat a pair", async () => {
		await expect(generateKeyConfig([aes128(), aes128()], 1)).rejects.toThrow(/INVALID_KEY_CONFIG/);
		await expect(generateKeyConfig([], 1)).rejects.toThrow(/INVALID_KEY_CONFIG/);

		// Different KEM: one key pair cannot serve both.
		const p256 = new CipherSuite(KEM_DHKEM_P256_HKDF_SHA256, kdf, AEAD_AES_128_GCM);
		await expect(generateKeyConfig([aes128(), p256], 1)).rejects.toThrow(/INVALID_KEY_CONFIG/);

		// Same KEM id, different implementation, so the key pair is not portable
		// between them. The id alone does not catch this.
		const noble = new CipherSuite(NobleKEM_X25519, NobleKDF_HKDF_SHA256, NobleAEAD_AES_128_GCM);
		await expect(generateKeyConfig([aes128(), noble], 1)).rejects.toThrow(/INVALID_KEY_CONFIG/);
	});

	it("serves a response with the AEAD the request selected", async () => {
		// responseCrypto is fixed at construction while the suite is per request,
		// so a gateway serving two AEADs supplies a factory for each.
		const keyConfig = await generateKeyConfig([aes128(), aes256()], 1);
		const gateway = new OHTTPServer([keyConfig], {
			responseCrypto: { aead: [AEAD_AES_128_GCM, AEAD_AES_256_GCM] },
		});
		const published = parseKeyConfig(serializeKeyConfig(keyConfig));
		const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");

		for (const suite of [aes128(), aes256()]) {
			const client = new OHTTPClient(suite, published);
			const { encapsulatedRequest, context } = await client.encapsulate(new Uint8Array([1]));
			const { context: serverContext } = await gateway.decapsulate(encapsulatedRequest);

			await expect(
				context.decryptResponse(await serverContext.encryptResponse(response)),
			).resolves.toEqual(response);
		}
	});

	it("rejects an override with no factory for a served algorithm", async () => {
		// A gateway that adds an AEAD and forgets its factory would otherwise
		// serve one pair and fail the other after the request had decrypted.
		const keyConfig = await generateKeyConfig([aes128(), aes256()], 1);

		expect(
			() => new OHTTPServer([keyConfig], { responseCrypto: { aead: AEAD_AES_256_GCM } }),
		).toThrow(expect.objectContaining({ code: OHTTPErrorCode.UnsupportedCipherSuite }));
		expect(
			() =>
				new OHTTPServer([keyConfig], {
					responseCrypto: { aead: [AEAD_AES_128_GCM, AEAD_AES_256_GCM] },
				}),
		).not.toThrow();
	});

	it("rejects a config whose advertised algorithms outrun its suites", async () => {
		// The constructors keep the two in step; a spread does not, and the server
		// is the last place to catch it before the lie reaches a client.
		const keyConfig = await generateKeyConfig(aes128(), 1);
		const lying = {
			...keyConfig,
			symmetricAlgorithms: [
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_256_GCM },
			],
		};

		expect(() => new OHTTPServer([lying])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
		expect(() => new OHTTPServer([{ ...keyConfig, kemId: KemId.ML_KEM_768 }])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
		// A keyId the wire format cannot carry: the header is one byte, so this
		// config would answer UnknownKeyId to every request.
		expect(() => new OHTTPServer([{ ...keyConfig, keyId: 256 }])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
	});
});

describe("client public key import", () => {
	it("retries after a failed import instead of caching the rejection", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const keyConfig = await generateKeyConfig(suite, 1);

		// Shadow the instance method: the first import fails, the rest work.
		const real = suite.DeserializePublicKey.bind(suite);
		let failNext = true;
		(suite as { DeserializePublicKey: typeof real }).DeserializePublicKey = (bytes) => {
			if (failNext) {
				failNext = false;
				return Promise.reject(new Error("importKey failed"));
			}
			return real(bytes);
		};

		const client = new OHTTPClient(suite, parseKeyConfig(serializeKeyConfig(keyConfig)));
		await expect(client.encapsulate(new Uint8Array([1]))).rejects.toThrow("importKey failed");
		// A cached rejection would poison the client for the rest of its life.
		await expect(client.encapsulate(new Uint8Array([1]))).resolves.toBeDefined();
	});
});

describe("client bhttp framing errors", () => {
	it("reports malformed inner bhttp from the gateway as InvalidMessage", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 1);
		const server = new OHTTPServer([serverKeyConfig]);
		const client = new OHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const { init, context } = await client.encapsulateRequest(
			new Request("https://target.example.com/", { method: "GET" }),
		);
		const { context: serverContext } = await server.decapsulate(
			new Uint8Array(await new Request("https://relay.example.com/", init).arrayBuffer()),
		);

		// Framing indicator 4, which bhttp does not define: the gateway sealed a
		// response the client can decrypt but cannot parse.
		const encrypted = await serverContext.encryptResponse(new Uint8Array([0x04, 0x00]));

		await expect(
			context.decapsulateResponse(
				new Response(encrypted, { headers: { "Content-Type": MediaType.RESPONSE } }),
			),
		).rejects.toThrow(expect.objectContaining({ code: OHTTPErrorCode.InvalidMessage }));
	});
});

describe("server key config list", () => {
	const suite = () =>
		new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

	it("rejects duplicate key identifiers", async () => {
		// Lookup is by keyId, so the second config would never be reached.
		const first = await generateKeyConfig(suite(), 1);
		const second = await generateKeyConfig(suite(), 1);

		expect(() => new OHTTPServer([first, second])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
		expect(() => new ChunkedOHTTPServer([first, second])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
	});

	it("rejects an empty list", () => {
		expect(() => new OHTTPServer([])).toThrow(
			expect.objectContaining({ code: OHTTPErrorCode.InvalidKeyConfig }),
		);
	});
});
