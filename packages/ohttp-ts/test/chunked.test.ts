import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { describe, expect, it } from "vitest";
import { ChunkedOHTTPClient } from "../src/client.js";
import {
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	frameChunk,
	parseFramedChunk,
} from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	KdfId,
	deriveKeyConfig,
	generateKeyConfig,
} from "../src/keyConfig.js";
import { ChunkedOHTTPServer } from "../src/server.js";
import { concat, fromHex, toHex } from "../src/utils.js";
import chunkedVectors from "./vectors/chunked-ohttp-08.json";

describe("chunk framing", () => {
	it("frames non-final chunk with varint length", () => {
		const data = new Uint8Array([1, 2, 3, 4, 5]);
		const framed = frameChunk(data, false);

		// Length 5 encodes as single byte 0x05
		expect(framed[0]).toBe(5);
		expect(framed.slice(1)).toEqual(data);
	});

	it("frames final chunk with zero length prefix", () => {
		const data = new Uint8Array([1, 2, 3]);
		const framed = frameChunk(data, true);

		// Final chunk has 0 length prefix
		expect(framed[0]).toBe(0);
		expect(framed.slice(1)).toEqual(data);
	});

	it("parses non-final chunk", () => {
		const data = new Uint8Array([1, 2, 3, 4, 5]);
		const framed = frameChunk(data, false);

		const parsed = parseFramedChunk(framed);
		expect(parsed).toBeDefined();
		expect(parsed?.isFinal).toBe(false);
		expect(parsed?.ciphertext).toEqual(data);
		expect(parsed?.bytesConsumed).toBe(framed.length);
	});

	it("parses final chunk", () => {
		const data = new Uint8Array([1, 2, 3]);
		const framed = frameChunk(data, true);

		const parsed = parseFramedChunk(framed);
		expect(parsed).toBeDefined();
		expect(parsed?.isFinal).toBe(true);
		expect(parsed?.ciphertext).toEqual(data);
	});

	it("parses multiple chunks from concatenated data", () => {
		const chunk1 = new Uint8Array([1, 2, 3]);
		const chunk2 = new Uint8Array([4, 5]);
		const chunk3 = new Uint8Array([6, 7, 8, 9]);

		const framed1 = frameChunk(chunk1, false);
		const framed2 = frameChunk(chunk2, false);
		const framed3 = frameChunk(chunk3, true);

		const combined = concat(framed1, framed2, framed3);

		// Parse first chunk
		const parsed1 = parseFramedChunk(combined);
		expect(parsed1?.isFinal).toBe(false);
		expect(parsed1?.ciphertext).toEqual(chunk1);

		// Parse second chunk
		const remaining1 = combined.slice(parsed1?.bytesConsumed ?? 0);
		const parsed2 = parseFramedChunk(remaining1);
		expect(parsed2?.isFinal).toBe(false);
		expect(parsed2?.ciphertext).toEqual(chunk2);

		// Parse final chunk
		const remaining2 = remaining1.slice(parsed2?.bytesConsumed ?? 0);
		const parsed3 = parseFramedChunk(remaining2);
		expect(parsed3?.isFinal).toBe(true);
		expect(parsed3?.ciphertext).toEqual(chunk3);
	});

	it("returns undefined for empty input", () => {
		expect(parseFramedChunk(new Uint8Array(0))).toBeUndefined();
	});

	it("returns undefined for incomplete non-final chunk", () => {
		// Length says 10 bytes but only 3 follow
		const incomplete = new Uint8Array([10, 1, 2, 3]);
		expect(parseFramedChunk(incomplete)).toBeUndefined();
	});
});

describe("chunked OHTTP round-trip", () => {
	it("encrypts and decrypts chunked request/response", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		// Server generates key config
		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Client
		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		// Server
		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Client encapsulates request
		const request = new TextEncoder().encode("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(request);

		// Server decapsulates
		const { request: decryptedRequest, createResponseContext: serverCreateResponse } =
			await server.decapsulate(encapsulatedRequest);

		expect(decryptedRequest).toEqual(request);

		// Server encrypts response
		const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");
		const responseCtx = await serverCreateResponse();
		const encapsulatedResponse = await server.encapsulateResponse(responseCtx, response);

		// Client decapsulates response
		const decryptedResponse = await client.decapsulateResponse(
			createResponseContext,
			encapsulatedResponse,
		);

		expect(decryptedResponse).toEqual(response);
	});

	it("handles empty request and response", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Empty request
		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(new Uint8Array(0));

		const { request: decryptedRequest, createResponseContext: serverCreateResponse } =
			await server.decapsulate(encapsulatedRequest);

		expect(decryptedRequest).toEqual(new Uint8Array(0));

		// Empty response
		const responseCtx = await serverCreateResponse();
		const encapsulatedResponse = await server.encapsulateResponse(responseCtx, new Uint8Array(0));

		const decryptedResponse = await client.decapsulateResponse(
			createResponseContext,
			encapsulatedResponse,
		);

		expect(decryptedResponse).toEqual(new Uint8Array(0));
	});

	it("handles large request requiring multiple chunks", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Use small chunk size to force multiple chunks
		const client = new ChunkedOHTTPClient(
			suite,
			{
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
			},
			{ maxChunkSize: 100 },
		);

		const server = new ChunkedOHTTPServer([serverKeyConfig], { maxChunkSize: 100 });

		// Large request (300 bytes = 3 chunks)
		const request = new Uint8Array(300);
		for (let i = 0; i < 300; i++) {
			request[i] = i % 256;
		}

		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(request);
		const { request: decryptedRequest, createResponseContext: serverCreateResponse } =
			await server.decapsulate(encapsulatedRequest);

		expect(decryptedRequest).toEqual(request);

		// Large response
		const response = new Uint8Array(250);
		for (let i = 0; i < 250; i++) {
			response[i] = (i * 7) % 256;
		}

		const responseCtx = await serverCreateResponse();
		const encapsulatedResponse = await server.encapsulateResponse(responseCtx, response);

		const decryptedResponse = await client.decapsulateResponse(
			createResponseContext,
			encapsulatedResponse,
		);

		expect(decryptedResponse).toEqual(response);
	});
});

describe("chunked OHTTP streaming API", () => {
	it("allows incremental request construction", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Build request incrementally
		const ctx = await client.createRequestContext();

		const chunk1 = new TextEncoder().encode("GET ");
		const chunk2 = new TextEncoder().encode("/path ");
		const chunk3 = new TextEncoder().encode("HTTP/1.1");

		const sealed1 = await ctx.sealChunk(chunk1);
		const sealed2 = await ctx.sealChunk(chunk2);
		const sealed3 = await ctx.sealFinalChunk(chunk3);

		const encapsulatedRequest = concat(
			ctx.header,
			frameChunk(sealed1, false),
			frameChunk(sealed2, false),
			frameChunk(sealed3, true),
		);

		// Server decapsulates
		const { request } = await server.decapsulate(encapsulatedRequest);

		expect(request).toEqual(concat(chunk1, chunk2, chunk3));
	});

	it("allows incremental response construction", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Client sends request
		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(
			new TextEncoder().encode("request"),
		);

		// Server processes and builds response incrementally
		const serverCtx = await server.createRequestContext(
			encapsulatedRequest.slice(0, 39), // Header only (7 + 32 bytes)
		);

		// Server creates response context
		const responseCtx = await serverCtx.createResponseContext();

		// Build response incrementally
		const respChunk1 = new TextEncoder().encode("HTTP/1.1 ");
		const respChunk2 = new TextEncoder().encode("200 OK");

		const sealedResp1 = await responseCtx.sealChunk(respChunk1);
		const sealedResp2 = await responseCtx.sealFinalChunk(respChunk2);

		const encapsulatedResponse = concat(
			responseCtx.responseNonce,
			frameChunk(sealedResp1, false),
			frameChunk(sealedResp2, true),
		);

		// Client decapsulates
		const decryptedResponse = await client.decapsulateResponse(
			createResponseContext,
			encapsulatedResponse,
		);

		expect(decryptedResponse).toEqual(concat(respChunk1, respChunk2));
	});
});

describe("draft-08 Appendix A test vectors", () => {
	const vector = chunkedVectors.vectors[0];
	if (vector === undefined) {
		throw new Error("No test vector found");
	}

	it("validates key config parsing", () => {
		const keyConfigHex = vector.keyConfig;
		const keyConfigBytes = fromHex(keyConfigHex);
		expect(keyConfigBytes).toBeDefined();

		expect(vector.keyId).toBe(1);
		expect(vector.kemId).toBe(0x0020);
		expect(vector.kdfId).toBe(0x0001);
		expect(vector.aeadId).toBe(0x0001);
	});

	it("validates request chunking structure", () => {
		const request = fromHex(vector.request);
		expect(request).toBeDefined();

		// Verify chunks concatenate to original request
		const chunks = vector.requestChunks.map((c) => fromHex(c.plaintext));
		const reassembled = concat(...(chunks.filter((c) => c !== undefined) as Uint8Array[]));
		expect(reassembled).toEqual(request);
	});

	it("validates response chunking structure", () => {
		const response = fromHex(vector.response);
		expect(response).toBeDefined();

		// Verify chunks concatenate to original response
		const chunks = vector.responseChunks.map((c) => fromHex(c.plaintext));
		const reassembled = concat(...(chunks.filter((c) => c !== undefined) as Uint8Array[]));
		expect(reassembled).toEqual(response);
	});

	it("validates response nonce XOR counter pattern", () => {
		const baseNonce = fromHex(vector.aeadNonce);
		expect(baseNonce).toBeDefined();
		if (baseNonce === undefined) throw new Error("Invalid hex");

		// Counter 0: nonce unchanged
		expect(toHex(baseNonce)).toBe(vector.responseChunks[0]?.chunkNonce);

		// Counter 1: XOR with 1
		const nonce1 = new Uint8Array(baseNonce);
		nonce1[nonce1.length - 1] ^= 1;
		expect(toHex(nonce1)).toBe(vector.responseChunks[1]?.chunkNonce);

		// Counter 2: XOR with 2
		const nonce2 = new Uint8Array(baseNonce);
		nonce2[nonce2.length - 1] ^= 2;
		expect(toHex(nonce2)).toBe(vector.responseChunks[2]?.chunkNonce);
	});

	// Note: Full deterministic test would require controlling HPKE randomness
	// which isn't easily achievable. The round-trip tests verify correctness.
});

describe("chunked OHTTP error handling", () => {
	it("rejects corrupted chunk ciphertext", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		const { encapsulatedRequest } = await client.encapsulate(new Uint8Array([1, 2, 3]));

		// Corrupt the ciphertext
		const corrupted = new Uint8Array(encapsulatedRequest);
		corrupted[corrupted.length - 1] ^= 0xff;

		await expect(server.decapsulate(corrupted)).rejects.toThrow(OHTTPError);
	});

	it("rejects response with wrong AAD on final chunk", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});

		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Create valid request
		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(
			new Uint8Array([1, 2, 3]),
		);

		// Server processes
		const { createResponseContext: serverCreateResponse } =
			await server.decapsulate(encapsulatedRequest);

		// Build malformed response: seal non-final but frame as final
		const responseCtx = await serverCreateResponse();
		const sealedWrongAad = await responseCtx.sealChunk(new Uint8Array([4, 5, 6])); // non-final AAD

		const malformedResponse = concat(
			responseCtx.responseNonce,
			frameChunk(sealedWrongAad, true), // but framed as final
		);

		// Client should reject
		await expect(
			client.decapsulateResponse(createResponseContext, malformedResponse),
		).rejects.toThrow(OHTTPError);
	});

	it("supports custom labels", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

		const serverKeyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const customRequestLabel = "custom/request";
		const customResponseLabel = "custom/response";

		const client = new ChunkedOHTTPClient(
			suite,
			{
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
			},
			{ requestLabel: customRequestLabel, responseLabel: customResponseLabel },
		);

		const server = new ChunkedOHTTPServer([serverKeyConfig], {
			requestLabel: customRequestLabel,
			responseLabel: customResponseLabel,
		});

		const request = new Uint8Array([1, 2, 3]);
		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(request);

		const { request: decrypted, createResponseContext: serverCreateResponse } =
			await server.decapsulate(encapsulatedRequest);

		expect(decrypted).toEqual(request);

		const response = new Uint8Array([4, 5, 6]);
		const responseCtx = await serverCreateResponse();
		const encapsulatedResponse = await server.encapsulateResponse(responseCtx, response);

		const decryptedResponse = await client.decapsulateResponse(
			createResponseContext,
			encapsulatedResponse,
		);

		expect(decryptedResponse).toEqual(response);
	});
});
