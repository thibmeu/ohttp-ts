import {
	AEAD_ChaCha20Poly1305 as NobleAEAD_ChaCha20Poly1305,
	KDF_HKDF_SHA256 as NobleKDF_HKDF_SHA256,
} from "@panva/hpke-noble";
import {
	AEAD_AES_128_GCM,
	AEAD_ChaCha20Poly1305,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { encode as encodeVarint } from "quicvarint";
import { describe, expect, it } from "vitest";
import { ChunkedOHTTPClient } from "../src/client.js";
import { CHUNKED_REQUEST_LABEL, kRecipientContext } from "../src/constants.js";
import {
	AEAD_TAG_SIZE,
	buildRequestInfo,
	computeChunkNonce,
	DEFAULT_MAX_FRAME_SIZE,
	deriveChunkedResponseKeys,
	frameChunk,
	parseFramedChunk,
	sealResponseChunk,
} from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	generateKeyConfig,
	importKeyConfig,
	KdfId,
	parseKeyConfig,
	serializeKeyConfig,
} from "../src/keyConfig.js";
import { ChunkedOHTTPServer } from "../src/server.js";
import { concat } from "../src/utils.js";
import { hex, supportsChaCha20Poly1305, toHex } from "./test-utils.js";
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
		const { encapsulatedRequest, createResponseContext } = await client.encapsulate(
			new Uint8Array(0),
		);

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

describe("chunk sequence guard", () => {
	const data = new TextEncoder().encode("chunk");

	/** Every context that tracks final-chunk state, each already past its final chunk. */
	async function finishedContexts() {
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

		const clientReq = await client.createRequestContext();
		const sealedReq = await clientReq.sealFinalChunk(data);
		const serverReq = await server.createRequestContext(clientReq.header);
		expect(await serverReq.openFinalChunk(sealedReq)).toEqual(data);

		const serverResp = await serverReq.createResponseContext();
		const sealedResp = await serverResp.sealFinalChunk(data);
		const clientResp = await clientReq.createResponseContext(serverResp.responseNonce);
		expect(await clientResp.openFinalChunk(sealedResp)).toEqual(data);

		// A second request, left untouched, for the failed-open case
		const spareReq = await client.createRequestContext();
		const spareSealed = await spareReq.sealFinalChunk(data);
		const spare = await server.createRequestContext(spareReq.header);

		return {
			spare,
			spareSealed,
			// [name, another final chunk, a further non-final chunk]
			contexts: [
				[
					"client request seal",
					() => clientReq.sealFinalChunk(data),
					() => clientReq.sealChunk(data),
				],
				[
					"server request open",
					() => serverReq.openFinalChunk(sealedReq),
					() => serverReq.openChunk(sealedReq),
				],
				[
					"server response seal",
					() => serverResp.sealFinalChunk(data),
					() => serverResp.sealChunk(data),
				],
				[
					"client response open",
					() => clientResp.openFinalChunk(sealedResp),
					() => clientResp.openChunk(sealedResp),
				],
			] as const,
		};
	}

	it("rejects any chunk after the final chunk", async () => {
		const { contexts } = await finishedContexts();

		for (const [name, again, next] of contexts) {
			await expect(again(), name).rejects.toThrow(OHTTPErrorCode.ChunkSequenceError);
			await expect(next(), name).rejects.toThrow(OHTTPErrorCode.ChunkSequenceError);
		}
	});

	it("stays open when the final chunk fails to decrypt", async () => {
		const { spare, spareSealed } = await finishedContexts();
		const tampered = Uint8Array.from(spareSealed);
		tampered[0] ^= 0x01;

		await expect(spare.openFinalChunk(tampered)).rejects.toThrow(OHTTPErrorCode.DecryptionFailed);
		expect(await spare.openFinalChunk(spareSealed)).toEqual(data);
	});
});

describe("draft-08 Appendix A test vectors", () => {
	const vector = chunkedVectors.vectors[0];
	if (vector === undefined) {
		throw new Error("No test vector found");
	}

	const suite = () =>
		new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

	/** Gateway side of the draft's exchange, rebuilt from its private key. */
	function draftKeyConfig() {
		const config = parseKeyConfig(hex(vector.keyConfig));
		return importKeyConfig(suite(), vector.keyId, config.publicKey, hex(vector.skR), [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
	}

	it("parses the draft's key config correctly", () => {
		const config = parseKeyConfig(hex(vector.keyConfig));

		expect(config.keyId).toBe(vector.keyId);
		expect(config.kemId).toBe(vector.kemId);
		// Canonical: what we parsed re-encodes to exactly the draft's bytes.
		expect(toHex(serializeKeyConfig(config))).toBe(vector.keyConfig);
	});

	it("builds the draft's HPKE info string", () => {
		const info = buildRequestInfo(
			vector.keyId,
			vector.kemId,
			vector.kdfId,
			vector.aeadId,
			CHUNKED_REQUEST_LABEL,
		);

		expect(toHex(info)).toBe(vector.info);
	});

	it("decapsulates the draft's encapsulated request", async () => {
		const server = new ChunkedOHTTPServer([await draftKeyConfig()]);

		const { request } = await server.decapsulate(hex(vector.encapsulatedRequest));

		expect(toHex(request)).toBe(vector.request);
	});

	it("opens the draft's request chunks one at a time, in order", async () => {
		const server = new ChunkedOHTTPServer([await draftKeyConfig()]);
		const encapsulated = hex(vector.encapsulatedRequest);
		const ctx = await server.createRequestContext(encapsulated.subarray(0, 39));

		let offset = 39;
		for (const chunk of vector.requestChunks) {
			const parsed = parseFramedChunk(encapsulated.subarray(offset));
			expect(parsed).toBeDefined();
			if (parsed === undefined) throw new Error("unreachable");
			// The vector's `ciphertext` carries its own varint length prefix.
			expect(toHex(encapsulated.subarray(offset, offset + parsed.bytesConsumed))).toBe(
				chunk.ciphertext,
			);
			expect(parsed.isFinal).toBe("final" in chunk);

			const plaintext = parsed.isFinal
				? await ctx.openFinalChunk(parsed.ciphertext)
				: await ctx.openChunk(parsed.ciphertext);
			expect(toHex(plaintext)).toBe(chunk.plaintext);
			offset += parsed.bytesConsumed;
		}
		expect(offset).toBe(encapsulated.length);
	});

	// The response leg derives its key from the request's HPKE context plus the
	// response nonce, so supplying the draft's nonce makes it deterministic.
	// This is what a round-trip test cannot do: if the counter stopped advancing,
	// seal and open would agree on the same reused nonce and the round-trip would
	// still pass, while these vectors would not.
	it("reproduces the draft's response key schedule and every chunk", async () => {
		const keyConfig = await draftKeyConfig();
		const server = new ChunkedOHTTPServer([keyConfig]);
		const ctx = await server.createRequestContext(hex(vector.encapsulatedRequest).subarray(0, 39));

		const { aeadKey, aeadNonce, aead } = await deriveChunkedResponseKeys(
			keyConfig.suite,
			ctx[kRecipientContext],
			hex(vector.enc),
			hex(vector.responseNonce),
		);

		expect(toHex(aeadNonce)).toBe(vector.aeadNonce);

		const framed: Uint8Array[] = [hex(vector.responseNonce)];
		for (const chunk of vector.responseChunks) {
			const isFinal = "final" in chunk;
			expect(toHex(computeChunkNonce(aeadNonce, chunk.counter))).toBe(chunk.chunkNonce);

			const sealed = await sealResponseChunk(
				aead,
				aeadKey,
				aeadNonce,
				chunk.counter,
				hex(chunk.plaintext),
				isFinal,
			);
			const withLength = frameChunk(sealed, isFinal);
			expect(toHex(withLength)).toBe(chunk.ciphertext);
			framed.push(withLength);
		}

		expect(toHex(concat(...framed))).toBe(vector.encapsulatedResponse);
	});
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

describe("chunk nonce computation", () => {
	it("computes nonce correctly for counter 0", () => {
		const baseNonce = new Uint8Array([
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		]);
		const nonce = computeChunkNonce(baseNonce, 0);
		expect(nonce).toEqual(baseNonce);
	});

	it("computes nonce correctly for counter 1", () => {
		const baseNonce = new Uint8Array([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		]);
		const nonce = computeChunkNonce(baseNonce, 1);
		expect(nonce[11]).toBe(0x01);
		expect(nonce.slice(0, 11)).toEqual(new Uint8Array(11));
	});

	it("computes nonce correctly for counter 256", () => {
		const baseNonce = new Uint8Array([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		]);
		const nonce = computeChunkNonce(baseNonce, 256);
		expect(nonce[10]).toBe(0x01);
		expect(nonce[11]).toBe(0x00);
	});

	it("computes nonce correctly for max counter (2^32 - 1)", () => {
		const baseNonce = new Uint8Array([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		]);
		const maxCounter = 2 ** 32 - 1;
		const nonce = computeChunkNonce(baseNonce, maxCounter);
		expect(nonce[8]).toBe(0xff);
		expect(nonce[9]).toBe(0xff);
		expect(nonce[10]).toBe(0xff);
		expect(nonce[11]).toBe(0xff);
	});
});

describe("varint edge cases", () => {
	it("frames and parses 2-byte varint (length 64)", () => {
		const data = new Uint8Array(64).fill(0xab);
		const framed = frameChunk(data, false);
		expect(framed[0]).toBe(0x40);
		expect(framed[1]).toBe(0x40);
		const parsed = parseFramedChunk(framed);
		expect(parsed?.ciphertext).toEqual(data);
		expect(parsed?.isFinal).toBe(false);
	});

	it("frames and parses 4-byte varint (length 16384)", () => {
		const data = new Uint8Array(16384).fill(0xcd);
		const framed = frameChunk(data, false);
		expect((framed[0] ?? 0) & 0xc0).toBe(0x80);
		const parsed = parseFramedChunk(framed);
		expect(parsed?.ciphertext).toEqual(data);
		expect(parsed?.isFinal).toBe(false);
	});

	it("throws for incomplete varint", () => {
		// 2-byte varint marker (0x40) but only 1 byte provided - can't parse
		const incomplete = new Uint8Array([0x40]);
		expect(() => parseFramedChunk(incomplete)).toThrow(OHTTPError);
	});

	it("returns undefined for truncated chunk data", () => {
		const truncated = new Uint8Array([10, 1, 2, 3, 4, 5]);
		expect(parseFramedChunk(truncated)).toBeUndefined();
	});
});

describe("draft-08 chunk validation (regression)", () => {
	const newPair = async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const keyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		const client = new ChunkedOHTTPClient(suite, {
			keyId: keyConfig.keyId,
			kemId: keyConfig.kemId,
			publicKey: keyConfig.publicKey,
			symmetricAlgorithms: keyConfig.symmetricAlgorithms,
		});
		const server = new ChunkedOHTTPServer([keyConfig]);
		return { client, server };
	};

	// A message is complete only once a final (0-length prefix) chunk is decrypted.
	it("rejects a stream that ends without a final chunk", async () => {
		const { client, server } = await newPair();
		const ctx = await client.createRequestContext();
		const sealed = await ctx.sealChunk(new Uint8Array([1, 2, 3]));
		const truncated = concat(ctx.header, frameChunk(sealed, false)); // no final marker
		await expect(server.decapsulate(truncated)).rejects.toThrow(OHTTPError);
	});

	// A non-final chunk MUST NOT contain a zero-length plaintext.
	it("rejects a non-final chunk with zero-length plaintext", async () => {
		const { client, server } = await newPair();
		const ctx = await client.createRequestContext();
		const emptySealed = await ctx.sealChunk(new Uint8Array(0));
		const finalSealed = await ctx.sealFinalChunk(new Uint8Array([1, 2, 3]));
		const request = concat(
			ctx.header,
			frameChunk(emptySealed, false),
			frameChunk(finalSealed, true),
		);
		await expect(server.decapsulate(request)).rejects.toThrow(OHTTPError);
	});
});

describe("chunked OHTTP with streaming BHTTP (Request/Response API)", () => {
	it("encapsulates and decapsulates HTTP Request with body", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 0x01, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});
		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Create a request with body
		const originalRequest = new Request("https://example.com/api/test?q=hello", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ message: "hello world" }),
		});

		// Client encapsulates
		const { init, context } = await client.encapsulateRequest(originalRequest);

		expect(init.method).toBe("POST");
		expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
			"message/ohttp-chunked-req",
		);

		// Simulate relay forwarding to gateway (server decapsulates)
		const relayRequest = new Request("https://relay.example.com/ohttp", init);
		const { request: innerRequest, context: serverContext } =
			await server.decapsulateRequest(relayRequest);

		// Verify inner request
		expect(innerRequest.method).toBe("POST");
		expect(innerRequest.url).toBe("https://example.com/api/test?q=hello");
		expect(innerRequest.headers.get("Content-Type")).toBe("application/json");
		const innerBody = await innerRequest.text();
		expect(JSON.parse(innerBody)).toEqual({ message: "hello world" });

		// Server creates response
		const serverResponse = new Response(JSON.stringify({ status: "ok" }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});

		// Server encapsulates response
		const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);
		expect(encapsulatedResponse.headers.get("Content-Type")).toBe("message/ohttp-chunked-res");

		// Client decapsulates response
		const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

		expect(finalResponse.status).toBe(200);
		expect(finalResponse.headers.get("Content-Type")).toBe("application/json");
		const responseBody = await finalResponse.text();
		expect(JSON.parse(responseBody)).toEqual({ status: "ok" });
	});

	it.skipIf(!supportsChaCha20Poly1305)(
		"streams a response through a responseCrypto override (ChaCha20 via noble)",
		async () => {
			// Exercises createResponseEncryptTransform/createResponseDecryptTransform
			// with an override, so the streaming path keeps honoring responseCrypto.
			const suite = new CipherSuite(
				KEM_DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_ChaCha20Poly1305,
			);
			const serverKeyConfig = await generateKeyConfig(suite, 0x01, [
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.ChaCha20Poly1305 },
			]);

			const responseCrypto = { kdf: NobleKDF_HKDF_SHA256, aead: NobleAEAD_ChaCha20Poly1305 };
			const client = new ChunkedOHTTPClient(
				suite,
				{
					keyId: serverKeyConfig.keyId,
					kemId: serverKeyConfig.kemId,
					publicKey: serverKeyConfig.publicKey,
					symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
				},
				{ responseCrypto, maxChunkSize: 64 },
			);
			const server = new ChunkedOHTTPServer([serverKeyConfig], {
				responseCrypto,
				maxChunkSize: 64,
			});

			const originalRequest = new Request("https://example.com/api/test", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ message: "hello world" }),
			});

			const { init, context } = await client.encapsulateRequest(originalRequest);
			const relayRequest = new Request("https://relay.example.com/ohttp", init);
			const { request: innerRequest, context: serverContext } =
				await server.decapsulateRequest(relayRequest);
			expect(JSON.parse(await innerRequest.text())).toEqual({ message: "hello world" });

			// Large body forces multiple streamed chunks through the transforms.
			const big = "x".repeat(500);
			const serverResponse = new Response(JSON.stringify({ status: "ok", big }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
			const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);
			const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

			expect(finalResponse.status).toBe(200);
			expect(JSON.parse(await finalResponse.text())).toEqual({ status: "ok", big });
		},
	);

	it("encapsulates and decapsulates HTTP Request without body", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 0x01, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(suite, {
			keyId: serverKeyConfig.keyId,
			kemId: serverKeyConfig.kemId,
			publicKey: serverKeyConfig.publicKey,
			symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
		});
		const server = new ChunkedOHTTPServer([serverKeyConfig]);

		// Create a GET request (no body)
		const originalRequest = new Request("https://example.com/resource", {
			method: "GET",
			headers: { Accept: "text/plain" },
		});

		// Client encapsulates
		const { init, context } = await client.encapsulateRequest(originalRequest);

		// Server decapsulates
		const relayRequest = new Request("https://relay.example.com/ohttp", init);
		const { request: innerRequest, context: serverContext } =
			await server.decapsulateRequest(relayRequest);

		expect(innerRequest.method).toBe("GET");
		expect(innerRequest.url).toBe("https://example.com/resource");
		expect(innerRequest.headers.get("Accept")).toBe("text/plain");

		// Server creates empty response
		const serverResponse = new Response(null, {
			status: 204,
		});

		// Server encapsulates response
		const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);

		// Client decapsulates response
		const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

		expect(finalResponse.status).toBe(204);
	});

	it("handles large request body", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 0x01, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Use small chunk size to test chunking
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

		// Create request with body larger than chunk size
		const largeBody = "x".repeat(500);
		const originalRequest = new Request("https://example.com/upload", {
			method: "POST",
			body: largeBody,
		});

		// Roundtrip
		const { init, context } = await client.encapsulateRequest(originalRequest);

		const relayRequest = new Request("https://relay.example.com/ohttp", init);
		const { request: innerRequest, context: serverContext } =
			await server.decapsulateRequest(relayRequest);

		const receivedBody = await innerRequest.text();
		expect(receivedBody).toBe(largeBody);

		// Large response
		const largeResponseBody = "y".repeat(500);
		const serverResponse = new Response(largeResponseBody, { status: 200 });
		const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);
		const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

		expect(await finalResponse.text()).toBe(largeResponseBody);
	});

	it("streams large body with integrity", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 0x01, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		// Small chunk size to force many OHTTP chunks
		const client = new ChunkedOHTTPClient(
			suite,
			{
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
			},
			{ maxChunkSize: 1024 },
		);
		const server = new ChunkedOHTTPServer([serverKeyConfig], { maxChunkSize: 1024 });

		// 1MB body
		const bodySize = 1024 * 1024;
		const originalBody = new Uint8Array(bodySize);
		for (let i = 0; i < bodySize; i++) {
			originalBody[i] = i % 256;
		}

		const originalRequest = new Request("https://example.com/upload", {
			method: "POST",
			body: originalBody,
		});

		// Encapsulate and decapsulate
		const { init, context } = await client.encapsulateRequest(originalRequest);

		const relayRequest = new Request("https://relay.example.com/ohttp", init);
		const { request: innerRequest, context: serverContext } =
			await server.decapsulateRequest(relayRequest);

		// Read body incrementally
		const reader = innerRequest.body?.getReader();
		if (!reader) throw new Error("expected reader");

		let totalReceived = 0;
		const chunks: Uint8Array[] = [];

		// eslint-disable-next-line no-constant-condition
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			chunks.push(value);
			totalReceived += value.length;
		}

		expect(totalReceived).toBe(bodySize);

		// Verify content integrity
		const received = concat(...chunks);
		expect(received).toEqual(originalBody);

		// Response with large body
		const responseBody = new Uint8Array(bodySize);
		for (let i = 0; i < bodySize; i++) {
			responseBody[i] = (255 - i) % 256;
		}

		const serverResponse = new Response(responseBody, { status: 200 });
		const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);
		const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

		// Read response body
		const responseReader = finalResponse.body?.getReader();
		if (!responseReader) throw new Error("expected responseReader");

		let responseTotalReceived = 0;
		const responseChunks: Uint8Array[] = [];

		// eslint-disable-next-line no-constant-condition
		while (true) {
			const { done, value } = await responseReader.read();
			if (done) break;
			responseChunks.push(value);
			responseTotalReceived += value.length;
		}

		expect(responseTotalReceived).toBe(bodySize);

		const receivedResponse = concat(...responseChunks);
		expect(receivedResponse).toEqual(responseBody);
	}, 30000);

	it("handles body with patterned data", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const serverKeyConfig = await generateKeyConfig(suite, 0x01, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);

		const client = new ChunkedOHTTPClient(
			suite,
			{
				keyId: serverKeyConfig.keyId,
				kemId: serverKeyConfig.kemId,
				publicKey: serverKeyConfig.publicKey,
				symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
			},
			{ maxChunkSize: 256 },
		);
		const server = new ChunkedOHTTPServer([serverKeyConfig], { maxChunkSize: 256 });

		// Create body with pattern to verify content integrity
		const chunkCount = 10;
		const chunkSize = 100;
		const fullBody = new Uint8Array(chunkCount * chunkSize);
		for (let i = 0; i < chunkCount; i++) {
			fullBody.fill(i, i * chunkSize, (i + 1) * chunkSize);
		}

		const originalRequest = new Request("https://example.com/stream", {
			method: "POST",
			body: fullBody,
		});

		const { init, context } = await client.encapsulateRequest(originalRequest);

		const relayRequest = new Request("https://relay.example.com/ohttp", init);
		const { request: innerRequest, context: serverContext } =
			await server.decapsulateRequest(relayRequest);

		// Verify all chunks received correctly
		const receivedBody = await innerRequest.arrayBuffer();
		const received = new Uint8Array(receivedBody);

		expect(received.length).toBe(chunkCount * chunkSize);

		// Verify each chunk's content
		for (let i = 0; i < chunkCount; i++) {
			const chunkStart = i * chunkSize;
			for (let j = 0; j < chunkSize; j++) {
				expect(received[chunkStart + j]).toBe(i);
			}
		}

		// Complete roundtrip with patterned response
		const responseBody = new Uint8Array(250);
		for (let i = 0; i < 5; i++) {
			responseBody.fill(i + 100, i * 50, (i + 1) * 50);
		}

		const serverResponse = new Response(responseBody, { status: 200 });
		const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);
		const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

		const finalResponseBody = new Uint8Array(await finalResponse.arrayBuffer());
		expect(finalResponseBody.length).toBe(250);

		// Verify response pattern
		for (let i = 0; i < 5; i++) {
			for (let j = 0; j < 50; j++) {
				expect(finalResponseBody[i * 50 + j]).toBe(i + 100);
			}
		}
	});
});

describe("chunked OHTTP tolerates fragmented reads (regression)", () => {
	// Re-chunk a byte stream into fixed-size reads, simulating arbitrary network
	// delivery boundaries (TCP segments, fetch() body chunks) that do not align
	// to OHTTP frame boundaries. The final chunk (length-0 marker) is delimited
	// by end-of-stream, so a decoder that decrypts it eagerly truncates it when
	// it arrives split across reads — this guards against that regression.
	function refragment(
		stream: ReadableStream<Uint8Array>,
		size: number,
	): ReadableStream<Uint8Array> {
		const reader = stream.getReader();
		let pending = new Uint8Array(0);
		let upstreamDone = false;
		return new ReadableStream<Uint8Array>({
			async pull(controller) {
				while (pending.length < size && !upstreamDone) {
					const { done, value } = await reader.read();
					if (done) {
						upstreamDone = true;
						break;
					}
					pending = concat(pending, value);
				}
				if (pending.length === 0) {
					controller.close();
					return;
				}
				const n = Math.min(size, pending.length);
				controller.enqueue(pending.slice(0, n));
				pending = pending.slice(n);
			},
		});
	}

	it.each([1, 7, 64, 1500])(
		"decrypts request and response split into %i-byte reads",
		async (readSize) => {
			const suite = new CipherSuite(
				KEM_DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_AES_128_GCM,
			);
			const keyConfig = await generateKeyConfig(suite, 0x01, [
				{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
			]);
			// Small maxChunkSize so the bodies span many frames, including a
			// final frame likely to straddle a read boundary.
			const client = new ChunkedOHTTPClient(
				suite,
				{
					keyId: keyConfig.keyId,
					kemId: keyConfig.kemId,
					publicKey: keyConfig.publicKey,
					symmetricAlgorithms: keyConfig.symmetricAlgorithms,
				},
				{ maxChunkSize: 64 },
			);
			const server = new ChunkedOHTTPServer([keyConfig], { maxChunkSize: 64 });

			const reqBody = `request-${"a".repeat(500)}`;
			const { init, context } = await client.encapsulateRequest(
				new Request("https://example.com/api", {
					method: "POST",
					headers: { "Content-Type": "text/plain" },
					body: reqBody,
				}),
			);
			const relayRequest = new Request("https://relay.example.com/ohttp", {
				...init,
				body: refragment(init.body as ReadableStream<Uint8Array>, readSize),
			});
			const { request: innerRequest, context: serverContext } =
				await server.decapsulateRequest(relayRequest);
			expect(await innerRequest.text()).toBe(reqBody);

			const resBody = `response-${"b".repeat(500)}`;
			const encapsulatedResponse = await serverContext.encapsulateResponse(
				new Response(resBody, { status: 200 }),
			);
			const fragmentedResponse = new Response(
				refragment(encapsulatedResponse.body as ReadableStream<Uint8Array>, readSize),
				{ status: encapsulatedResponse.status, headers: encapsulatedResponse.headers },
			);
			const finalResponse = await context.decapsulateResponse(fragmentedResponse);
			expect(await finalResponse.text()).toBe(resBody);
		},
	);
});

describe("received frame size limits (DoS regression)", () => {
	const encodeVarint4 = (n: number): Uint8Array =>
		new Uint8Array([0x80 | ((n >> 24) & 0x3f), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);

	it("parseFramedChunk rejects a frame larger than the cap instead of waiting for it", () => {
		// 1 GiB declared, one byte present.
		const hostile = concat(encodeVarint4(0x3fffffff), new Uint8Array([0x00]));
		expect(() => parseFramedChunk(hostile)).toThrow(OHTTPError);
		expect(() => parseFramedChunk(hostile)).toThrow(/CHUNK_LIMIT_EXCEEDED/);
	});

	it("parseFramedChunk honours an explicit cap and still returns undefined below it", () => {
		const frame = concat(encodeVarint4(4096), new Uint8Array(10));
		// Under the cap but genuinely incomplete: still "need more data".
		expect(parseFramedChunk(frame, 8192)).toBeUndefined();
		// Over a tighter cap: rejected outright.
		expect(() => parseFramedChunk(frame, 1024)).toThrow(OHTTPError);
	});

	it("parseFramedChunk accepts a frame exactly at the cap", () => {
		const size = 64;
		const frame = concat(encodeVarint4(size), new Uint8Array(size));
		const parsed = parseFramedChunk(frame, size);
		expect(parsed?.isFinal).toBe(false);
		expect(parsed?.ciphertext.length).toBe(size);
	});

	it("the decrypt stream rejects an oversized declared frame length", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const keyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		const client = new ChunkedOHTTPClient(suite, keyConfig);
		const server = new ChunkedOHTTPServer([keyConfig], { maxFrameSize: 4096 });

		const { encapsulatedRequest } = await client.encapsulate(
			new ReadableStream({
				start(c) {
					c.enqueue(new TextEncoder().encode("hello"));
					c.close();
				},
			}),
		);

		// Keep the real header, replace the body with one hostile frame header.
		const header = await collectHeader(encapsulatedRequest);
		const hostile = concat(header, encodeVarint4(0x3fffffff), new Uint8Array([0x00]));

		await expect(server.decapsulate(hostile)).rejects.toThrow(/CHUNK_LIMIT_EXCEEDED/);
	});

	it("the decrypt stream bounds the final chunk, which has no declared length", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const keyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		const client = new ChunkedOHTTPClient(suite, keyConfig);
		const server = new ChunkedOHTTPServer([keyConfig], { maxFrameSize: 4096 });

		const { encapsulatedRequest } = await client.encapsulate(
			new ReadableStream({
				start(c) {
					c.enqueue(new TextEncoder().encode("hello"));
					c.close();
				},
			}),
		);
		const header = await collectHeader(encapsulatedRequest);

		// 0-length marker opens the final chunk, then just keep sending.
		const flood = new Uint8Array(16384);
		const hostile = concat(header, new Uint8Array([0x00]), flood);

		await expect(server.decapsulate(hostile)).rejects.toThrow(/CHUNK_LIMIT_EXCEEDED/);
	});

	it("parseFramedChunk bounds the final chunk too", () => {
		const oversized = concat(new Uint8Array([0x00]), new Uint8Array(4097));
		expect(() => parseFramedChunk(oversized, 4096)).toThrow(/CHUNK_LIMIT_EXCEEDED/);
		expect(
			parseFramedChunk(concat(new Uint8Array([0x00]), new Uint8Array(4096)), 4096)?.isFinal,
		).toBe(true);
	});

	it("a chunk size above the default frame cap still round-trips when both sides set it", async () => {
		const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
		const keyConfig = await generateKeyConfig(suite, 1, [
			{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
		]);
		// maxChunkSize alone must lift the receive cap with it, tag included.
		const maxChunkSize = 2 * 1024 * 1024;
		const client = new ChunkedOHTTPClient(suite, keyConfig, { maxChunkSize });
		const server = new ChunkedOHTTPServer([keyConfig], { maxChunkSize });
		expect(server.maxFrameSize).toBeGreaterThanOrEqual(maxChunkSize + AEAD_TAG_SIZE);

		// One chunk, just past the default 1 MiB frame cap.
		const payload = new Uint8Array(DEFAULT_MAX_FRAME_SIZE + 100).fill(0x5a);
		const { encapsulatedRequest } = await client.encapsulate(payload);
		const { request } = await server.decapsulate(encapsulatedRequest);
		expect(request).toEqual(payload);
	});
});

/** Read the encapsulated request header (7 bytes + Nenc for X25519). */
async function collectHeader(encapsulatedRequest: Uint8Array): Promise<Uint8Array> {
	return encapsulatedRequest.subarray(0, 7 + 32);
}

describe("non-minimal varint framing", () => {
	// RFC 9000 permits a value to be encoded in any of the four varint widths, so
	// the same frame length has up to four wire encodings and all decode alike.
	it("accepts a non-minimal 2-byte final-chunk marker", () => {
		const frame = concat(new Uint8Array([0x40, 0x00]), new Uint8Array([1, 2, 3]));
		const parsed = parseFramedChunk(frame);
		expect(parsed?.isFinal).toBe(true);
		expect(parsed?.ciphertext).toEqual(new Uint8Array([1, 2, 3]));
		expect(parsed?.bytesConsumed).toBe(frame.length);
	});

	it("accepts a non-minimal 4-byte final-chunk marker", () => {
		const parsed = parseFramedChunk(new Uint8Array([0x80, 0x00, 0x00, 0x00]));
		expect(parsed?.isFinal).toBe(true);
		expect(parsed?.ciphertext).toEqual(new Uint8Array(0));
		expect(parsed?.bytesConsumed).toBe(4);
	});

	it("accepts a non-minimal 8-byte final-chunk marker", () => {
		const parsed = parseFramedChunk(new Uint8Array([0xc0, 0, 0, 0, 0, 0, 0, 0]));
		expect(parsed?.isFinal).toBe(true);
		expect(parsed?.ciphertext).toEqual(new Uint8Array(0));
		expect(parsed?.bytesConsumed).toBe(8);
	});

	it("accepts a non-minimal encoding of a small non-final length", () => {
		const payload = new Uint8Array([9, 8, 7, 6, 5]);
		const frame = concat(encodeVarint(5, 2), payload);
		const parsed = parseFramedChunk(frame);
		expect(parsed?.isFinal).toBe(false);
		expect(parsed?.ciphertext).toEqual(payload);
		expect(parsed?.bytesConsumed).toBe(7);
	});

	it("rejects an 8-byte varint declaring a value above quicvarint's MAX", () => {
		const frame = new Uint8Array([0xc0, 0, 0, 0, 0x80, 0, 0, 0]);
		expect(() => parseFramedChunk(frame)).toThrow(/INVALID_MESSAGE/);
	});
});
