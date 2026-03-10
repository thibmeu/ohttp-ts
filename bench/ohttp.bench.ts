/**
 * OHTTP throughput benchmarks
 *
 * These measure raw crypto performance with in-memory data.
 * For streaming benefits (TTFB, memory), see ttfb.bench.ts
 */

import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { bench, describe } from "vitest";
import { AeadId, KdfId, KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

const keyConfig = await KeyConfig.generate(suite, 0x01, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);

const client = new OHTTPClient(suite, keyConfig);
const server = new OHTTPServer([keyConfig]);

function randomBytes(size: number): Uint8Array {
	const buf = new Uint8Array(size);
	const chunkSize = 65_536;
	for (let offset = 0; offset < size; offset += chunkSize) {
		const len = Math.min(chunkSize, size - offset);
		crypto.getRandomValues(buf.subarray(offset, offset + len));
	}
	return buf;
}

const _1KB = randomBytes(1_024);
const _16KB = randomBytes(16_384);
const _100KB = randomBytes(102_400);
const _1MB = randomBytes(1_048_576);

describe("encapsulate", () => {
	bench("1KB", async () => {
		await client.encapsulate(_1KB);
	});

	bench("16KB", async () => {
		await client.encapsulate(_16KB);
	});

	bench("100KB", async () => {
		await client.encapsulate(_100KB);
	});

	bench("1MB", async () => {
		await client.encapsulate(_1MB);
	});
});

describe("full round-trip", () => {
	bench("1KB", async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(_1KB);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(_1KB);
		await context.decryptResponse(encRes);
	});

	bench("16KB", async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(_16KB);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(_16KB);
		await context.decryptResponse(encRes);
	});

	bench("100KB", async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(_100KB);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(_100KB);
		await context.decryptResponse(encRes);
	});

	bench("1MB", async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(_1MB);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(_1MB);
		await context.decryptResponse(encRes);
	});
});
