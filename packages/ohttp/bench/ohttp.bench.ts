import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { bench, describe } from "vitest";
import {
	AeadId,
	ChunkedOHTTPClient,
	ChunkedOHTTPServer,
	KdfId,
	KeyConfig,
	OHTTPClient,
	OHTTPServer,
} from "../src/index.js";

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

const keyConfig = await KeyConfig.generate(suite, 0x01, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);

const client = new OHTTPClient(suite, keyConfig);
const server = new OHTTPServer([keyConfig]);
const chunkedClient = new ChunkedOHTTPClient(suite, keyConfig);
const chunkedServer = new ChunkedOHTTPServer([keyConfig]);

// Random payload generator (handles >64KB via chunking)
function randomBytes(size: number): Uint8Array {
	const buf = new Uint8Array(size);
	const chunkSize = 65_536;
	for (let offset = 0; offset < size; offset += chunkSize) {
		const len = Math.min(chunkSize, size - offset);
		crypto.getRandomValues(buf.subarray(offset, offset + len));
	}
	return buf;
}

// Test payloads (random data, not zeros)
const _64B = randomBytes(64);
const _1KB = randomBytes(1_024);
const _16KB = randomBytes(16_384);
const _100KB = randomBytes(102_400);
const _1MB = randomBytes(1_048_576);
const _10MB = randomBytes(10_485_760);

describe("client.encapsulate", () => {
	bench("64B", async () => {
		await client.encapsulate(_64B);
	});

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

	bench("10MB", async () => {
		await client.encapsulate(_10MB);
	});
});

describe("server.decapsulate", async () => {
	const { encapsulatedRequest: enc64B } = await client.encapsulate(_64B);
	const { encapsulatedRequest: enc1KB } = await client.encapsulate(_1KB);
	const { encapsulatedRequest: enc16KB } = await client.encapsulate(_16KB);
	const { encapsulatedRequest: enc100KB } = await client.encapsulate(_100KB);
	const { encapsulatedRequest: enc1MB } = await client.encapsulate(_1MB);
	const { encapsulatedRequest: enc10MB } = await client.encapsulate(_10MB);

	bench("64B", async () => {
		await server.decapsulate(enc64B);
	});

	bench("1KB", async () => {
		await server.decapsulate(enc1KB);
	});

	bench("16KB", async () => {
		await server.decapsulate(enc16KB);
	});

	bench("100KB", async () => {
		await server.decapsulate(enc100KB);
	});

	bench("1MB", async () => {
		await server.decapsulate(enc1MB);
	});

	bench("10MB", async () => {
		await server.decapsulate(enc10MB);
	});
});

describe("full round-trip", () => {
	bench("64B", async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(_64B);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(_64B);
		await context.decryptResponse(encRes);
	});

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

	bench("10MB", async () => {
		const { encapsulatedRequest, context } = await client.encapsulate(_10MB);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(_10MB);
		await context.decryptResponse(encRes);
	});
});

describe("chunked round-trip", () => {
	bench("1KB", async () => {
		const { encapsulatedRequest, createResponseContext } =
			await chunkedClient.encapsulate(_1KB);
		const { createResponseContext: serverCreate } =
			await chunkedServer.decapsulate(encapsulatedRequest);
		const resCtx = await serverCreate();
		const encRes = await chunkedServer.encapsulateResponse(resCtx, _1KB);
		await chunkedClient.decapsulateResponse(createResponseContext, encRes);
	});

	bench("16KB", async () => {
		const { encapsulatedRequest, createResponseContext } =
			await chunkedClient.encapsulate(_16KB);
		const { createResponseContext: serverCreate } =
			await chunkedServer.decapsulate(encapsulatedRequest);
		const resCtx = await serverCreate();
		const encRes = await chunkedServer.encapsulateResponse(resCtx, _16KB);
		await chunkedClient.decapsulateResponse(createResponseContext, encRes);
	});

	bench("100KB", async () => {
		const { encapsulatedRequest, createResponseContext } =
			await chunkedClient.encapsulate(_100KB);
		const { createResponseContext: serverCreate } =
			await chunkedServer.decapsulate(encapsulatedRequest);
		const resCtx = await serverCreate();
		const encRes = await chunkedServer.encapsulateResponse(resCtx, _100KB);
		await chunkedClient.decapsulateResponse(createResponseContext, encRes);
	});

	bench("1MB", async () => {
		const { encapsulatedRequest, createResponseContext } =
			await chunkedClient.encapsulate(_1MB);
		const { createResponseContext: serverCreate } =
			await chunkedServer.decapsulate(encapsulatedRequest);
		const resCtx = await serverCreate();
		const encRes = await chunkedServer.encapsulateResponse(resCtx, _1MB);
		await chunkedClient.decapsulateResponse(createResponseContext, encRes);
	});
});
