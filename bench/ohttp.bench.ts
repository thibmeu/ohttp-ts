/**
 * OHTTP throughput benchmarks (single-shot, non-chunked).
 *
 * Isolates each hot path so a change can be attributed:
 *  - encapsulateRequest  : client KEM SetupSender + Seal over the whole body
 *  - decapsulateRequest  : server KEM SetupRecipient + Open  (the server hot path)
 *  - encryptResponse     : HKDF Extract/Expand + raw AEAD Seal (response path)
 *  - decryptResponse     : HKDF Extract/Expand + raw AEAD Open
 *  - round-trip          : everything above, with a fresh ephemeral key each op
 *
 * Two payload sizes pick out the two regimes:
 *  - 1KB  : public-key setup dominates
 *  - 1MB  : bulk AEAD dominates
 *
 * The decap/decrypt cases reuse a pre-built request/response fixture so the
 * measured op excludes its own setup. These ops are stateless (fresh KEM
 * recipient context / fresh derived keys each call), so repeating them on the
 * same fixture is valid.
 *
 * Run: npm run bench            (Node)
 *      npm run bench:browser    (Chromium, same file)
 * For allocation/GC deltas of these paths, see `npm run bench:alloc`.
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

// Two regimes: setup-dominated (1KB) and AEAD-dominated (1MB).
const SIZES = [
	["1KB", 1_024],
	["1MB", 1_048_576],
] as const;

const payloads = new Map(SIZES.map(([label, n]) => [label, randomBytes(n)]));

// Pre-built fixtures so decap/decrypt benches measure only their own op.
interface Fixture {
	encapsulatedRequest: Uint8Array;
	clientCtx: Awaited<ReturnType<typeof client.encapsulate>>["context"];
	serverCtx: Awaited<ReturnType<typeof server.decapsulate>>["context"];
	encryptedResponse: Uint8Array;
}

const fixtures = new Map<string, Fixture>();
for (const [label] of SIZES) {
	const payload = payloads.get(label)!;
	const { encapsulatedRequest, context: clientCtx } = await client.encapsulate(payload);
	const { context: serverCtx } = await server.decapsulate(encapsulatedRequest);
	const encryptedResponse = await serverCtx.encryptResponse(payload);
	fixtures.set(label, { encapsulatedRequest, clientCtx, serverCtx, encryptedResponse });
}

describe("encapsulateRequest (client)", () => {
	for (const [label] of SIZES) {
		bench(label, async () => {
			await client.encapsulate(payloads.get(label)!);
		});
	}
});

describe("decapsulateRequest (server)", () => {
	for (const [label] of SIZES) {
		bench(label, async () => {
			await server.decapsulate(fixtures.get(label)!.encapsulatedRequest);
		});
	}
});

describe("encryptResponse (server)", () => {
	for (const [label] of SIZES) {
		bench(label, async () => {
			await fixtures.get(label)!.serverCtx.encryptResponse(payloads.get(label)!);
		});
	}
});

describe("decryptResponse (client)", () => {
	for (const [label] of SIZES) {
		bench(label, async () => {
			await fixtures.get(label)!.clientCtx.decryptResponse(fixtures.get(label)!.encryptedResponse);
		});
	}
});

describe("full round-trip", () => {
	for (const [label] of SIZES) {
		bench(label, async () => {
			const payload = payloads.get(label)!;
			const { encapsulatedRequest, context } = await client.encapsulate(payload);
			const { context: sctx } = await server.decapsulate(encapsulatedRequest);
			const encRes = await sctx.encryptResponse(payload);
			await context.decryptResponse(encRes);
		});
	}
});
