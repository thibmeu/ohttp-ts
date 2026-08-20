/**
 * Property tests for the non-chunked RFC 9458 encapsulation path: OHTTPClient,
 * OHTTPServer, and the primitives in src/encapsulation.ts.
 *
 * Fixtures (suites, key configs, clients, servers) are derived once at module
 * load and reused across every property run, since key generation dominates
 * the cost of a single HPKE round-trip.
 */

import { fc, it } from "@fast-check/vitest";
import {
	AEAD_AES_128_GCM,
	AEAD_AES_256_GCM,
	AEAD_ChaCha20Poly1305,
	CipherSuite,
	KDF_HKDF_SHA256,
	KDF_HKDF_SHA384,
	KDF_HKDF_SHA512,
	KEM_DHKEM_P256_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { describe, expect } from "vitest";
import { OHTTPClient } from "../src/client.js";
import {
	buildRequestHeader,
	buildRequestInfo,
	decapsulateRequest,
	encapsulateResponse,
	getResponseNonceLength,
	parseRequestHeader,
} from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import {
	AeadId,
	deriveKeyConfig,
	getEncLength,
	KdfId,
	KemId,
	type KeyConfigWithPrivate,
} from "../src/keyConfig.js";
import { OHTTPServer } from "../src/server.js";
import { concat } from "../src/utils.js";
import { bytesArb, CRYPTO_RUNS } from "./props-helpers.js";

// ============================================================================
// Fixtures: derived once, reused across every property run
// ============================================================================

const suiteA = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const suiteB = new CipherSuite(KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
// A second suite (different KEM and AEAD) for the cross-suite `setups` entry.

const keyConfigA = await deriveKeyConfig(suiteA, seedBytes(0x11), 1, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);
const keyConfigB = await deriveKeyConfig(suiteB, seedBytes(0x22), 7, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_256_GCM },
]);
// Same keyId as keyConfigA, different underlying key material: used for
// cross-key isolation checks.
const keyConfigAAlt = await deriveKeyConfig(suiteA, seedBytes(0x33), keyConfigA.keyId, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);

interface Setup {
	readonly name: string;
	readonly suite: CipherSuite;
	readonly keyConfig: KeyConfigWithPrivate;
	readonly client: OHTTPClient;
	readonly server: OHTTPServer;
}

const setups: readonly Setup[] = [
	{
		name: "X25519+AES-128-GCM",
		suite: suiteA,
		keyConfig: keyConfigA,
		client: new OHTTPClient(suiteA, keyConfigA),
		server: new OHTTPServer([keyConfigA]),
	},
	{
		name: "P-256+AES-256-GCM",
		suite: suiteB,
		keyConfig: keyConfigB,
		client: new OHTTPClient(suiteB, keyConfigB),
		server: new OHTTPServer([keyConfigB]),
	},
];

const firstSetup = setups[0];
if (firstSetup === undefined) throw new Error("no setup");

const CRYPTO = { numRuns: CRYPTO_RUNS };

// ============================================================================
// 1. Request/response round-trip
// ============================================================================

describe("request/response round-trip", () => {
	for (const s of setups) {
		it.prop([bytesArb({ maxLength: 4096 }), bytesArb({ maxLength: 4096 })], CRYPTO)(
			`recovers request and response bytes exactly (${s.name})`,
			async (request, response) => {
				const { encapsulatedRequest, context } = await s.client.encapsulate(request);
				const { request: decrypted, context: serverContext } =
					await s.server.decapsulate(encapsulatedRequest);
				expect(decrypted).toEqual(request);

				const encapsulatedResponse = await serverContext.encryptResponse(response);
				expect(await context.decryptResponse(encapsulatedResponse)).toEqual(response);
			},
		);
	}

	it("round-trips a 0-byte request and a 0-byte response", async () => {
		const { encapsulatedRequest, context } = await firstSetup.client.encapsulate(new Uint8Array(0));
		const { request, context: serverContext } =
			await firstSetup.server.decapsulate(encapsulatedRequest);
		expect(request).toEqual(new Uint8Array(0));
		const encapsulatedResponse = await serverContext.encryptResponse(new Uint8Array(0));
		await expect(context.decryptResponse(encapsulatedResponse)).resolves.toEqual(new Uint8Array(0));
	});

	it("round-trips a 1-byte request and a 1-byte response", async () => {
		const req = new Uint8Array([0x42]);
		const resp = new Uint8Array([0x99]);
		const { encapsulatedRequest, context } = await firstSetup.client.encapsulate(req);
		const { request, context: serverContext } =
			await firstSetup.server.decapsulate(encapsulatedRequest);
		expect(request).toEqual(req);
		const encapsulatedResponse = await serverContext.encryptResponse(resp);
		await expect(context.decryptResponse(encapsulatedResponse)).resolves.toEqual(resp);
	});
});

// ============================================================================
// 2. Response nonce length (RFC 9458 Section 4.2)
// ============================================================================

describe("response nonce length (RFC 9458 4.2)", () => {
	const kdfFactories = [KDF_HKDF_SHA256, KDF_HKDF_SHA384, KDF_HKDF_SHA512];
	const aeadCases = [
		{ factory: AEAD_AES_128_GCM, expectedNonceLength: 16 },
		{ factory: AEAD_AES_256_GCM, expectedNonceLength: 32 },
		{ factory: AEAD_ChaCha20Poly1305, expectedNonceLength: 32 },
	];

	it.prop([fc.constantFrom(...kdfFactories), fc.constantFrom(...aeadCases)], CRYPTO)(
		"equals max(Nn, Nk) for every supported KDF/AEAD combination",
		(kdfFactory, aeadCase) => {
			// KEM choice does not affect response nonce length, which is
			// derived purely from the AEAD's key/nonce sizes.
			const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, kdfFactory, aeadCase.factory);
			const nonceLength = getResponseNonceLength(suite);
			expect(nonceLength).toBe(Math.max(suite.AEAD.Nn, suite.AEAD.Nk));
			expect(nonceLength).toBe(aeadCase.expectedNonceLength);
		},
	);

	for (const s of setups) {
		it.prop([bytesArb({ maxLength: 2048 })], CRYPTO)(
			`encapsulated response is nonceLength + plaintext length + tag length (${s.name})`,
			async (response) => {
				const { encapsulatedRequest } = await s.client.encapsulate(new Uint8Array([1, 2, 3]));
				const { context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
				const encapsulatedResponse = await serverContext.encryptResponse(response);
				const nonceLength = getResponseNonceLength(s.suite);
				expect(encapsulatedResponse.length).toBe(nonceLength + response.length + s.suite.AEAD.Nt);
			},
		);

		const nonceLength = getResponseNonceLength(s.suite);
		it.prop(
			[fc.integer({ min: 0, max: nonceLength * 2 + 8 }).filter((n) => n !== nonceLength)],
			CRYPTO,
		)(
			`encapsulateResponse rejects a nonce of any length other than max(Nn, Nk) (${s.name})`,
			async (wrongLength) => {
				const { encapsulatedRequest } = await s.client.encapsulate(new Uint8Array([1]));
				const serverCtx = await decapsulateRequest(encapsulatedRequest, [s.keyConfig]);
				await assertRejectsWithNoPlaintext(
					() =>
						encapsulateResponse(serverCtx, new Uint8Array([1, 2, 3]), new Uint8Array(wrongLength)),
					OHTTPErrorCode.InvalidMessage,
				);
			},
		);
	}
});

// ============================================================================
// 3. Header shape (RFC 9458 Section 4.1)
// ============================================================================

describe("header shape (RFC 9458 4.1)", () => {
	const keyIdArb = fc.integer({ min: 0, max: 255 });
	const wireIdArb = fc.integer({ min: 0, max: 0xffff });
	const realKemIdArb = fc.constantFrom(...Object.values(KemId));

	it.prop([keyIdArb, wireIdArb, wireIdArb, wireIdArb], CRYPTO)(
		"buildRequestHeader always produces exactly 7 bytes",
		(keyId, kemId, kdfId, aeadId) => {
			expect(buildRequestHeader(keyId, kemId, kdfId, aeadId).length).toBe(7);
		},
	);

	it.prop([keyIdArb, realKemIdArb, wireIdArb, wireIdArb, fc.uint8Array({ maxLength: 16 })], CRYPTO)(
		"parseRequestHeader round-trips keyId/kdfId/aeadId (including non-library ids) with a real KEM id",
		(keyId, kemId, kdfId, aeadId, trailing) => {
			const encLength = getEncLength(kemId);
			const enc = new Uint8Array(encLength).fill(0xab);
			const header = buildRequestHeader(keyId, kemId, kdfId, aeadId);

			const { header: parsed, offset } = parseRequestHeader(concat(header, enc, trailing));
			expect(parsed.keyId).toBe(keyId);
			expect(parsed.kemId).toBe(kemId);
			// kdfId/aeadId are raw wire values: parseRequestHeader does not
			// validate them, even when they are not valid library ids.
			expect(parsed.kdfId).toBe(kdfId);
			expect(parsed.aeadId).toBe(aeadId);
			expect(parsed.enc).toEqual(enc);
			expect(offset).toBe(7 + encLength);
		},
	);

	it.prop([keyIdArb, realKemIdArb, wireIdArb, wireIdArb], CRYPTO)(
		"buildRequestInfo ends with the 7-byte header",
		(keyId, kemId, kdfId, aeadId) => {
			const info = buildRequestInfo(keyId, kemId, kdfId, aeadId);
			expect(info.subarray(info.length - 7)).toEqual(
				buildRequestHeader(keyId, kemId, kdfId, aeadId),
			);
		},
	);
});

// ============================================================================
// 4. Fail closed on mutation: single-bit flips
// ============================================================================

const bitFlipRequestArb = fc.record({
	request: bytesArb({ minLength: 1, maxLength: 24 }),
	region: fc.constantFrom<"header" | "enc" | "ciphertext">("header", "enc", "ciphertext"),
	offsetSeed: fc.nat(),
	bit: fc.integer({ min: 0, max: 7 }),
});

describe("fail closed on mutation: single-bit flips", () => {
	for (const s of setups) {
		const encLen = getEncLength(s.keyConfig.kemId);

		it.prop([bitFlipRequestArb], CRYPTO)(
			`rejects any single-bit flip of an encapsulated request, never returns plaintext (${s.name})`,
			async ({ request, region, offsetSeed, bit }) => {
				const { encapsulatedRequest } = await s.client.encapsulate(request);
				const bounds: Record<typeof region, readonly [number, number]> = {
					header: [0, 7],
					enc: [7, 7 + encLen],
					ciphertext: [7 + encLen, encapsulatedRequest.length],
				};
				const [start, end] = bounds[region];
				const idx = start + (offsetSeed % (end - start));

				await assertRejectsWithNoPlaintext(
					() => s.server.decapsulate(flipBit(encapsulatedRequest, idx, bit)).then((r) => r.request),
					expectedRequestFlipCodes(idx),
				);
			},
		);

		it.prop(
			[
				bytesArb({ minLength: 1, maxLength: 24 }),
				bytesArb({ maxLength: 24 }),
				fc.nat(),
				fc.integer({ min: 0, max: 7 }),
			],
			CRYPTO,
		)(
			`rejects any single-bit flip of an encapsulated response, never returns plaintext (${s.name})`,
			async (request, response, offsetSeed, bit) => {
				const { encapsulatedRequest, context } = await s.client.encapsulate(request);
				const { context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
				const encapsulatedResponse = await serverContext.encryptResponse(response);
				const idx = offsetSeed % encapsulatedResponse.length;

				// Any bit flip in nonce or ciphertext+tag changes the derived
				// AEAD key/nonce or breaks authentication, so it always maps
				// to DecryptionFailed.
				await assertRejectsWithNoPlaintext(
					() => context.decryptResponse(flipBit(encapsulatedResponse, idx, bit)),
					OHTTPErrorCode.DecryptionFailed,
				);
			},
		);
	}
});

// ============================================================================
// 5. Truncation and extension
// ============================================================================

describe("truncation and extension", () => {
	for (const s of setups) {
		it.prop(
			[
				bytesArb({ minLength: 1, maxLength: 24 }),
				fc.nat(),
				bytesArb({ minLength: 1, maxLength: 16 }),
				fc.boolean(),
			],
			CRYPTO,
		)(
			`rejects a truncated or extended encapsulated request, never returns plaintext (${s.name})`,
			async (request, cutSeed, extra, truncate) => {
				const { encapsulatedRequest } = await s.client.encapsulate(request);
				const mutated = truncate
					? encapsulatedRequest.slice(0, cutSeed % encapsulatedRequest.length)
					: concat(encapsulatedRequest, extra);

				await assertRejectsWithNoPlaintext(() =>
					s.server.decapsulate(mutated).then((r) => r.request),
				);
			},
		);

		it.prop(
			[
				bytesArb({ maxLength: 24 }),
				fc.nat(),
				bytesArb({ minLength: 1, maxLength: 16 }),
				fc.boolean(),
			],
			CRYPTO,
		)(
			`rejects a truncated or extended encapsulated response, never returns plaintext (${s.name})`,
			async (response, cutSeed, extra, truncate) => {
				const { encapsulatedRequest, context } = await s.client.encapsulate(new Uint8Array([7]));
				const { context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
				const encapsulatedResponse = await serverContext.encryptResponse(response);

				const mutated = truncate
					? encapsulatedResponse.slice(0, cutSeed % encapsulatedResponse.length)
					: concat(encapsulatedResponse, extra);

				await assertRejectsWithNoPlaintext(() => context.decryptResponse(mutated));
			},
		);
	}
});

// ============================================================================
// 6. Cross-context isolation
// ============================================================================

describe("cross-context isolation", () => {
	for (const s of setups) {
		it.prop([bytesArb({ maxLength: 64 }), bytesArb({ maxLength: 64 })], CRYPTO)(
			`a response encapsulated for one request context does not decrypt under another (${s.name})`,
			async (request, response) => {
				// Two independent encapsulations of the (possibly identical)
				// request use fresh ephemeral HPKE keys, so their contexts differ.
				const enc1 = await s.client.encapsulate(request);
				const enc2 = await s.client.encapsulate(request);

				const { context: serverContext1 } = await s.server.decapsulate(enc1.encapsulatedRequest);
				const encapsulatedResponse = await serverContext1.encryptResponse(response);

				await assertRejectsWithNoPlaintext(
					() => enc2.context.decryptResponse(encapsulatedResponse),
					OHTTPErrorCode.DecryptionFailed,
				);
			},
		);
	}

	const serverWithOtherKey = new OHTTPServer([keyConfigAAlt]);

	it.prop([bytesArb({ maxLength: 64 })], CRYPTO)(
		"a request encapsulated for key A does not decapsulate under a server holding only a different key with the same keyId",
		async (request) => {
			const { encapsulatedRequest } = await firstSetup.client.encapsulate(request);
			await assertRejectsWithNoPlaintext(
				() => serverWithOtherKey.decapsulate(encapsulatedRequest).then((r) => r.request),
				OHTTPErrorCode.DecryptionFailed,
			);
		},
	);
});

// Helpers

function seedBytes(fill: number, length = 64): Uint8Array {
	return new Uint8Array(length).fill(fill);
}

/**
 * Runs `fn`, which is expected to throw/reject. Asserts that it does, that no
 * value (in particular no plaintext) escapes on the resolved path, and — when
 * `expectedCodes` is given — that the failure is an OHTTPError whose code is
 * one of them.
 */
async function assertRejectsWithNoPlaintext(
	fn: () => unknown,
	expectedCodes?: OHTTPErrorCode | readonly OHTTPErrorCode[],
): Promise<void> {
	let result: unknown;
	let thrown: unknown;
	try {
		result = await fn();
	} catch (e) {
		thrown = e;
	}
	expect(result).toBeUndefined();
	expect(thrown).toBeInstanceOf(OHTTPError);
	if (expectedCodes !== undefined && thrown instanceof OHTTPError) {
		const codes = Array.isArray(expectedCodes) ? expectedCodes : [expectedCodes];
		expect(codes).toContain(thrown.code);
	}
}

function flipBit(data: Uint8Array, index: number, bit: number): Uint8Array {
	const copy = new Uint8Array(data);
	const current = copy[index];
	if (current === undefined) {
		throw new Error("flipBit: index out of range");
	}
	copy[index] = current ^ (1 << bit);
	return copy;
}

/**
 * Given the exact byte index flipped in an encapsulated request (indices 0-6
 * are the header, [7, 7+Nenc) is enc, the rest is ciphertext+tag), returns the
 * set of OHTTPError codes that flip could possibly produce.
 *
 * - index 0 (keyId): always a different byte value, and the server only knows
 *   one keyId per setup, so lookup always misses -> UnknownKeyId.
 * - indices 1-2 (kemId): always a different 16-bit value. Either it is not a
 *   recognized KEM (UnsupportedCipherSuite from getEncLength), the resulting
 *   Nenc no longer fits the message (InvalidMessage), or it is a recognized
 *   but different KEM than the key config's (UnsupportedCipherSuite).
 * - indices 3-6 (kdfId/aeadId): always a different pair than the single
 *   symmetric algorithm each setup's key config offers -> UnsupportedCipherSuite.
 * - enc or ciphertext bytes: HPKE setup or AEAD authentication fails -> both
 *   map to DecryptionFailed.
 */
function expectedRequestFlipCodes(idx: number): readonly OHTTPErrorCode[] {
	if (idx === 0) return [OHTTPErrorCode.UnknownKeyId];
	if (idx === 1 || idx === 2) {
		return [OHTTPErrorCode.InvalidMessage, OHTTPErrorCode.UnsupportedCipherSuite];
	}
	if (idx >= 3 && idx <= 6) return [OHTTPErrorCode.UnsupportedCipherSuite];
	return [OHTTPErrorCode.DecryptionFailed];
}
