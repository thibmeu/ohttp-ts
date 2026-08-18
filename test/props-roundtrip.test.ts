/**
 * Property tests for the non-chunked RFC 9458 encapsulation path: OHTTPClient,
 * OHTTPServer, and the primitives in src/encapsulation.ts.
 *
 * Fixtures (suites, key configs, clients, servers) are derived once at module
 * load and reused across every property run, since key generation dominates
 * the cost of a single HPKE round-trip.
 */

import fc from "fast-check";
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
import { describe, expect, it } from "vitest";
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
import { bytesArb } from "./props-helpers.js";

// ============================================================================
// Fixtures: derived once, reused across every property run
// ============================================================================

function seedBytes(fill: number, length = 64): Uint8Array {
	return new Uint8Array(length).fill(fill);
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
	const total = parts.reduce((sum, p) => sum + p.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const p of parts) {
		out.set(p, offset);
		offset += p.length;
	}
	return out;
}

const suiteA = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const suiteB = new CipherSuite(KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
// Same KDF/AEAD as suiteA but a different KEM: used to build a request whose
// header carries a KEM id that mismatches a same-keyId key config while its
// kdfId/aeadId still match, isolating the KEM comparison in decapsulateRequest.
const suiteCrossKem = new CipherSuite(
	KEM_DHKEM_P256_HKDF_SHA256,
	KDF_HKDF_SHA256,
	AEAD_AES_128_GCM,
);

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
// Same keyId and symmetric algorithm pair as keyConfigA, but a different KEM.
const keyConfigCrossKem = await deriveKeyConfig(suiteCrossKem, seedBytes(0x44), keyConfigA.keyId, [
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

// ============================================================================
// Shared assertion helper
// ============================================================================

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

// ============================================================================
// 1. Request/response round-trip
// ============================================================================

describe("request/response round-trip", () => {
	for (const s of setups) {
		it(`recovers request and response bytes exactly (${s.name})`, async () => {
			await fc.assert(
				fc.asyncProperty(
					bytesArb({ maxLength: 4096 }),
					bytesArb({ maxLength: 4096 }),
					async (request, response) => {
						const { encapsulatedRequest, context } = await s.client.encapsulate(request);
						const { request: decrypted, context: serverContext } =
							await s.server.decapsulate(encapsulatedRequest);
						expect(decrypted).toEqual(request);

						const encapsulatedResponse = await serverContext.encryptResponse(response);
						const decryptedResponse = await context.decryptResponse(encapsulatedResponse);
						expect(decryptedResponse).toEqual(response);
					},
				),
				{ numRuns: 15 },
			);
		});
	}

	it("round-trips a 0-byte request and a 0-byte response", async () => {
		const s = setups[0];
		if (s === undefined) throw new Error("no setup");
		const { encapsulatedRequest, context } = await s.client.encapsulate(new Uint8Array(0));
		const { request, context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
		expect(request).toEqual(new Uint8Array(0));
		const encapsulatedResponse = await serverContext.encryptResponse(new Uint8Array(0));
		await expect(context.decryptResponse(encapsulatedResponse)).resolves.toEqual(new Uint8Array(0));
	});

	it("round-trips a 1-byte request and a 1-byte response", async () => {
		const s = setups[0];
		if (s === undefined) throw new Error("no setup");
		const req = new Uint8Array([0x42]);
		const resp = new Uint8Array([0x99]);
		const { encapsulatedRequest, context } = await s.client.encapsulate(req);
		const { request, context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
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

	it("equals max(Nn, Nk) for every supported KDF/AEAD combination", () => {
		fc.assert(
			fc.property(
				fc.constantFrom(...kdfFactories),
				fc.constantFrom(...aeadCases),
				(kdfFactory, aeadCase) => {
					// KEM choice does not affect response nonce length, which is
					// derived purely from the AEAD's key/nonce sizes.
					const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, kdfFactory, aeadCase.factory);
					const nonceLength = getResponseNonceLength(suite);
					expect(nonceLength).toBe(Math.max(suite.AEAD.Nn, suite.AEAD.Nk));
					expect(nonceLength).toBe(aeadCase.expectedNonceLength);
				},
			),
			{ numRuns: 9 },
		);
	});

	for (const s of setups) {
		it(`encapsulated response is nonceLength + plaintext length + tag length (${s.name})`, async () => {
			await fc.assert(
				fc.asyncProperty(bytesArb({ maxLength: 2048 }), async (response) => {
					const { encapsulatedRequest } = await s.client.encapsulate(new Uint8Array([1, 2, 3]));
					const { context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
					const encapsulatedResponse = await serverContext.encryptResponse(response);
					const nonceLength = getResponseNonceLength(s.suite);
					expect(encapsulatedResponse.length).toBe(nonceLength + response.length + s.suite.AEAD.Nt);
				}),
				{ numRuns: 10 },
			);
		});

		it(`encapsulateResponse rejects a nonce of any length other than max(Nn, Nk) (${s.name})`, async () => {
			const nonceLength = getResponseNonceLength(s.suite);
			const { encapsulatedRequest } = await s.client.encapsulate(new Uint8Array([1]));
			const serverCtx = await decapsulateRequest(encapsulatedRequest, [s.keyConfig]);

			await fc.assert(
				fc.asyncProperty(
					fc.integer({ min: 0, max: nonceLength * 2 + 8 }).filter((n) => n !== nonceLength),
					async (wrongLength) => {
						const wrongNonce = new Uint8Array(wrongLength);
						await assertRejectsWithNoPlaintext(
							() => encapsulateResponse(serverCtx, new Uint8Array([1, 2, 3]), wrongNonce),
							OHTTPErrorCode.InvalidMessage,
						);
					},
				),
				{ numRuns: 15 },
			);
		});
	}
});

// ============================================================================
// 3. Header shape (RFC 9458 Section 4.1)
// ============================================================================

describe("header shape (RFC 9458 4.1)", () => {
	const realKemIds = Object.values(KemId);

	it("buildRequestHeader always produces exactly 7 bytes", () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 0, max: 255 }),
				fc.integer({ min: 0, max: 0xffff }),
				fc.integer({ min: 0, max: 0xffff }),
				fc.integer({ min: 0, max: 0xffff }),
				(keyId, kemId, kdfId, aeadId) => {
					expect(buildRequestHeader(keyId, kemId, kdfId, aeadId).length).toBe(7);
				},
			),
			{ numRuns: 30 },
		);
	});

	it("parseRequestHeader round-trips keyId/kdfId/aeadId (including non-library ids) with a real KEM id", () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 0, max: 255 }),
				fc.constantFrom(...realKemIds),
				fc.integer({ min: 0, max: 0xffff }),
				fc.integer({ min: 0, max: 0xffff }),
				fc.uint8Array({ minLength: 0, maxLength: 16 }),
				(keyId, kemId, kdfId, aeadId, trailing) => {
					const encLength = getEncLength(kemId);
					const enc = new Uint8Array(encLength).fill(0xab);
					const header = buildRequestHeader(keyId, kemId, kdfId, aeadId);
					const data = concatBytes(header, enc, trailing);

					const { header: parsed, offset } = parseRequestHeader(data);
					expect(parsed.keyId).toBe(keyId);
					expect(parsed.kemId).toBe(kemId);
					// kdfId/aeadId are raw wire values: parseRequestHeader does not
					// validate them, even when they are not valid library ids.
					expect(parsed.kdfId).toBe(kdfId);
					expect(parsed.aeadId).toBe(aeadId);
					expect(parsed.enc).toEqual(enc);
					expect(offset).toBe(7 + encLength);
				},
			),
			{ numRuns: 60 },
		);
	});

	it("buildRequestInfo ends with the 7-byte header", () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 0, max: 255 }),
				fc.constantFrom(...realKemIds),
				fc.integer({ min: 0, max: 0xffff }),
				fc.integer({ min: 0, max: 0xffff }),
				(keyId, kemId, kdfId, aeadId) => {
					const info = buildRequestInfo(keyId, kemId, kdfId, aeadId);
					const header = buildRequestHeader(keyId, kemId, kdfId, aeadId);
					expect(info.subarray(info.length - 7)).toEqual(header);
				},
			),
			{ numRuns: 20 },
		);
	});
});

// ============================================================================
// 4. Fail closed on mutation: single-bit flips
// ============================================================================

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

const bitFlipRequestArb = fc.record({
	request: bytesArb({ minLength: 1, maxLength: 24 }),
	region: fc.constantFrom<"header" | "enc" | "ciphertext">("header", "enc", "ciphertext"),
	offsetSeed: fc.nat(),
	bit: fc.integer({ min: 0, max: 7 }),
});

describe("fail closed on mutation: single-bit flips", () => {
	for (const s of setups) {
		it(`rejects any single-bit flip of an encapsulated request, never returns plaintext (${s.name})`, async () => {
			const encLen = getEncLength(s.keyConfig.kemId);

			await fc.assert(
				fc.asyncProperty(bitFlipRequestArb, async ({ request, region, offsetSeed, bit }) => {
					const { encapsulatedRequest } = await s.client.encapsulate(request);
					const bounds: Record<typeof region, readonly [number, number]> = {
						header: [0, 7],
						enc: [7, 7 + encLen],
						ciphertext: [7 + encLen, encapsulatedRequest.length],
					};
					const [start, end] = bounds[region];
					const regionLength = end - start;
					const idx = start + (offsetSeed % regionLength);
					const mutated = flipBit(encapsulatedRequest, idx, bit);

					await assertRejectsWithNoPlaintext(
						() => s.server.decapsulate(mutated).then((r) => r.request),
						expectedRequestFlipCodes(idx),
					);
				}),
				{ numRuns: 40 },
			);
		});

		it(`rejects any single-bit flip of an encapsulated response, never returns plaintext (${s.name})`, async () => {
			await fc.assert(
				fc.asyncProperty(
					bytesArb({ minLength: 1, maxLength: 24 }),
					bytesArb({ minLength: 0, maxLength: 24 }),
					fc.nat(),
					fc.integer({ min: 0, max: 7 }),
					async (request, response, offsetSeed, bit) => {
						const { encapsulatedRequest, context } = await s.client.encapsulate(request);
						const { context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
						const encapsulatedResponse = await serverContext.encryptResponse(response);

						const idx = offsetSeed % encapsulatedResponse.length;
						const mutated = flipBit(encapsulatedResponse, idx, bit);

						// Any bit flip in nonce or ciphertext+tag changes the derived
						// AEAD key/nonce or breaks authentication, so it always maps
						// to DecryptionFailed.
						await assertRejectsWithNoPlaintext(
							() => context.decryptResponse(mutated),
							OHTTPErrorCode.DecryptionFailed,
						);
					},
				),
				{ numRuns: 30 },
			);
		});
	}
});

// ============================================================================
// 5. Truncation and extension
// ============================================================================

describe("truncation and extension", () => {
	for (const s of setups) {
		it(`rejects a truncated or extended encapsulated request, never returns plaintext (${s.name})`, async () => {
			await fc.assert(
				fc.asyncProperty(
					bytesArb({ minLength: 1, maxLength: 24 }),
					fc.nat(),
					bytesArb({ minLength: 1, maxLength: 16 }),
					fc.boolean(),
					async (request, cutSeed, extra, truncate) => {
						const { encapsulatedRequest } = await s.client.encapsulate(request);
						const mutated = truncate
							? encapsulatedRequest.slice(0, cutSeed % encapsulatedRequest.length)
							: concatBytes(encapsulatedRequest, extra);

						await assertRejectsWithNoPlaintext(() =>
							s.server.decapsulate(mutated).then((r) => r.request),
						);
					},
				),
				{ numRuns: 25 },
			);
		});

		it(`rejects a truncated or extended encapsulated response, never returns plaintext (${s.name})`, async () => {
			await fc.assert(
				fc.asyncProperty(
					bytesArb({ minLength: 0, maxLength: 24 }),
					fc.nat(),
					bytesArb({ minLength: 1, maxLength: 16 }),
					fc.boolean(),
					async (response, cutSeed, extra, truncate) => {
						const { encapsulatedRequest, context } = await s.client.encapsulate(
							new Uint8Array([7]),
						);
						const { context: serverContext } = await s.server.decapsulate(encapsulatedRequest);
						const encapsulatedResponse = await serverContext.encryptResponse(response);

						const mutated = truncate
							? encapsulatedResponse.slice(0, cutSeed % encapsulatedResponse.length)
							: concatBytes(encapsulatedResponse, extra);

						await assertRejectsWithNoPlaintext(() => context.decryptResponse(mutated));
					},
				),
				{ numRuns: 20 },
			);
		});
	}
});

// ============================================================================
// 6. Cross-context isolation
// ============================================================================

describe("cross-context isolation", () => {
	for (const s of setups) {
		it(`a response encapsulated for one request context does not decrypt under another (${s.name})`, async () => {
			await fc.assert(
				fc.asyncProperty(
					bytesArb({ minLength: 0, maxLength: 64 }),
					bytesArb({ minLength: 0, maxLength: 64 }),
					async (request, response) => {
						// Two independent encapsulations of the (possibly identical)
						// request use fresh ephemeral HPKE keys, so their contexts differ.
						const enc1 = await s.client.encapsulate(request);
						const enc2 = await s.client.encapsulate(request);

						const { context: serverContext1 } = await s.server.decapsulate(
							enc1.encapsulatedRequest,
						);
						const encapsulatedResponse = await serverContext1.encryptResponse(response);

						await assertRejectsWithNoPlaintext(
							() => enc2.context.decryptResponse(encapsulatedResponse),
							OHTTPErrorCode.DecryptionFailed,
						);
					},
				),
				{ numRuns: 10 },
			);
		});
	}

	it("a request encapsulated for key A does not decapsulate under a server holding only a different key with the same keyId", async () => {
		const clientA = setups[0]?.client;
		if (clientA === undefined) throw new Error("no setup");
		const serverWithOtherKey = new OHTTPServer([keyConfigAAlt]);

		await fc.assert(
			fc.asyncProperty(bytesArb({ minLength: 0, maxLength: 64 }), async (request) => {
				const { encapsulatedRequest } = await clientA.encapsulate(request);
				await assertRejectsWithNoPlaintext(
					() => serverWithOtherKey.decapsulate(encapsulatedRequest).then((r) => r.request),
					OHTTPErrorCode.DecryptionFailed,
				);
			}),
			{ numRuns: 10 },
		);
	});
});

// ============================================================================
// Explicit vectors
// ============================================================================

describe("explicit vectors", () => {
	it("rejects a 6-byte request", async () => {
		await assertRejectsWithNoPlaintext(
			() => parseRequestHeader(new Uint8Array(6)),
			OHTTPErrorCode.InvalidMessage,
		);
	});

	it("rejects a request that is exactly 7 bytes (header only, no enc)", async () => {
		const header = buildRequestHeader(
			1,
			KemId.X25519_HKDF_SHA256,
			KdfId.HKDF_SHA256,
			AeadId.AES_128_GCM,
		);
		expect(header.length).toBe(7);
		await assertRejectsWithNoPlaintext(
			() => parseRequestHeader(header),
			OHTTPErrorCode.InvalidMessage,
		);
	});

	it("rejects a request with kemId 0x0000", async () => {
		const header = buildRequestHeader(1, 0x0000, KdfId.HKDF_SHA256, AeadId.AES_128_GCM);
		await assertRejectsWithNoPlaintext(
			() => parseRequestHeader(header),
			OHTTPErrorCode.UnsupportedCipherSuite,
		);
	});

	it("rejects a request with kemId 0xFFFF", async () => {
		const header = buildRequestHeader(1, 0xffff, KdfId.HKDF_SHA256, AeadId.AES_128_GCM);
		await assertRejectsWithNoPlaintext(
			() => parseRequestHeader(header),
			OHTTPErrorCode.UnsupportedCipherSuite,
		);
	});

	it("rejects a request whose header kemId differs from the matching keyId's key config", async () => {
		// keyConfigCrossKem shares keyConfigA's keyId and symmetric algorithm
		// pair, but was derived under a different KEM. The server holds only
		// keyConfigA, so the keyId lookup succeeds and the request must be
		// rejected on the KEM comparison specifically, before any HPKE
		// operation is attempted against keyConfigA's (X25519) key pair.
		const s = setups[0];
		if (s === undefined) throw new Error("no setup");
		const crossKemClient = new OHTTPClient(suiteCrossKem, keyConfigCrossKem);
		const { encapsulatedRequest } = await crossKemClient.encapsulate(new Uint8Array([1, 2, 3]));

		await assertRejectsWithNoPlaintext(
			() => s.server.decapsulate(encapsulatedRequest).then((r) => r.request),
			OHTTPErrorCode.UnsupportedCipherSuite,
		);
	});

	it("rejects a valid header with zero-length ciphertext", async () => {
		const s = setups[0];
		if (s === undefined) throw new Error("no setup");
		const encLen = getEncLength(s.keyConfig.kemId);
		const { encapsulatedRequest } = await s.client.encapsulate(new Uint8Array([1, 2, 3]));
		const headerAndEncOnly = encapsulatedRequest.slice(0, 7 + encLen);

		await assertRejectsWithNoPlaintext(
			() => s.server.decapsulate(headerAndEncOnly).then((r) => r.request),
			OHTTPErrorCode.DecryptionFailed,
		);
	});

	it("rejects a response of exactly nonceLength bytes (empty ciphertext)", async () => {
		const s = setups[0];
		if (s === undefined) throw new Error("no setup");
		const { context } = await s.client.encapsulate(new Uint8Array([1]));
		const nonceLength = getResponseNonceLength(s.suite);

		await assertRejectsWithNoPlaintext(
			() => context.decryptResponse(new Uint8Array(nonceLength)),
			OHTTPErrorCode.DecryptionFailed,
		);
	});

	it("rejects a response of nonceLength - 1 bytes", async () => {
		const s = setups[0];
		if (s === undefined) throw new Error("no setup");
		const { context } = await s.client.encapsulate(new Uint8Array([1]));
		const nonceLength = getResponseNonceLength(s.suite);

		await assertRejectsWithNoPlaintext(
			() => context.decryptResponse(new Uint8Array(nonceLength - 1)),
			OHTTPErrorCode.InvalidMessage,
		);
	});
});
