/**
 * Property tests for chunked OHTTP streaming (draft-ietf-ohai-chunked-ohttp-08,
 * Sections 6.2 and 7.3): the chunker/encrypt/decrypt transforms in
 * src/streaming.ts, the ChunkedOHTTPClient/ChunkedOHTTPServer convenience
 * methods built on top of them, and the response chunk AEAD primitives in
 * src/encapsulation.ts.
 */

import fc from "fast-check";
import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { encode as encodeVarint } from "quicvarint";
import { describe, expect, it } from "vitest";
import { ChunkedOHTTPClient } from "../src/client.js";
import {
	computeChunkNonce,
	DEFAULT_MAX_FRAME_SIZE,
	frameChunk,
	openResponseChunk,
	sealResponseChunk,
} from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import { AeadId, generateKeyConfig, KdfId } from "../src/keyConfig.js";
import { ChunkedOHTTPServer } from "../src/server.js";
import {
	collectStream,
	createChunkerTransform,
	createRequestDecryptTransform,
	createRequestEncryptTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
	streamOfBytes,
} from "../src/streaming.js";
import { concat } from "../src/utils.js";
import {
	bytesArb,
	bytesOfLengthArb,
	CRYPTO_RUNS,
	splitAt,
	splitPointsArb,
} from "./props-helpers.js";

// ============================================================================
// Shared fixtures - built once and reused across every property run below.
// Key generation is the expensive part; per-run HPKE handshakes (a single
// X25519 DH each) and AEAD calls are cheap enough to redo every run.
// ============================================================================

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

const serverKeyConfig = await generateKeyConfig(suite, 1, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);

const publicKeyConfig = {
	keyId: serverKeyConfig.keyId,
	kemId: serverKeyConfig.kemId,
	publicKey: serverKeyConfig.publicKey,
	symmetricAlgorithms: serverKeyConfig.symmetricAlgorithms,
};

const client = new ChunkedOHTTPClient(suite, publicKeyConfig);
const server = new ChunkedOHTTPServer([serverKeyConfig]);

/** A fresh, matched HPKE sender/recipient pair. Each owns independent sequence
 * state, so tests that need in-order Seal/Open calls to line up must draw a
 * fresh pair rather than share one across property runs. */
async function freshRequestPair() {
	const clientCtx = await client.createRequestContext();
	const serverCtx = await server.createRequestContext(clientCtx.header);
	return { clientCtx, serverCtx };
}

/**
 * Fixed response-chunk AEAD key material, derived once and reused across every
 * response-leg property below. sealResponseChunk/openResponseChunk are pure
 * functions of an explicit counter (draft-08 Section 6.2), so sharing this
 * derivation across runs is safe: nothing here carries state between calls.
 */
const responseKeys = await (async () => {
	const { serverCtx } = await freshRequestPair();
	const responseCtx = await serverCtx.createResponseContext();
	return {
		aead: responseCtx._aead,
		aeadKey: responseCtx._aeadKey,
		aeadNonce: responseCtx._aeadNonce,
	};
})();

// ============================================================================
// Local helpers (test-only; not exported from the package)
// ============================================================================

/** A ReadableStream that emits each piece as its own read, then closes. */
function streamFromPieces(pieces: readonly Uint8Array[]): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		start(controller) {
			for (const piece of pieces) {
				if (piece.length > 0) controller.enqueue(piece);
			}
			controller.close();
		},
	});
}

/** Collect a stream's chunks without merging them, to inspect individual chunk sizes. */
async function collectPieces(stream: ReadableStream<Uint8Array>): Promise<Uint8Array[]> {
	const pieces: Uint8Array[] = [];
	const reader = stream.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		pieces.push(value);
	}
	return pieces;
}

/** Split `data` into one piece per byte. */
function byteAtATime(data: Uint8Array): Uint8Array[] {
	return Array.from(data, (b) => Uint8Array.of(b));
}

/** Await `promise`, asserting it rejects with an OHTTPError, and return it. */
async function expectOHTTPError(promise: Promise<unknown>): Promise<OHTTPError> {
	try {
		await promise;
	} catch (error) {
		if (error instanceof OHTTPError) return error;
		throw error;
	}
	throw new Error("expected an OHTTPError to be thrown, but the promise resolved");
}

async function decryptRequestFrames(
	recipientContext: Parameters<typeof createRequestDecryptTransform>[0],
	pieces: readonly Uint8Array[],
	maxFrameSize: number = DEFAULT_MAX_FRAME_SIZE,
): Promise<Uint8Array> {
	return collectStream(
		streamFromPieces(pieces).pipeThrough(
			createRequestDecryptTransform(recipientContext, maxFrameSize),
		),
	);
}

async function decryptResponseFrames(
	pieces: readonly Uint8Array[],
	maxFrameSize: number = DEFAULT_MAX_FRAME_SIZE,
): Promise<Uint8Array> {
	return collectStream(
		streamFromPieces(pieces).pipeThrough(
			createResponseDecryptTransform(
				responseKeys.aead,
				responseKeys.aeadKey,
				responseKeys.aeadNonce,
				maxFrameSize,
			),
		),
	);
}

// ============================================================================
// Property 2: createChunkerTransform
// ============================================================================

describe("createChunkerTransform", () => {
	it("emits chunks of at most n, all but the last exactly n, concatenating to the input", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesArb({ maxLength: 200 }), { maxLength: 10 }),
				fc.integer({ min: 1, max: 100 }),
				async (writes, maxChunkSize) => {
					const input = concat(...writes);
					const chunks = await collectPieces(
						streamFromPieces(writes).pipeThrough(createChunkerTransform(maxChunkSize)),
					);

					for (let i = 0; i < chunks.length; i++) {
						const chunk = chunks[i] as Uint8Array;
						expect(chunk.length).toBeLessThanOrEqual(maxChunkSize);
						if (i < chunks.length - 1) {
							expect(chunk.length).toBe(maxChunkSize);
						}
					}
					expect(concat(...chunks)).toEqual(input);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});

// ============================================================================
// Property 1: chunk-boundary independence (request and response legs)
// ============================================================================

describe("chunk-boundary independence", () => {
	it("request: re-splitting the ciphertext stream at arbitrary boundaries still decrypts to the original plaintext", async () => {
		await fc.assert(
			fc.asyncProperty(
				bytesArb({ maxLength: 512 }),
				fc.integer({ min: 1, max: 48 }),
				async (plaintext, maxChunkSize) => {
					const { clientCtx, serverCtx } = await freshRequestPair();
					const cipherBody = await collectStream(
						streamOfBytes(plaintext)
							.pipeThrough(createChunkerTransform(maxChunkSize))
							.pipeThrough(createRequestEncryptTransform(clientCtx._senderContext)),
					);

					// One giant buffer (a single read).
					expect(await decryptRequestFrames(serverCtx._recipientContext, [cipherBody])).toEqual(
						plaintext,
					);

					// Byte-at-a-time delivery.
					const { serverCtx: serverCtx2 } = await freshRequestPair2(clientCtx);
					expect(
						await decryptRequestFrames(serverCtx2._recipientContext, byteAtATime(cipherBody)),
					).toEqual(plaintext);

					// Arbitrary re-split boundaries drawn from the shared helper.
					const points = fc.sample(splitPointsArb(cipherBody.length, 8), 1)[0] ?? [];
					const { serverCtx: serverCtx3 } = await freshRequestPair2(clientCtx);
					expect(
						await decryptRequestFrames(serverCtx3._recipientContext, splitAt(cipherBody, points)),
					).toEqual(plaintext);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("response: re-splitting the ciphertext stream at arbitrary boundaries still decrypts to the original plaintext", async () => {
		await fc.assert(
			fc.asyncProperty(
				bytesArb({ maxLength: 512 }),
				fc.integer({ min: 1, max: 48 }),
				async (plaintext, maxChunkSize) => {
					const cipherBody = await collectStream(
						streamOfBytes(plaintext)
							.pipeThrough(createChunkerTransform(maxChunkSize))
							.pipeThrough(
								createResponseEncryptTransform(
									responseKeys.aead,
									responseKeys.aeadKey,
									responseKeys.aeadNonce,
								),
							),
					);

					// One giant buffer.
					expect(await decryptResponseFrames([cipherBody])).toEqual(plaintext);
					// Byte-at-a-time delivery.
					expect(await decryptResponseFrames(byteAtATime(cipherBody))).toEqual(plaintext);
					// Arbitrary re-split boundaries.
					const points = fc.sample(splitPointsArb(cipherBody.length, 8), 1)[0] ?? [];
					expect(await decryptResponseFrames(splitAt(cipherBody, points))).toEqual(plaintext);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});

/** Reuse an already-sealed request's header to derive another matched
 * recipient context, since the header alone (independent of any Seal calls
 * already issued on the sender) is all SetupRecipient needs. */
async function freshRequestPair2(clientCtx: { header: Uint8Array }) {
	const serverCtx = await server.createRequestContext(clientCtx.header);
	return { serverCtx };
}

// ============================================================================
// Property 3: truncation is rejected
// ============================================================================

describe("truncation is rejected", () => {
	it("any proper prefix of a valid chunked request body fails to decrypt, never yielding partial plaintext", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesOfLengthArb(6), { minLength: 1, maxLength: 4 }),
				bytesOfLengthArb(6),
				async (nonFinalPlaintexts, finalPlaintext) => {
					const clientCtx = await client.createRequestContext();

					const nonFinalFrames: Uint8Array[] = [];
					for (const pt of nonFinalPlaintexts) {
						const ct = await clientCtx.sealChunk(pt);
						nonFinalFrames.push(frameChunk(ct, false));
					}
					const finalCt = await clientCtx.sealFinalChunk(finalPlaintext);
					const finalFrame = frameChunk(finalCt, true);

					const markerOffset = nonFinalFrames.reduce((n, f) => n + f.length, 0);
					const body = concat(...nonFinalFrames, finalFrame);

					// Any cut strictly before the end drops at least the last byte of the
					// final chunk's ciphertext, so it can never be a complete message.
					const cut = fc.sample(fc.integer({ min: 0, max: body.length - 1 }), 1)[0] ?? 0;
					const prefix = body.subarray(0, cut);

					const { serverCtx: freshServerCtx } = await freshRequestPair2(clientCtx);
					const error = await expectOHTTPError(
						decryptRequestFrames(freshServerCtx._recipientContext, [prefix]),
					);

					// Below the final marker, the stream ends without ever seeing one:
					// that is unambiguously InvalidMessage. At or past it, the marker
					// was seen but its ciphertext is incomplete, which fails to
					// authenticate instead (still an OHTTPError, just not this code).
					if (cut <= markerOffset) {
						expect(error.code).toBe(OHTTPErrorCode.InvalidMessage);
					}
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("dropping just the final chunk (all non-final frames present, no final marker) is InvalidMessage", async () => {
		const { clientCtx } = await freshRequestPair();
		const ct1 = await clientCtx.sealChunk(new Uint8Array([1, 2, 3]));
		const body = frameChunk(ct1, false); // no final marker follows

		const { serverCtx } = await freshRequestPair2(clientCtx);
		const error = await expectOHTTPError(decryptRequestFrames(serverCtx._recipientContext, [body]));
		expect(error.code).toBe(OHTTPErrorCode.InvalidMessage);
	});

	it("cutting mid-frame (partial length prefix or partial ciphertext) never resolves, and reports InvalidMessage once the stream ends", async () => {
		const { clientCtx } = await freshRequestPair();
		const ct1 = await clientCtx.sealChunk(new Uint8Array(40));
		const framed = frameChunk(ct1, false);
		const midFrame = framed.subarray(0, framed.length - 5); // cut inside the ciphertext

		const { serverCtx } = await freshRequestPair2(clientCtx);
		const error = await expectOHTTPError(
			decryptRequestFrames(serverCtx._recipientContext, [midFrame]),
		);
		expect(error.code).toBe(OHTTPErrorCode.InvalidMessage);
	});
});

// ============================================================================
// Property 4: a non-final chunk that decrypts to zero-length plaintext is rejected
// ============================================================================

describe("zero-length non-final chunk is rejected", () => {
	it("a deliberately-sealed empty non-final chunk anywhere in the stream fails decryption", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesOfLengthArb(4), { minLength: 0, maxLength: 3 }),
				fc.array(bytesOfLengthArb(4), { minLength: 0, maxLength: 3 }),
				bytesOfLengthArb(4),
				async (before, after, finalPlaintext) => {
					let counter = 0;
					const frames: Uint8Array[] = [];

					for (const pt of before) {
						const ct = await sealResponseChunk(
							responseKeys.aead,
							responseKeys.aeadKey,
							responseKeys.aeadNonce,
							counter++,
							pt,
							false,
						);
						frames.push(frameChunk(ct, false));
					}

					// The deliberately-invalid frame: a real Seal of an empty plaintext,
					// framed as non-final with its true (non-zero, tag-only) ciphertext
					// length - distinct from the wire's final-chunk marker.
					const zeroCt = await sealResponseChunk(
						responseKeys.aead,
						responseKeys.aeadKey,
						responseKeys.aeadNonce,
						counter++,
						new Uint8Array(0),
						false,
					);
					expect(zeroCt.length).toBeGreaterThan(0); // AEAD tag makes the wire length non-zero
					frames.push(frameChunk(zeroCt, false));

					for (const pt of after) {
						const ct = await sealResponseChunk(
							responseKeys.aead,
							responseKeys.aeadKey,
							responseKeys.aeadNonce,
							counter++,
							pt,
							false,
						);
						frames.push(frameChunk(ct, false));
					}

					const finalCt = await sealResponseChunk(
						responseKeys.aead,
						responseKeys.aeadKey,
						responseKeys.aeadNonce,
						counter++,
						finalPlaintext,
						true,
					);
					frames.push(frameChunk(finalCt, true));

					const body = concat(...frames);
					const error = await expectOHTTPError(decryptResponseFrames([body]));
					expect(error.code).toBe(OHTTPErrorCode.DecryptionFailed);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});

// ============================================================================
// Property 5: counter discipline for response chunks
// ============================================================================

describe("response chunk counter discipline", () => {
	it("frame i needs counter i; a mismatched counter or the wrong AAD fails to open", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesOfLengthArb(5), { minLength: 1, maxLength: 5 }),
				fc.integer({ min: 0, max: 5 }),
				async (plaintexts, wrongOffset) => {
					const n = plaintexts.length;
					const ciphertexts: Uint8Array[] = [];
					for (let i = 0; i < n; i++) {
						const isFinal = i === n - 1;
						const pt = plaintexts[i] as Uint8Array;
						const ct = await sealResponseChunk(
							responseKeys.aead,
							responseKeys.aeadKey,
							responseKeys.aeadNonce,
							i,
							pt,
							isFinal,
						);
						ciphertexts.push(ct);
					}

					for (let i = 0; i < n; i++) {
						const isFinal = i === n - 1;
						const ct = ciphertexts[i] as Uint8Array;

						// Correct counter (and AAD) opens to the original plaintext.
						const opened = await openResponseChunk(
							responseKeys.aead,
							responseKeys.aeadKey,
							responseKeys.aeadNonce,
							i,
							ct,
							isFinal,
						);
						expect(opened).toEqual(plaintexts[i]);

						// A wrong counter fails, whatever the AAD.
						const wrongCounter = (i + 1 + (wrongOffset % Math.max(n, 1))) % (n + 3);
						if (wrongCounter !== i) {
							await expectOHTTPError(
								openResponseChunk(
									responseKeys.aead,
									responseKeys.aeadKey,
									responseKeys.aeadNonce,
									wrongCounter,
									ct,
									isFinal,
								),
							);
						}

						// The right counter but the wrong AAD (final vs non-final) fails too.
						await expectOHTTPError(
							openResponseChunk(
								responseKeys.aead,
								responseKeys.aeadKey,
								responseKeys.aeadNonce,
								i,
								ct,
								!isFinal,
							),
						);
					}
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("counters produced by the streaming transforms are 0,1,2,... with the final chunk one past the last non-final counter", async () => {
		await fc.assert(
			fc.asyncProperty(
				bytesArb({ maxLength: 256 }),
				fc.integer({ min: 1, max: 24 }),
				async (plaintext, maxChunkSize) => {
					const cipherBody = await collectStream(
						streamOfBytes(plaintext)
							.pipeThrough(createChunkerTransform(maxChunkSize))
							.pipeThrough(
								createResponseEncryptTransform(
									responseKeys.aead,
									responseKeys.aeadKey,
									responseKeys.aeadNonce,
								),
							),
					);

					// Walk the wire frames ourselves and open each with its expected
					// counter, confirming the transform assigned 0,1,2,... in order.
					let offset = 0;
					let counter = 0;
					for (;;) {
						const firstByte = cipherBody[offset] as number;
						const vlen = 1 << (firstByte >> 6);
						const header = cipherBody.subarray(offset, offset + vlen);
						const isFinalMarker = vlen === 1 && (header[0] as number) === 0;

						if (isFinalMarker) {
							const finalCt = cipherBody.subarray(offset + vlen);
							await expect(
								openResponseChunk(
									responseKeys.aead,
									responseKeys.aeadKey,
									responseKeys.aeadNonce,
									counter,
									finalCt,
									true,
								),
							).resolves.toBeInstanceOf(Uint8Array);
							break;
						}

						// Non-final frame: decode its declared length the same way the
						// transform does, to find the next frame boundary.
						let length = 0;
						for (let i = 0; i < vlen; i++) {
							const b = header[i] as number;
							length = i === 0 ? b & 0x3f : length * 256 + b;
						}
						const ct = cipherBody.subarray(offset + vlen, offset + vlen + length);
						await expect(
							openResponseChunk(
								responseKeys.aead,
								responseKeys.aeadKey,
								responseKeys.aeadNonce,
								counter,
								ct,
								false,
							),
						).resolves.toBeInstanceOf(Uint8Array);
						offset += vlen + length;
						counter++;
					}
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});

describe("computeChunkNonce", () => {
	it("XORing the same counter back into a computed nonce recovers the base nonce", () => {
		fc.assert(
			fc.property(
				bytesOfLengthArb(12),
				fc.integer({ min: 0, max: 0xffffffff }),
				(base, counter) => {
					const nonce = computeChunkNonce(base, counter);
					expect(computeChunkNonce(nonce, counter)).toEqual(base);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});

// ============================================================================
// Property 6: reordering/duplication/dropping whole frames must fail
// ============================================================================

describe("frame reordering, duplication, and dropping", () => {
	it("any non-identity permutation of the non-final frames fails to decrypt", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesOfLengthArb(4), { minLength: 2, maxLength: 4 }),
				bytesOfLengthArb(4),
				fc.integer({ min: 0, max: 0xffffffff }),
				async (plaintexts, finalPlaintext, seed) => {
					const clientCtx = await client.createRequestContext();
					const frames: Uint8Array[] = [];
					for (const pt of plaintexts) {
						frames.push(frameChunk(await clientCtx.sealChunk(pt), false));
					}
					const finalFrame = frameChunk(await clientCtx.sealFinalChunk(finalPlaintext), true);

					const order = permute(frames.length, seed);
					if (order.every((v, i) => v === i)) return; // skip the rare identity draw

					const permuted = order.map((idx) => frames[idx] as Uint8Array);
					const body = concat(...permuted, finalFrame);

					const { serverCtx } = await freshRequestPair2(clientCtx);
					await expectOHTTPError(decryptRequestFrames(serverCtx._recipientContext, [body]));
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("duplicating one non-final frame fails to decrypt", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesOfLengthArb(4), { minLength: 1, maxLength: 4 }),
				bytesOfLengthArb(4),
				fc.integer({ min: 0, max: 0xffffffff }),
				async (plaintexts, finalPlaintext, seed) => {
					const { clientCtx } = await freshRequestPair();
					const frames: Uint8Array[] = [];
					for (const pt of plaintexts) {
						frames.push(frameChunk(await clientCtx.sealChunk(pt), false));
					}
					const finalFrame = frameChunk(await clientCtx.sealFinalChunk(finalPlaintext), true);

					const dupIndex = seed % frames.length;
					const withDup = [
						...frames.slice(0, dupIndex + 1),
						frames[dupIndex],
						...frames.slice(dupIndex + 1),
					];
					const body = concat(...withDup, finalFrame);

					const { serverCtx } = await freshRequestPair2(clientCtx);
					await expectOHTTPError(decryptRequestFrames(serverCtx._recipientContext, [body]));
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("dropping one non-final frame fails to decrypt", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(bytesOfLengthArb(4), { minLength: 2, maxLength: 4 }),
				bytesOfLengthArb(4),
				fc.integer({ min: 0, max: 0xffffffff }),
				async (plaintexts, finalPlaintext, seed) => {
					const { clientCtx } = await freshRequestPair();
					const frames: Uint8Array[] = [];
					for (const pt of plaintexts) {
						frames.push(frameChunk(await clientCtx.sealChunk(pt), false));
					}
					const finalFrame = frameChunk(await clientCtx.sealFinalChunk(finalPlaintext), true);

					const dropIndex = seed % frames.length;
					const withoutOne = frames.filter((_, i) => i !== dropIndex);
					const body = concat(...withoutOne, finalFrame);

					const { serverCtx } = await freshRequestPair2(clientCtx);
					await expectOHTTPError(decryptRequestFrames(serverCtx._recipientContext, [body]));
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});

/** Deterministic Fisher-Yates permutation of [0, n) seeded by `seed`, so the
 * permutation choice is reproducible from an integer fast-check can shrink. */
function permute(n: number, seed: number): number[] {
	const arr = Array.from({ length: n }, (_, i) => i);
	let state = seed >>> 0 || 1;
	const nextRand = (): number => {
		state ^= state << 13;
		state ^= state >>> 17;
		state ^= state << 5;
		state >>>= 0;
		return state;
	};
	for (let i = arr.length - 1; i > 0; i--) {
		const j = nextRand() % (i + 1);
		const tmp = arr[i] as number;
		arr[i] = arr[j] as number;
		arr[j] = tmp;
	}
	return arr;
}

// ============================================================================
// Property 7: maxFrameSize enforcement
// ============================================================================

describe("maxFrameSize enforcement", () => {
	const maxFrameSize = 64;

	it("a declared non-final length above maxFrameSize is rejected before that many bytes arrive", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.integer({ min: maxFrameSize + 1, max: maxFrameSize + 10_000 }),
				async (declaredLength) => {
					// Only the length prefix is sent - never the (nonexistent) payload -
					// proving the check runs before the frame is buffered.
					const header = encodeVarint(declaredLength);
					const error = await expectOHTTPError(decryptResponseFrames([header], maxFrameSize));
					expect(error.code).toBe(OHTTPErrorCode.ChunkLimitExceeded);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("a final chunk whose accumulated length exceeds maxFrameSize is rejected", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.integer({ min: maxFrameSize + 1, max: maxFrameSize + 500 }),
				async (overflowLength) => {
					const marker = encodeVarint(0);
					const body = concat(marker, new Uint8Array(overflowLength));
					const error = await expectOHTTPError(decryptResponseFrames([body], maxFrameSize));
					expect(error.code).toBe(OHTTPErrorCode.ChunkLimitExceeded);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});

	it("a declared non-final length exactly at maxFrameSize is not itself rejected", async () => {
		// The boundary case: `length > maxFrameSize` must be strict, so a frame
		// exactly at the limit should wait for its payload rather than reject
		// immediately (whatever happens once the payload arrives is a separate
		// concern - it's real ciphertext or bust, tested elsewhere).
		const header = encodeVarint(maxFrameSize);
		const errorOrUndefined = await Promise.race([
			decryptResponseFrames([header], maxFrameSize).then(
				() => undefined,
				(e: unknown) => e,
			),
			new Promise((resolve) => setTimeout(() => resolve(undefined), 50)),
		]);
		if (errorOrUndefined instanceof OHTTPError) {
			expect(errorOrUndefined.code).not.toBe(OHTTPErrorCode.ChunkLimitExceeded);
		}
	});
});

// ============================================================================
// Property 8: full chunked round-trip through ChunkedOHTTPClient/Server
// ============================================================================

describe("ChunkedOHTTPClient/ChunkedOHTTPServer round-trip", () => {
	it("request and response payloads survive encapsulation for arbitrary maxChunkSize, including empty payloads", async () => {
		await fc.assert(
			fc.asyncProperty(
				bytesArb({ maxLength: 1024 }),
				bytesArb({ maxLength: 1024 }),
				fc.integer({ min: 1, max: 96 }),
				async (requestPayload, responsePayload, maxChunkSize) => {
					const runClient = new ChunkedOHTTPClient(suite, publicKeyConfig, { maxChunkSize });
					const runServer = new ChunkedOHTTPServer([serverKeyConfig], { maxChunkSize });

					const { encapsulatedRequest, createResponseContext } =
						await runClient.encapsulate(requestPayload);
					const { request, createResponseContext: serverCreateResponse } =
						await runServer.decapsulate(encapsulatedRequest);
					expect(request).toEqual(requestPayload);

					const responseCtx = await serverCreateResponse();
					const encapsulatedResponse = await runServer.encapsulateResponse(
						responseCtx,
						responsePayload,
					);
					const decryptedResponse = await runClient.decapsulateResponse(
						createResponseContext,
						encapsulatedResponse,
					);
					expect(decryptedResponse).toEqual(responsePayload);
				},
			),
			{ numRuns: CRYPTO_RUNS },
		);
	});
});
