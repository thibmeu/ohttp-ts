/**
 * Concurrency and interleaving properties for the chunked path.
 *
 * The other `props-*` files are input-output: they feed bytes in and check bytes
 * out, letting the AEAD calls settle in whatever order the runtime picks - which,
 * with real WebCrypto, is issue order essentially always. These properties fix
 * the inputs and vary the *scheduling* instead, because the pipelined transforms
 * keep a window of {@link AEAD_PIPELINE_DEPTH} AEAD calls in flight and drain it
 * through a FIFO, and nothing else in the suite makes that FIFO do any work.
 *
 * Cloudflare's Tamarin analysis of OHTTP (https://github.com/cloudflare/ohttp-analysis)
 * proves protocol-level properties - secrecy, unlinkability, gateway authentication -
 * on top of assumptions the *implementation* has to keep, chief among them that an
 * (AEAD key, nonce) pair is never reused. A symbolic proof cannot check that for us.
 * These are the implementation-side obligations behind it.
 */

import { fc, it } from "@fast-check/vitest";
import {
	AEAD_AES_128_GCM,
	type AEAD as AeadImpl,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { describe, expect } from "vitest";
import { ChunkedOHTTPClient } from "../src/client.js";
import { kAeadKey, kAeadNonce } from "../src/constants.js";
import {
	computeChunkNonce,
	frameChunk,
	openResponseChunk,
	type ParsedChunk,
	parseFramedChunk,
	sealResponseChunk,
} from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import { AeadId, generateKeyConfig, KdfId } from "../src/keyConfig.js";
import { ChunkedOHTTPServer } from "../src/server.js";
import {
	collectStream,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
	streamOfBytes,
} from "../src/streaming.js";
import { concat } from "../src/utils.js";
import { bytesArb } from "./props-helpers.js";

// ============================================================================
// Fixtures
// ============================================================================

const realAead = AEAD_AES_128_GCM();
const aeadKey = new Uint8Array(realAead.Nk).fill(0xa5);
const baseNonce = new Uint8Array(realAead.Nn).fill(0x3c);

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

/** A matched server-side (sealing) and client-side (opening) response context. */
async function responseContexts() {
	const { encapsulatedRequest, createResponseContext } = await client.encapsulate(
		new TextEncoder().encode("request"),
	);
	const serverRequestCtx = await server.createRequestContext(encapsulatedRequest.subarray(0, 39));
	const sealer = await serverRequestCtx.createResponseContext();
	const opener = await createResponseContext(sealer.responseNonce);
	return { sealer, opener };
}

/**
 * Plaintext chunks, each non-empty (a zero-length non-final chunk is itself an
 * error). `minChunks` is 2 where a property needs a frame to follow the one it
 * targets, so the case is generated rather than filtered for.
 */
const chunksArb = (minChunks = 1) =>
	fc.array(bytesArb({ minLength: 1, maxLength: 48 }), { minLength: minChunks, maxLength: 8 });

/** The framed body a well-behaved sealer would produce for `chunks`. */
async function sealFrames(chunks: readonly Uint8Array[]): Promise<Uint8Array[]> {
	const frames: Uint8Array[] = [];
	for (let i = 0; i < chunks.length; i++) {
		const isFinal = i === chunks.length - 1;
		const ct = await sealResponseChunk(
			realAead,
			aeadKey,
			baseNonce,
			i,
			chunks[i] as Uint8Array,
			isFinal,
		);
		frames.push(frameChunk(ct, isFinal));
	}
	return frames;
}

/**
 * An AEAD whose calls resolve when the scheduler says so, rather than when the
 * underlying crypto finishes. `onCall` can substitute a rejection for one call,
 * which is how a mid-window failure gets placed at a chosen index.
 */
function scheduledAead(s: fc.Scheduler, onCall?: (index: number) => Error | undefined): AeadImpl {
	let index = 0;
	const wrap =
		(real: (k: Uint8Array, n: Uint8Array, a: Uint8Array, d: Uint8Array) => Promise<Uint8Array>) =>
		(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, data: Uint8Array) => {
			const failure = onCall?.(index++);
			// The transforms hand the AEAD zero-copy views (`StreamBuffer.peek` returns a
			// subarray; the chunker emits views of its input) and await them much later.
			// Snapshotting at call time and comparing at release time catches a backing
			// buffer that got reused underneath a pipelined call - the obvious next
			// StreamBuffer optimisation, which real WebCrypto would hide because it
			// copies its input at dispatch. On the Open path this surfaces as a plain
			// decryption failure rather than this message, because `openResponseChunk`
			// catches everything `aead.Open` throws.
			const snapshot = Uint8Array.from(data);
			return s.schedule(Promise.resolve(null)).then(() => {
				expect(data, "buffer handed to the AEAD changed before the call ran").toEqual(snapshot);
				if (failure) throw failure;
				return real(key, nonce, aad, data);
			});
		};
	return {
		id: realAead.id,
		type: "AEAD",
		name: realAead.name,
		Nk: realAead.Nk,
		Nn: realAead.Nn,
		Nt: realAead.Nt,
		Seal: wrap(realAead.Seal.bind(realAead)),
		Open: wrap(realAead.Open.bind(realAead)),
	};
}

/** A stream emitting each element as its own chunk, as the chunker would. */
function chunkStream(chunks: readonly Uint8Array[]): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		start(controller) {
			for (const chunk of chunks) controller.enqueue(chunk);
			controller.close();
		},
	});
}

/** Split a framed body back into its frames. */
function parseFrames(body: Uint8Array): ParsedChunk[] {
	const frames: ParsedChunk[] = [];
	let offset = 0;
	while (offset < body.length) {
		const frame = parseFramedChunk(body.subarray(offset));
		if (frame === undefined) throw new Error("truncated frame");
		frames.push(frame);
		offset += frame.bytesConsumed;
	}
	return frames;
}

/** Drain a stream, returning what was emitted before it errored (if it did). */
async function readUntilError(
	stream: ReadableStream<Uint8Array>,
): Promise<{ chunks: Uint8Array[]; error: unknown }> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	for (;;) {
		try {
			const { done, value } = await reader.read();
			if (done) return { chunks, error: undefined };
			chunks.push(value);
		} catch (error) {
			return { chunks, error };
		}
	}
}

// ============================================================================
// 1. Nonce uniqueness under concurrent issue
//
// The obligation the Tamarin model rests on. Needs no scheduler: concurrency of
// *issue* is enough, because a counter claimed after its own `await` is already
// stale for the call that follows it.
// ============================================================================

describe("concurrent use of one response context", () => {
	it.prop([chunksArb()], { numRuns: 20 })(
		"seals issued together each get their own counter, so no nonce is reused",
		async (chunks) => {
			const { sealer } = await responseContexts();
			const ciphertexts = await Promise.all(chunks.map((c) => sealer.sealChunk(c)));

			// Chunk i must open at counter i and at no other counter in range.
			for (let i = 0; i < chunks.length; i++) {
				const opensAt: number[] = [];
				for (let counter = 0; counter < chunks.length; counter++) {
					try {
						const pt = await openResponseChunk(
							realAead,
							sealer[kAeadKey],
							sealer[kAeadNonce],
							counter,
							ciphertexts[i] as Uint8Array,
							false,
						);
						expect(pt).toEqual(chunks[i]);
						opensAt.push(counter);
					} catch {
						// wrong counter: expected
					}
				}
				expect(opensAt, `chunk ${i} should open at exactly counter ${i}`).toEqual([i]);
			}
		},
	);

	it.prop([chunksArb()], { numRuns: 20 })(
		"opens issued together consume distinct counters and all succeed",
		async (chunks) => {
			const { sealer, opener } = await responseContexts();
			const ciphertexts: Uint8Array[] = [];
			for (const chunk of chunks) ciphertexts.push(await sealer.sealChunk(chunk));

			const plaintexts = await Promise.all(ciphertexts.map((ct) => opener.openChunk(ct)));
			expect(plaintexts).toEqual(chunks);
		},
	);
});

// ============================================================================
// 2. Output is a function of the input, not of completion order
// ============================================================================

describe("AEAD completion order", () => {
	it.prop([fc.scheduler(), chunksArb()], { numRuns: 50 })(
		"encrypting emits frame i sealed at counter i, however the windowed seals complete",
		async (s, chunks) => {
			const aead = scheduledAead(s);
			const body = await s.waitFor(
				collectStream(
					chunkStream(chunks).pipeThrough(createResponseEncryptTransform(aead, aeadKey, baseNonce)),
				),
			);

			// Oracle is the input, not a second run of the same transform: frame i has
			// to open at counter i, which pins order independently of how it was drained.
			const frames = parseFrames(body);
			expect(frames.length).toBe(chunks.length);
			for (let i = 0; i < frames.length; i++) {
				const frame = frames[i] as ParsedChunk;
				expect(frame.isFinal).toBe(i === frames.length - 1);
				const pt = await openResponseChunk(
					realAead,
					aeadKey,
					baseNonce,
					i,
					frame.ciphertext,
					frame.isFinal,
				);
				expect(pt).toEqual(chunks[i]);
			}
		},
	);

	it.prop([fc.scheduler(), chunksArb()], { numRuns: 50 })(
		"decrypting emits the same plaintext, in order, however the windowed opens complete",
		async (s, chunks) => {
			const body = concat(...(await sealFrames(chunks)));

			const aead = scheduledAead(s);
			const out = await s.waitFor(
				collectStream(
					streamOfBytes(body).pipeThrough(createResponseDecryptTransform(aead, aeadKey, baseNonce)),
				),
			);

			expect(out).toEqual(concat(...chunks));
		},
	);
});

// ============================================================================
// 3. A mid-window failure has a fixed outcome
// ============================================================================

describe("failure inside the in-flight window", () => {
	it.prop([fc.scheduler(), chunksArb(2), fc.nat()], { numRuns: 50 })(
		"the first failing frame fixes both the error code and the plaintext emitted before it",
		async (s, chunks, k) => {
			// At least one frame follows the failing one, so the failure lands inside a
			// window rather than at end-of-stream.
			const failAt = k % (chunks.length - 1);

			const body = concat(...(await sealFrames(chunks)));
			const aead = scheduledAead(s, (i) =>
				i === failAt ? new OHTTPError(OHTTPErrorCode.DecryptionFailed) : undefined,
			);

			const { chunks: emitted, error } = await s.waitFor(
				readUntilError(
					streamOfBytes(body).pipeThrough(createResponseDecryptTransform(aead, aeadKey, baseNonce)),
				),
			);

			expect(error).toBeInstanceOf(OHTTPError);
			expect((error as OHTTPError).code).toBe(OHTTPErrorCode.DecryptionFailed);
			// Everything ahead of the failure is emitted; nothing behind it is.
			expect(emitted.length).toBe(failAt);
			expect(concat(...emitted)).toEqual(concat(...chunks.slice(0, failAt)));
		},
	);
});

// ============================================================================
// 4. Abandoning the window is quiet
//
// `settle()` exists so that seals/opens still in flight when the stream is torn
// down have their rejections captured at issue time. Nothing else asserts it.
// ============================================================================

describe("abandoned in-flight window", () => {
	it.prop([fc.scheduler(), chunksArb(2), fc.nat()], { numRuns: 30 })(
		"tearing the stream down mid-window surfaces no unhandled rejection",
		async (s, chunks, k) => {
			const failAt = k % (chunks.length - 1);

			const unhandled: unknown[] = [];
			const onUnhandled = (reason: unknown) => unhandled.push(reason);
			// Only Node exposes this hook; under the browser and workers configs the
			// property still drives the teardown, it just cannot observe the result.
			const observable = typeof process !== "undefined" && typeof process.on === "function";
			if (observable) process.on("unhandledRejection", onUnhandled);
			try {
				const body = concat(...(await sealFrames(chunks)));
				// Every call after the first failure also rejects: those are the ones
				// left in the abandoned window.
				const aead = scheduledAead(s, (i) =>
					i >= failAt ? new OHTTPError(OHTTPErrorCode.DecryptionFailed) : undefined,
				);

				await s.waitFor(
					readUntilError(
						streamOfBytes(body).pipeThrough(
							createResponseDecryptTransform(aead, aeadKey, baseNonce),
						),
					),
				);
				// Node reports unhandled rejections on a later macrotask.
				await new Promise((resolve) => setTimeout(resolve, 0));
				if (observable) expect(unhandled).toEqual([]);
			} finally {
				if (observable) process.off("unhandledRejection", onUnhandled);
			}
		},
	);
});

// ============================================================================
// 5. Counter-derived nonces stay distinct across the whole window
//
// The transforms claim counters synchronously; this pins the consequence that
// matters rather than the mechanism.
// ============================================================================

describe("nonces emitted by the response transforms", () => {
	it.prop([fc.scheduler(), chunksArb()], { numRuns: 30 })(
		"every seal in a stream uses a distinct nonce, whatever the completion order",
		async (s, chunks) => {
			const nonces: string[] = [];
			const aead = scheduledAead(s);
			const recording: AeadImpl = {
				...aead,
				Seal: (key, nonce, aad, pt) => {
					nonces.push(nonce.join(","));
					return aead.Seal(key, nonce, aad, pt);
				},
			};

			await s.waitFor(
				collectStream(
					chunkStream(chunks).pipeThrough(
						createResponseEncryptTransform(recording, aeadKey, baseNonce),
					),
				),
			);

			expect(new Set(nonces).size, "a nonce was reused").toBe(nonces.length);
			// and they are the counter-derived ones, in order
			expect(nonces).toEqual(chunks.map((_, i) => computeChunkNonce(baseNonce, i).join(",")));
		},
	);
});
