import { fc, it } from "@fast-check/vitest";
import { encode as encodeVarint } from "quicvarint";
import { describe, expect } from "vitest";
import { DEFAULT_MAX_FRAME_SIZE, frameChunk, parseFramedChunk } from "../src/encapsulation.js";
import { OHTTPError, OHTTPErrorCode } from "../src/errors.js";
import { concat } from "../src/utils.js";
import { bytesArb, bytesOfLengthArb } from "./props-helpers.js";

/**
 * Non-final chunk ciphertexts of at least 1 byte: a zero-length ciphertext
 * frames to the same bytes as the final-chunk marker (length 0 always means
 * final), so it is excluded here to keep frameChunk(ct, false) round-trippable.
 * Mixes general small lengths with the exact 1/2/4-byte varint boundary
 * crossings (63/64, 16383/16384).
 */
const nonFinalCiphertextArb: fc.Arbitrary<Uint8Array> = fc.oneof(
	bytesArb({ minLength: 1, maxLength: 300 }),
	fc.constantFrom(62, 63, 64, 65, 16382, 16383, 16384, 16385).chain((n) => bytesOfLengthArb(n)),
);

/**
 * Varint-representable values chosen to hit each of the four wire-size classes
 * (1/2/4/8 bytes) with roughly equal weight, rather than leaving it to chance.
 */
const varintValueArb: fc.Arbitrary<number> = fc.oneof(
	fc.integer({ min: 0, max: 63 }),
	fc.integer({ min: 64, max: 16383 }),
	fc.integer({ min: 16384, max: 1073741823 }),
	fc.integer({ min: 1073741824, max: 2147483647 }),
);

/** A framed non-final chunk together with a cut point somewhere inside it. */
const truncatedFrameArb = nonFinalCiphertextArb.chain((ct) => {
	const framed = frameChunk(ct, false);
	return fc.record({
		ct: fc.constant(ct),
		framed: fc.constant(framed),
		varintLength: fc.constant(encodeVarint(ct.length).length),
		prefixLength: fc.integer({ min: 0, max: framed.length }),
	});
});

/** A payload whose declared length sits within its own maxFrameSize. */
const withinLimitArb = fc
	.integer({ min: 1, max: 2000 })
	.chain((maxFrameSize) =>
		fc
			.integer({ min: 1, max: maxFrameSize })
			.chain((declared) =>
				bytesOfLengthArb(declared).map((payload) => ({ maxFrameSize, declared, payload })),
			),
	);

describe("frameChunk / parseFramedChunk round-trip", () => {
	it.prop([nonFinalCiphertextArb])(
		"round-trips a non-final frame for arbitrary ciphertext, including varint boundary lengths",
		(ct) => {
			const framed = frameChunk(ct, false);
			const parsed = parseFramedChunk(framed);
			expect(parsed).toBeDefined();
			if (parsed === undefined) return;
			expect(parsed.isFinal).toBe(false);
			expect(parsed.ciphertext).toEqual(ct);
			expect(parsed.ciphertext.buffer).toBe(framed.buffer);
			expect(parsed.bytesConsumed).toBe(encodeVarint(ct.length).length + ct.length);
			expect(parsed.bytesConsumed).toBe(framed.length);
		},
	);

	it.prop([bytesArb({ maxLength: 500 })])(
		"round-trips a final frame for arbitrary ciphertext",
		(ct) => {
			const framed = frameChunk(ct, true);
			const parsed = parseFramedChunk(framed);
			expect(parsed).toBeDefined();
			if (parsed === undefined) return;
			expect(parsed.isFinal).toBe(true);
			expect(parsed.ciphertext).toEqual(ct);
			expect(parsed.ciphertext.buffer).toBe(framed.buffer);
			expect(parsed.bytesConsumed).toBe(framed.length);
		},
	);

	it.prop([
		fc.array(bytesArb({ minLength: 1, maxLength: 50 }), { maxLength: 6 }),
		bytesArb({ maxLength: 50 }),
	])(
		"sequentially parses a stream of framed non-final chunks followed by a final chunk",
		(chunks, finalChunk) => {
			const framedChunks = chunks.map((c) => frameChunk(c, false));
			const stream = concat(...framedChunks, frameChunk(finalChunk, true));

			const recovered: Uint8Array[] = [];
			let offset = 0;
			let isFinal = false;
			while (!isFinal) {
				const parsed = parseFramedChunk(stream.subarray(offset));
				expect(parsed).toBeDefined();
				if (parsed === undefined) return;
				recovered.push(parsed.ciphertext);
				offset += parsed.bytesConsumed;
				isFinal = parsed.isFinal;
			}

			expect(offset).toBe(stream.length);
			expect(recovered.length).toBe(chunks.length + 1);
			for (let i = 0; i < chunks.length; i++) {
				expect(recovered[i]).toEqual(chunks[i]);
			}
			expect(recovered[chunks.length]).toEqual(finalChunk);
		},
	);
});

describe("parseFramedChunk truncation safety", () => {
	it.prop([truncatedFrameArb])(
		"on any prefix of a framed non-final chunk, either returns undefined or throws — never a wrong ParsedChunk",
		({ ct, framed, varintLength, prefixLength }) => {
			const prefix = framed.subarray(0, prefixLength);
			const totalLength = varintLength + ct.length;

			if (prefixLength === 0) {
				expect(parseFramedChunk(prefix)).toBeUndefined();
				return;
			}
			if (prefixLength < varintLength) {
				// Fewer bytes than the first byte's prefix demands: the varint
				// decode itself fails, which parseFramedChunk turns into InvalidMessage.
				expect(catchOHTTPError(() => parseFramedChunk(prefix)).code).toBe(
					OHTTPErrorCode.InvalidMessage,
				);
				return;
			}
			if (prefixLength < totalLength) {
				// Varint complete, ciphertext still short: not enough data yet.
				expect(parseFramedChunk(prefix)).toBeUndefined();
				return;
			}

			// prefixLength === totalLength === framed.length: the full frame.
			const parsed = parseFramedChunk(prefix);
			expect(parsed).toBeDefined();
			if (parsed === undefined) return;
			expect(parsed.isFinal).toBe(false);
			expect(parsed.ciphertext).toEqual(ct);
			expect(parsed.bytesConsumed).toBe(totalLength);
		},
	);
});

describe("parseFramedChunk maxFrameSize enforcement", () => {
	it.prop([
		varintValueArb.filter((v) => v > DEFAULT_MAX_FRAME_SIZE),
		fc.integer({ min: 0, max: 20 }),
	])(
		"throws ChunkLimitExceeded for a declared length over the default max, regardless of bytes present",
		(declared, trailingCount) => {
			const frame = concat(encodeVarint(declared), new Uint8Array(trailingCount));
			expect(catchOHTTPError(() => parseFramedChunk(frame)).code).toBe(
				OHTTPErrorCode.ChunkLimitExceeded,
			);
		},
	);

	it.prop([
		fc.integer({ min: 1, max: 5000 }),
		fc.integer({ min: 1, max: 2000000000 }),
		fc.integer({ min: 0, max: 20 }),
	])(
		"throws ChunkLimitExceeded for a declared length over a custom maxFrameSize, regardless of bytes present",
		(maxFrameSize, overshoot, trailingCount) => {
			const declared = maxFrameSize + overshoot;
			const frame = concat(encodeVarint(declared), new Uint8Array(trailingCount));
			expect(catchOHTTPError(() => parseFramedChunk(frame, maxFrameSize)).code).toBe(
				OHTTPErrorCode.ChunkLimitExceeded,
			);
		},
	);

	it.prop([withinLimitArb])(
		"parses when a declared length is within maxFrameSize and enough bytes are present",
		({ maxFrameSize, payload }) => {
			const frame = concat(encodeVarint(payload.length), payload);
			const parsed = parseFramedChunk(frame, maxFrameSize);
			expect(parsed).toBeDefined();
			if (parsed === undefined) return;
			expect(parsed.isFinal).toBe(false);
			expect(parsed.ciphertext).toEqual(payload);
			expect(parsed.bytesConsumed).toBe(frame.length);
		},
	);
});

// Helpers

/** Run `fn`, returning the OHTTPError it threw. Fails the test if it throws anything else, or nothing. */
function catchOHTTPError(fn: () => unknown): OHTTPError {
	try {
		fn();
	} catch (err) {
		if (err instanceof OHTTPError) {
			return err;
		}
		throw err;
	}
	throw new Error("expected an OHTTPError to be thrown");
}
