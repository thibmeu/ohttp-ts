/**
 * Shared arbitraries for the property tests - not exported from the package.
 *
 * `fc.uint8Array` draws byte values from a distribution biased toward small
 * integers, so on its own it rarely reaches the wire shapes that matter here
 * (0xff runs, high varint prefixes, full-range key material). The arbitraries
 * below mix that generator with uniformly random and patterned bytes so a
 * property sees both shrink-friendly and adversarial inputs.
 */

import fc from "fast-check";

/** Uniform bytes from a 32-bit seed (xorshift32), so every byte value is reachable. */
function seededBytes(length: number, seed: number): Uint8Array {
	const out = new Uint8Array(length);
	let state = seed | 0 || 0x9e3779b9;
	for (let i = 0; i < length; i++) {
		state ^= state << 13;
		state ^= state >>> 17;
		state ^= state << 5;
		out[i] = (state >>> 24) & 0xff;
	}
	return out;
}

export interface BytesConstraints {
	readonly minLength?: number;
	readonly maxLength?: number;
}

/**
 * Byte arrays mixing three shapes: fast-check's own (small values, shrinks
 * well), uniformly random bytes, and single-value fills at byte boundaries.
 */
export function bytesArb(constraints: BytesConstraints = {}): fc.Arbitrary<Uint8Array> {
	const minLength = constraints.minLength ?? 0;
	const maxLength = constraints.maxLength ?? 64;
	const lengthArb = fc.integer({ min: minLength, max: maxLength });
	return fc.oneof(
		fc.uint8Array({ minLength, maxLength }),
		fc
			.tuple(lengthArb, fc.integer({ min: 0, max: 0xffffffff }))
			.map(([n, seed]) => seededBytes(n, seed)),
		fc
			.tuple(lengthArb, fc.constantFrom(0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xfe, 0xff))
			.map(([n, b]) => new Uint8Array(n).fill(b)),
	);
}

/** Bytes of exactly `length`, drawn from the same mix as {@link bytesArb}. */
export function bytesOfLengthArb(length: number): fc.Arbitrary<Uint8Array> {
	return bytesArb({ minLength: length, maxLength: length });
}

/**
 * Split points for cutting `total` bytes into consecutive pieces: a sorted list
 * of offsets in (0, total), used to exercise arbitrary stream chunk boundaries.
 */
export function splitPointsArb(total: number, maxSplits = 8): fc.Arbitrary<number[]> {
	if (total <= 1) return fc.constant([]);
	return fc
		.array(fc.integer({ min: 1, max: total - 1 }), { maxLength: maxSplits })
		.map((points) => [...new Set(points)].sort((a, b) => a - b));
}

/** Cut `data` at `points` into consecutive pieces covering all of it. */
export function splitAt(data: Uint8Array, points: readonly number[]): Uint8Array[] {
	const pieces: Uint8Array[] = [];
	let prev = 0;
	for (const p of points) {
		pieces.push(data.subarray(prev, p));
		prev = p;
	}
	pieces.push(data.subarray(prev));
	return pieces;
}

/**
 * Run count for properties that perform HPKE or AEAD operations. Each run costs
 * a key schedule or a seal/open, so these run far fewer times than the default.
 */
export const CRYPTO_RUNS = 20;
