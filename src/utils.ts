import { AEAD_TAG_SIZE, DEFAULT_MAX_CHUNK_SIZE, DEFAULT_MAX_FRAME_SIZE } from "./constants.js";

/**
 * Concatenate multiple Uint8Arrays into one
 */
export function concat(...arrays: Uint8Array[]): Uint8Array<ArrayBuffer> {
	const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const arr of arrays) {
		result.set(arr, offset);
		offset += arr.length;
	}
	return result;
}

/**
 * Resolve the chunk/frame size options shared by the chunked client and server.
 *
 * A `maxChunkSize` of 0 spins `createChunkerTransform` forever and a
 * non-integer silently disables chunking, so both are rejected here. Sizes
 * above the 16384 default are allowed: draft-08 Section 3 makes that a SHOULD
 * for senders "aware of support for larger sizes by the receiving party".
 *
 * The two are independent directions: `maxChunkSize` bounds what this side
 * sends, `maxFrameSize` what it accepts. Defaulting `maxFrameSize` raises it to
 * cover `maxChunkSize`, but passing both is free to set an asymmetric receive
 * bound, so only the one-AEAD-tag floor is enforced.
 */
export function resolveChunkSizes(options: {
	readonly maxChunkSize?: number;
	readonly maxFrameSize?: number;
}): { maxChunkSize: number; maxFrameSize: number } {
	const maxChunkSize = options.maxChunkSize ?? DEFAULT_MAX_CHUNK_SIZE;
	if (!Number.isSafeInteger(maxChunkSize) || maxChunkSize < 1) {
		throw new RangeError(`maxChunkSize must be a positive integer, got ${maxChunkSize}`);
	}

	const maxFrameSize =
		options.maxFrameSize ?? Math.max(DEFAULT_MAX_FRAME_SIZE, maxChunkSize + AEAD_TAG_SIZE);
	if (!Number.isSafeInteger(maxFrameSize) || maxFrameSize < AEAD_TAG_SIZE) {
		throw new RangeError(
			`maxFrameSize must be an integer of at least ${AEAD_TAG_SIZE} (one AEAD tag), got ${maxFrameSize}`,
		);
	}

	return { maxChunkSize, maxFrameSize };
}

/**
 * Narrow bytes produced by hpke to the `ArrayBuffer` backing they already have.
 *
 * hpke returns a bare `Uint8Array`, i.e. `Uint8Array<ArrayBufferLike>`, which
 * `BodyInit` rejects. These are always freshly allocated, never on a
 * `SharedArrayBuffer`, so the narrowing is free and needs no copy.
 */
export function asOwnedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
	return bytes as Uint8Array<ArrayBuffer>;
}
