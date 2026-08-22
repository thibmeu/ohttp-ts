import { DEFAULT_MAX_CHUNK_SIZE, DEFAULT_MAX_MESSAGE_SIZE } from "./constants.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";

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

/** Resolve the per-message plaintext limit shared by chunked endpoints. */
export function resolveMaxMessageSize(maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE): number {
	if (!Number.isSafeInteger(maxMessageSize) || maxMessageSize < 0) {
		throw new RangeError(`maxMessageSize must be a non-negative integer, got ${maxMessageSize}`);
	}
	return maxMessageSize;
}

/** Account for one direction of one chunked message. */
export function createChunkBudget(maxMessageSize: number) {
	let chunks = 0;
	let bytes = 0;
	return (size: number, final: boolean): void => {
		if (
			chunks >= 2 ** 32 ||
			size > DEFAULT_MAX_CHUNK_SIZE ||
			(!final && size === 0) ||
			bytes + size > maxMessageSize
		) {
			throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
		}
		chunks++;
		bytes += size;
	};
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
