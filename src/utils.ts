import { DEFAULT_MAX_CHUNK_SIZE, DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE } from "./constants.ts";
import { OHTTPError, OHTTPErrorCode } from "./errors.ts";

/**
 * Concatenate multiple Uint8Arrays into one
 */
export function concat(arrays: readonly Uint8Array[]): Uint8Array<ArrayBuffer>;
export function concat(...arrays: Uint8Array[]): Uint8Array<ArrayBuffer>;
export function concat(...input: Uint8Array[] | [readonly Uint8Array[]]): Uint8Array<ArrayBuffer> {
	const arrays = input.length === 1 && Array.isArray(input[0]) ? input[0] : input;
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
export function resolveMaxMessageSize(
	maxMessageSize = DEFAULT_MAX_CHUNKED_OHTTP_MESSAGE_SIZE,
): number {
	if (!Number.isSafeInteger(maxMessageSize) || maxMessageSize < 0) {
		throw new RangeError(`maxMessageSize must be a non-negative integer, got ${maxMessageSize}`);
	}
	return maxMessageSize;
}

/** Collect a body up to a byte limit, cancelling its stream on overflow. */
export async function collectLimitedBody(
	message: {
		readonly body?: ReadableStream<Uint8Array> | null;
		arrayBuffer(): Promise<ArrayBuffer>;
	},
	maxSize: number,
): Promise<Uint8Array<ArrayBuffer>> {
	const body = message.body;
	if (body == null) {
		// Firefox can provide arrayBuffer() without exposing the body stream.
		const bytes = new Uint8Array(await message.arrayBuffer());
		assertMessageSize(bytes, maxSize);
		return bytes;
	}
	const parts: Uint8Array[] = [];
	let bytes = 0;
	const reader = body.getReader();
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) return concat(parts);
			const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
			bytes += chunk.byteLength;
			if (bytes > maxSize) {
				const error = new OHTTPError(OHTTPErrorCode.MessageTooLarge);
				try {
					await reader.cancel(error);
				} catch {}
				throw error;
			}
			parts.push(chunk);
		}
	} finally {
		reader.releaseLock();
	}
}

export function assertMessageSize(bytes: Uint8Array, maxMessageSize: number): void {
	if (bytes.byteLength > maxMessageSize) {
		throw new OHTTPError(OHTTPErrorCode.MessageTooLarge);
	}
}

/** Account for one direction of one chunked message. */
export function createChunkBudget(maxMessageSize: number) {
	let chunks = 0;
	let bytes = 0;
	return (size: number, final: boolean): void => {
		if (chunks >= 2 ** 32 || size > DEFAULT_MAX_CHUNK_SIZE || (!final && size === 0)) {
			throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
		}
		if (bytes + size > maxMessageSize) {
			throw new OHTTPError(OHTTPErrorCode.MessageTooLarge);
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
