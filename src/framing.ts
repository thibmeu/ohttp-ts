import { decode as decodeVarint, encode as encodeVarint } from "quicvarint";
import { DEFAULT_MAX_FRAME_SIZE } from "./constants.ts";
import { OHTTPError, OHTTPErrorCode } from "./errors.ts";
import { concat } from "./utils.ts";

/**
 * Frame a chunk with varint length prefix
 *
 * Non-final chunks: length (varint) + ciphertext
 * Final chunk: 0 (varint) + ciphertext
 *
 * Throws ChunkLimitExceeded for an empty non-final chunk: its zero length
 * would mark it final.
 */
export function frameChunk(ciphertext: Uint8Array, isFinal: boolean): Uint8Array<ArrayBuffer> {
	if (!isFinal && ciphertext.length === 0) {
		throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
	}
	const length = isFinal ? 0 : ciphertext.length;
	const lengthBytes = encodeVarint(length);
	return concat(lengthBytes, ciphertext);
}

/**
 * Result of parsing a framed chunk
 */
export interface ParsedChunk<T extends ArrayBufferLike = ArrayBuffer> {
	readonly ciphertext: Uint8Array<T>;
	readonly isFinal: boolean;
	readonly bytesConsumed: number;
}

/**
 * Parse a framed chunk, returning the ciphertext and whether it's final
 *
 * Returns undefined if not enough data available, including a length prefix
 * split across reads. A final chunk extends to end of stream, so it is only
 * returned once `endOfStream` says `data` holds the rest of the body.
 * Throws OHTTPError if the varint encoding is malformed, if a frame exceeds
 * the 16 KiB-plus-tag cap every chunk context enforces, or (InvalidMessage) if
 * `endOfStream` is set and `data` ends mid-frame.
 *
 * `ciphertext` views `data`; do not mutate `data` while holding it.
 */
export function parseFramedChunk<T extends ArrayBufferLike>(
	data: Uint8Array<T>,
	{ endOfStream = false }: { endOfStream?: boolean } = {},
): ParsedChunk<T> | undefined {
	const incomplete = (): undefined => {
		if (endOfStream) {
			throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
		}
		return undefined;
	};

	if (data.length === 0) {
		return incomplete();
	}

	// A length prefix split across reads is incomplete, not malformed
	if (data.length < 1 << ((data[0] as number) >> 6)) {
		return incomplete();
	}

	// Decode varint length - may throw on malformed input
	let length: number;
	let varintLength: number;
	try {
		const result = decodeVarint(data);
		length = result.value;
		varintLength = result.usize;
	} catch {
		throw new OHTTPError(OHTTPErrorCode.InvalidMessage);
	}

	if (length === 0) {
		// Final chunk - extends to end of stream, so only the cap bounds it
		const ciphertext = data.subarray(varintLength);
		if (ciphertext.length > DEFAULT_MAX_FRAME_SIZE) {
			throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
		}
		if (!endOfStream) {
			return undefined;
		}
		return {
			ciphertext,
			isFinal: true,
			bytesConsumed: data.length,
		};
	}

	// Non-final chunk
	if (length > DEFAULT_MAX_FRAME_SIZE) {
		throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
	}
	const totalLength = varintLength + length;
	if (data.length < totalLength) {
		return incomplete();
	}

	return {
		ciphertext: data.subarray(varintLength, totalLength),
		isFinal: false,
		bytesConsumed: totalLength,
	};
}
