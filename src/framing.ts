import { decode as decodeVarint, encode as encodeVarint } from "quicvarint";
import { DEFAULT_MAX_FRAME_SIZE } from "./constants.js";
import { OHTTPError, OHTTPErrorCode } from "./errors.js";
import { concat } from "./utils.js";

/**
 * Frame a chunk with varint length prefix
 *
 * Non-final chunks: length (varint) + ciphertext
 * Final chunk: 0 (varint) + ciphertext
 */
export function frameChunk(ciphertext: Uint8Array, isFinal: boolean): Uint8Array<ArrayBuffer> {
	const length = isFinal ? 0 : ciphertext.length;
	const lengthBytes = encodeVarint(length);
	return concat(lengthBytes, ciphertext);
}

/**
 * Result of parsing a framed chunk
 */
export interface ParsedChunk {
	readonly ciphertext: Uint8Array<ArrayBuffer>;
	readonly isFinal: boolean;
	readonly bytesConsumed: number;
}

/**
 * Parse a framed chunk, returning the ciphertext and whether it's final
 *
 * Returns undefined if not enough data available.
 * Throws OHTTPError if the varint encoding is malformed, or if the declared
 * frame length exceeds `maxFrameSize`.
 */
export function parseFramedChunk(
	data: Uint8Array,
	maxFrameSize: number = DEFAULT_MAX_FRAME_SIZE,
): ParsedChunk | undefined {
	if (data.length === 0) {
		return undefined;
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
		const ciphertext = data.slice(varintLength);
		if (ciphertext.length > maxFrameSize) {
			throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
		}
		return {
			ciphertext,
			isFinal: true,
			bytesConsumed: data.length,
		};
	}

	// Non-final chunk
	if (length > maxFrameSize) {
		throw new OHTTPError(OHTTPErrorCode.ChunkLimitExceeded);
	}
	const totalLength = varintLength + length;
	if (data.length < totalLength) {
		// Not enough data
		return undefined;
	}

	return {
		ciphertext: data.slice(varintLength, totalLength),
		isFinal: false,
		bytesConsumed: totalLength,
	};
}
