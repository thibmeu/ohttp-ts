import {
	BHttpDecoder,
	BHttpEncoder,
	MessageLimitExceededError,
	MetadataLimitExceededError,
	type Padding,
	padmeWithFloor,
} from "bhttp-ts";

import { OHTTPError, OHTTPErrorCode } from "./errors.ts";

let encoder: BHttpEncoder | undefined;
let decoder: BHttpDecoder | undefined;

export const bhttpEncoder = (): BHttpEncoder => (encoder ??= new BHttpEncoder());
export const bhttpDecoder = (): BHttpDecoder => (decoder ??= new BHttpDecoder());

export const DEFAULT_PADDING = /* @__PURE__ */ padmeWithFloor(1024);

export function resolvePadding(value: Padding, maxMessageSize: number): Padding {
	if (typeof value === "function") {
		const minimum = value(1);
		if (!Number.isSafeInteger(minimum) || minimum < 1) {
			throw new RangeError("padding must return a safe integer >= size");
		}
		if (minimum > maxMessageSize)
			throw new RangeError("minimum padded size exceeds maxMessageSize");
		return value;
	}
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new RangeError(`padding must be a non-negative safe integer, got ${value}`);
	}
	if (value > maxMessageSize) throw new RangeError("minimum padded size exceeds maxMessageSize");
	return value;
}

export function mapBhttpEncodingError(error: unknown): unknown {
	return error instanceof MessageLimitExceededError || error instanceof MetadataLimitExceededError
		? new OHTTPError(OHTTPErrorCode.MessageTooLarge)
		: error;
}

/**
 * Keep the code a decryption pipeline raised and report Binary HTTP size limits
 * as MessageTooLarge; anything else is a framing error.
 */
export function asInvalidMessage(error: unknown): OHTTPError {
	const mapped = mapBhttpEncodingError(error);
	return mapped instanceof OHTTPError ? mapped : new OHTTPError(OHTTPErrorCode.InvalidMessage);
}
