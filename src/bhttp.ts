import {
	BHttpDecoder,
	BHttpEncoder,
	MessageLimitExceededError,
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
	return error instanceof MessageLimitExceededError
		? new OHTTPError(OHTTPErrorCode.MessageTooLarge)
		: error;
}
