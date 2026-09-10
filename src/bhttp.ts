import { BHttpDecoder, BHttpEncoder, MessageLimitExceededError } from "bhttp-ts";

import { OHTTPError, OHTTPErrorCode } from "./errors.ts";

let encoder: BHttpEncoder | undefined;
let decoder: BHttpDecoder | undefined;

export const bhttpEncoder = (): BHttpEncoder => (encoder ??= new BHttpEncoder());
export const bhttpDecoder = (): BHttpDecoder => (decoder ??= new BHttpDecoder());

export function resolvePadding(value: number): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new RangeError(`padding must be a non-negative safe integer, got ${value}`);
	}
	return value;
}

export function mapBhttpEncodingError(error: unknown): unknown {
	return error instanceof MessageLimitExceededError
		? new OHTTPError(OHTTPErrorCode.MessageTooLarge)
		: error;
}
