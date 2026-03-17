import { BHttpDecoder, BHttpEncoder } from "bhttp-js";

export {
	type BHttpContentEvent,
	type BHttpEndEvent,
	type BHttpEvent,
	type BHttpInformationalEvent,
	type BHttpRequestPreambleEvent,
	BHttpRequestStreamEncoder,
	type BHttpResponsePreambleEvent,
	BHttpResponseStreamEncoder,
	BHttpStreamDecoder,
	type BHttpTrailersEvent,
} from "bhttp-js";

/**
 * OHTTP media types for Content-Type headers
 */
export const MediaType = {
	/** Key configuration: application/ohttp-keys (RFC 9458 Section 9.1) */
	KEYS: "application/ohttp-keys",
	/** Encapsulated request: message/ohttp-req (RFC 9458 Section 9.2) */
	REQUEST: "message/ohttp-req",
	/** Encapsulated response: message/ohttp-res (RFC 9458 Section 9.3) */
	RESPONSE: "message/ohttp-res",
	/** Chunked encapsulated request: message/ohttp-chunked-req (draft-08 Section 8.1) */
	CHUNKED_REQUEST: "message/ohttp-chunked-req",
	/** Chunked encapsulated response: message/ohttp-chunked-res (draft-08 Section 8.2) */
	CHUNKED_RESPONSE: "message/ohttp-chunked-res",
} as const;

export type MediaType = (typeof MediaType)[keyof typeof MediaType];

/** Shared Binary HTTP encoder/decoder (stateless singletons) */
export const bhttp = {
	encoder: new BHttpEncoder(),
	decoder: new BHttpDecoder(),
};
