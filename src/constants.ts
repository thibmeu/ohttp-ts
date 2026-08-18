const textEncoder = new TextEncoder();

function encodeString(s: string): Uint8Array {
	return textEncoder.encode(s);
}

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
} from "bhttp-ts";

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

/**
 * Default labels for OHTTP request/response (RFC 9458 Section 4.3-4.4)
 */
export const DEFAULT_REQUEST_LABEL = "message/bhttp request";
export const DEFAULT_RESPONSE_LABEL = "message/bhttp response";

/**
 * Labels for chunked OHTTP (draft-ietf-ohai-chunked-ohttp-08 Section 6.1-6.2)
 */
export const CHUNKED_REQUEST_LABEL = "message/bhttp chunked request";
export const CHUNKED_RESPONSE_LABEL = "message/bhttp chunked response";

/**
 * Default maximum chunk size (draft-08 Section 3)
 */
export const DEFAULT_MAX_CHUNK_SIZE = 16384;

/**
 * Default cap on a single received ciphertext frame, in bytes (1 MiB).
 *
 * Distinct from {@link DEFAULT_MAX_CHUNK_SIZE}, which bounds what this side
 * *sends*: a peer may legitimately choose a larger chunk size, so the receive
 * limit is set generously above it rather than equal to it.
 *
 * A frame is a chunk's *ciphertext*, so it runs {@link AEAD_TAG_SIZE} bytes
 * longer than the plaintext chunk it carries.
 */
export const DEFAULT_MAX_FRAME_SIZE = 1 << 20;

/**
 * AEAD tag length in bytes, 16 for every AEAD OHTTP registers (draft-08 Section 6).
 */
export const AEAD_TAG_SIZE = 16;

/**
 * AAD for final chunk (draft-08 Section 6.1-6.2)
 */
export const FINAL_CHUNK_AAD = /* @__PURE__ */ encodeString("final");
