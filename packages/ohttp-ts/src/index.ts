// OHTTP-TS: Oblivious HTTP implementation
// RFC 9458: https://www.rfc-editor.org/rfc/rfc9458.txt
// Chunked OHTTP: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt
// Incremental: https://www.ietf.org/archive/id/draft-ietf-httpbis-incremental-04.txt

export const VERSION = "0.0.1";

// ============================================================================
// Errors
// ============================================================================

export { OHTTPError, OHTTPErrorCode, isOHTTPError } from "./errors.js";

// ============================================================================
// Client & Server classes
// ============================================================================

export {
	ChunkedOHTTPClient,
	OHTTPClient,
	type ChunkedOHTTPClientOptions,
	type ChunkedRequestContext,
	type ChunkedResponseContext,
	type ClientContext,
	type EncapsulatedRequest,
	type OHTTPClientOptions,
} from "./client.js";

export {
	ChunkedOHTTPServer,
	OHTTPServer,
	type ChunkedOHTTPServerOptions,
	type ChunkedServerRequestContext,
	type ChunkedServerResponseContext,
	type DecapsulatedRequest,
	type OHTTPServerOptions,
	type ServerContext,
} from "./server.js";

// ============================================================================
// Algorithm IDs (like hpke factory constants)
// ============================================================================

export {
	AeadId,
	KdfId,
	KemId,
	isValidAeadId,
	isValidKdfId,
	isValidKemId,
} from "./keyConfig.js";

// ============================================================================
// KeyConfig namespace
// ============================================================================

import {
	deriveKeyConfig,
	generateKeyConfig,
	getPublicKeyLength,
	importKeyConfig,
	parseKeyConfig,
	parseKeyConfigs,
	serializeKeyConfig,
	serializeKeyConfigs,
	type KeyConfig as KeyConfigType,
	type KeyConfigWithPrivate as KeyConfigWithPrivateType,
	type SymmetricAlgorithm as SymmetricAlgorithmType,
} from "./keyConfig.js";

/** KeyConfig utilities for parsing, serializing, and generating OHTTP key configurations */
export const KeyConfig = {
	/** Generate a new KeyConfig with random key pair */
	generate: generateKeyConfig,
	/** Derive a deterministic KeyConfig from a seed */
	derive: deriveKeyConfig,
	/** Import a KeyConfig from raw key bytes */
	import: importKeyConfig,
	/** Parse a single KeyConfig from bytes */
	parse: parseKeyConfig,
	/** Parse multiple KeyConfigs from application/ohttp-keys format */
	parseMultiple: parseKeyConfigs,
	/** Serialize a KeyConfig to bytes */
	serialize: serializeKeyConfig,
	/** Serialize multiple KeyConfigs to application/ohttp-keys format */
	serializeMultiple: serializeKeyConfigs,
	/** Get the public key length for a KEM */
	getPublicKeyLength,
} as const;

// Re-export types
export type KeyConfig = KeyConfigType;
export type KeyConfigWithPrivate = KeyConfigWithPrivateType;
export type SymmetricAlgorithm = SymmetricAlgorithmType;

// ============================================================================
// Media Types (RFC 9458 Section 9, draft-ietf-ohai-chunked-ohttp-08 Section 8)
// ============================================================================

/** OHTTP media types for Content-Type headers */
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

// ============================================================================
// Labels namespace
// ============================================================================

import {
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	FINAL_CHUNK_AAD,
} from "./encapsulation.js";

/** Protocol labels for OHTTP request/response encryption */
export const Labels = {
	/** Default label for standard OHTTP requests (RFC 9458) */
	REQUEST: DEFAULT_REQUEST_LABEL,
	/** Default label for standard OHTTP responses (RFC 9458) */
	RESPONSE: DEFAULT_RESPONSE_LABEL,
	/** Label for chunked OHTTP requests (draft-08) */
	CHUNKED_REQUEST: CHUNKED_REQUEST_LABEL,
	/** Label for chunked OHTTP responses (draft-08) */
	CHUNKED_RESPONSE: CHUNKED_RESPONSE_LABEL,
	/** AAD for final chunk in chunked OHTTP */
	FINAL_CHUNK_AAD,
	/** Default maximum chunk size (16384 bytes) */
	DEFAULT_MAX_CHUNK_SIZE,
} as const;

// ============================================================================
// Incremental namespace
// ============================================================================

import {
	INCREMENTAL_HEADER,
	createIncrementalHeaders,
	getIncremental,
	parseIncremental,
	serializeIncremental,
	setIncremental,
} from "./incremental.js";

/** Incremental HTTP header utilities (draft-ietf-httpbis-incremental) */
export const Incremental = {
	/** Header name: "Incremental" */
	HEADER: INCREMENTAL_HEADER,
	/** Parse Incremental header value to boolean */
	parse: parseIncremental,
	/** Serialize boolean to Incremental header value */
	serialize: serializeIncremental,
	/** Get Incremental value from Headers object */
	get: getIncremental,
	/** Set Incremental value on Headers object */
	set: setIncremental,
	/** Create new Headers with Incremental header set */
	createHeaders: createIncrementalHeaders,
} as const;

// ============================================================================
// Low-level encapsulation (for advanced use)
// ============================================================================

export {
	frameChunk,
	parseFramedChunk,
	type ClientEncapsulationContext,
	type EncapsulatedRequestHeader,
	type ParsedChunk,
	type ServerEncapsulationContext,
} from "./encapsulation.js";
