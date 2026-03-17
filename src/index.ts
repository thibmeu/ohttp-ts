// OHTTP-TS: Oblivious HTTP implementation
// RFC 9458: https://www.rfc-editor.org/rfc/rfc9458.txt
// Chunked OHTTP: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt
// Incremental: https://www.ietf.org/archive/id/draft-ietf-httpbis-incremental-04.txt

// ============================================================================
// Errors
// ============================================================================

export { isOHTTPError, OHTTPError, OHTTPErrorCode } from "./errors.js";

// ============================================================================
// Client & Server classes
// ============================================================================

export {
	type ChunkedHttpClientContext,
	ChunkedOHTTPClient,
	type ChunkedOHTTPClientOptions,
	type ChunkedRequestContext,
	type ChunkedResponseContext,
	type ClientContext,
	type EncapsulatedChunkedRequestInit,
	type EncapsulatedRequest,
	type EncapsulatedRequestInit,
	type HttpClientContext,
	OHTTPClient,
	type OHTTPClientOptions,
} from "./client.js";

export {
	type ChunkedHttpServerContext,
	ChunkedOHTTPServer,
	type ChunkedOHTTPServerOptions,
	type ChunkedServerRequestContext,
	type ChunkedServerResponseContext,
	type DecapsulatedChunkedHttpRequest,
	type DecapsulatedHttpRequest,
	type DecapsulatedRequest,
	type HttpServerContext,
	OHTTPServer,
	type OHTTPServerOptions,
	type ServerContext,
} from "./server.js";

// ============================================================================
// Algorithm IDs (like hpke factory constants)
// ============================================================================

export {
	AeadId,
	isValidAeadId,
	isValidKdfId,
	isValidKemId,
	KdfId,
	KemId,
} from "./keyConfig.js";

// ============================================================================
// KeyConfig namespace
// ============================================================================

import {
	deriveKeyConfig,
	generateKeyConfig,
	getPublicKeyLength,
	importKeyConfig,
	type KeyConfig as KeyConfigType,
	type KeyConfigWithPrivate as KeyConfigWithPrivateType,
	parseKeyConfig,
	parseKeyConfigs,
	type SymmetricAlgorithm as SymmetricAlgorithmType,
	serializeKeyConfig,
	serializeKeyConfigs,
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

export { MediaType } from "./constants.js";

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
	createIncrementalHeaders,
	getIncremental,
	INCREMENTAL_HEADER,
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
	type ClientEncapsulationContext,
	type EncapsulatedRequestHeader,
	frameChunk,
	type ParsedChunk,
	parseFramedChunk,
	type ServerEncapsulationContext,
} from "./encapsulation.js";
