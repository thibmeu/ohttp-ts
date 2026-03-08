// OHTTP-TS: Oblivious HTTP implementation
// RFC 9458: https://www.rfc-editor.org/rfc/rfc9458.txt
// Chunked OHTTP: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt
// Incremental: https://www.ietf.org/archive/id/draft-ietf-httpbis-incremental-04.txt

export const VERSION = "0.0.1";

// Errors
export { OHTTPError, OHTTPErrorCode, isOHTTPError } from "./errors.js";

// Utils
export { constantTimeEqual, fromHex, toHex } from "./utils.js";

// Key configuration
export {
	AeadId,
	KdfId,
	KemId,
	deriveKeyConfig,
	generateKeyConfig,
	getPublicKeyLength,
	importKeyConfig,
	isValidAeadId,
	isValidKdfId,
	isValidKemId,
	parseKeyConfig,
	parseKeyConfigs,
	serializeKeyConfig,
	serializeKeyConfigs,
	type KeyConfig,
	type KeyConfigWithPrivate,
	type SymmetricAlgorithm,
} from "./keyConfig.js";

// Encapsulation
export {
	CHUNKED_REQUEST_LABEL,
	CHUNKED_RESPONSE_LABEL,
	DEFAULT_MAX_CHUNK_SIZE,
	DEFAULT_REQUEST_LABEL,
	DEFAULT_RESPONSE_LABEL,
	FINAL_CHUNK_AAD,
	frameChunk,
	parseFramedChunk,
	type ClientEncapsulationContext,
	type EncapsulatedRequestHeader,
	type ParsedChunk,
	type ServerEncapsulationContext,
} from "./encapsulation.js";

// Client
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

// Server
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

// Incremental header (draft-ietf-httpbis-incremental)
export {
	INCREMENTAL_HEADER,
	createIncrementalHeaders,
	getIncremental,
	parseIncremental,
	serializeIncremental,
	setIncremental,
} from "./incremental.js";
