/**
 * OHTTP error codes - opaque to prevent information leakage
 */
export const OHTTPErrorCode = {
	/** Failed to parse key configuration */
	InvalidKeyConfig: "INVALID_KEY_CONFIG",
	/** Unknown key identifier */
	UnknownKeyId: "UNKNOWN_KEY_ID",
	/** Unsupported cipher suite */
	UnsupportedCipherSuite: "UNSUPPORTED_CIPHER_SUITE",
	/** Decryption failed - deliberately opaque */
	DecryptionFailed: "DECRYPTION_FAILED",
	/** Encryption failed */
	EncryptionFailed: "ENCRYPTION_FAILED",
	/** Invalid message format */
	InvalidMessage: "INVALID_MESSAGE",
	/** Chunk sequence error */
	ChunkSequenceError: "CHUNK_SEQUENCE_ERROR",
	/** Chunk limit exceeded */
	ChunkLimitExceeded: "CHUNK_LIMIT_EXCEEDED",
} as const;

export type OHTTPErrorCode = (typeof OHTTPErrorCode)[keyof typeof OHTTPErrorCode];

/**
 * Opaque error type for OHTTP operations.
 * Messages are deliberately vague to prevent oracle attacks.
 */
export class OHTTPError extends Error {
	readonly code: OHTTPErrorCode;

	constructor(code: OHTTPErrorCode) {
		// Opaque message - no details about what failed
		super(`OHTTP error: ${code}`);
		this.name = "OHTTPError";
		this.code = code;
		Object.setPrototypeOf(this, OHTTPError.prototype);
	}
}

/**
 * Type guard for OHTTPError
 */
export function isOHTTPError(error: unknown): error is OHTTPError {
	return error instanceof OHTTPError;
}
