/**
 * Incremental HTTP header field (draft-ietf-httpbis-incremental)
 *
 * The Incremental header is a Structured Field of type Item (boolean).
 * - `?1` = request incremental forwarding
 * - `?0` = allow buffering (default)
 *
 * Used by chunked OHTTP to signal intermediaries not to buffer messages.
 */

/**
 * Header field name
 */
export const INCREMENTAL_HEADER = "Incremental";

/**
 * Serialize an Incremental header value
 *
 * @param incremental - true for incremental forwarding, false for buffering
 * @returns Structured field boolean string ("?1" or "?0")
 */
export function serializeIncremental(incremental: boolean): string {
	return incremental ? "?1" : "?0";
}

/**
 * Parse an Incremental header value
 *
 * Accepts structured field boolean format:
 * - "?1" or "?1" with parameters → true
 * - "?0" or "?0" with parameters → false
 * - Invalid/unknown values → undefined
 *
 * @param value - The header value string
 * @returns true/false if valid boolean, undefined if invalid
 */
export function parseIncremental(value: string): boolean | undefined {
	const trimmed = value.trim();

	// Per RFC 9651 §3.3.6, boolean is "?" followed by "0" or "1"
	// Parameters may follow after ";"
	if (trimmed.startsWith("?1")) {
		// Check for valid continuation (end of string, whitespace, or parameters)
		const rest = trimmed.slice(2);
		if (rest === "" || rest.startsWith(";") || /^\s/.test(rest)) {
			return true;
		}
	}

	if (trimmed.startsWith("?0")) {
		const rest = trimmed.slice(2);
		if (rest === "" || rest.startsWith(";") || /^\s/.test(rest)) {
			return false;
		}
	}

	// Invalid format
	return undefined;
}

/**
 * Create headers with Incremental field set
 *
 * @param incremental - true to request incremental forwarding
 * @returns Headers object with Incremental field
 */
export function createIncrementalHeaders(incremental: boolean = true): Headers {
	const headers = new Headers();
	headers.set(INCREMENTAL_HEADER, serializeIncremental(incremental));
	return headers;
}

/**
 * Check if headers indicate incremental forwarding
 *
 * @param headers - Headers to check
 * @returns true if Incremental: ?1, false if Incremental: ?0, undefined if not set or invalid
 */
export function getIncremental(headers: Headers): boolean | undefined {
	const value = headers.get(INCREMENTAL_HEADER);
	if (value === null) {
		return undefined;
	}
	return parseIncremental(value);
}

/**
 * Set the Incremental header on existing headers
 *
 * @param headers - Headers to modify
 * @param incremental - true for incremental forwarding
 */
export function setIncremental(headers: Headers, incremental: boolean): void {
	headers.set(INCREMENTAL_HEADER, serializeIncremental(incremental));
}
