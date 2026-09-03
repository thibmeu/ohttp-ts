/**
 * Incremental HTTP header field (RFC 10036)
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
 * Accepts only the canonical "?1" and "?0" values.
 *
 * Structured Fields parameters are not supported. Incremental is advisory, so
 * unsupported or malformed values return undefined.
 *
 * @param value - The header value string
 * @returns true/false if valid boolean, undefined if invalid
 */
export function parseIncremental(value: string): boolean | undefined {
	if (value === "?1") return true;
	if (value === "?0") return false;
	return undefined;
}

/**
 * Create headers with Incremental field set
 *
 * @param incremental - true to request incremental forwarding
 * @returns Headers object with Incremental field
 */
export function createIncrementalHeaders(incremental = true): Headers {
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
