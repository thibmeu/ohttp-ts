/**
 * Encode bytes to hex string
 */
export function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/**
 * Decode hex string to bytes
 * Returns undefined if invalid hex
 */
export function fromHex(hex: string): Uint8Array | undefined {
	if (hex.length % 2 !== 0) {
		return undefined;
	}

	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		const byte = Number.parseInt(hex.slice(i, i + 2), 16);
		if (Number.isNaN(byte)) {
			return undefined;
		}
		bytes[i / 2] = byte;
	}
	return bytes;
}

/**
 * Constant-time comparison of two byte arrays.
 * Returns true if arrays are equal, false otherwise.
 * Timing is independent of where arrays differ.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) {
		return false;
	}

	let result = 0;
	for (let i = 0; i < a.length; i++) {
		// XOR accumulates differences without early exit
		// biome-ignore lint/style/noNonNullAssertion: length check above guarantees index exists
		result |= a[i]! ^ b[i]!;
	}
	return result === 0;
}

/**
 * Concatenate multiple Uint8Arrays into one
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
	const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const arr of arrays) {
		result.set(arr, offset);
		offset += arr.length;
	}
	return result;
}

/**
 * Encode a number as big-endian bytes
 */
export function encodeNumber(value: number, byteLength: number): Uint8Array {
	const bytes = new Uint8Array(byteLength);
	for (let i = byteLength - 1; i >= 0; i--) {
		bytes[i] = value & 0xff;
		value = Math.floor(value / 256);
	}
	return bytes;
}

/**
 * Decode big-endian bytes to number
 * Returns undefined if bytes exceed safe integer range
 */
export function decodeNumber(bytes: Uint8Array): number | undefined {
	if (bytes.length > 6) {
		// Exceeds safe integer range
		return undefined;
	}

	let value = 0;
	for (const byte of bytes) {
		value = value * 256 + byte;
	}
	return value;
}

/**
 * XOR two byte arrays of equal length
 */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
	if (a.length !== b.length) {
		throw new Error("XOR requires equal length arrays");
	}

	const result = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) {
		// biome-ignore lint/style/noNonNullAssertion: length check guarantees index exists
		result[i] = a[i]! ^ b[i]!;
	}
	return result;
}

/**
 * Encode ASCII string to bytes
 */
export function encodeString(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}
