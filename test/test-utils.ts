/**
 * Test utilities - not exported from main package
 */

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
		// biome-ignore lint/style/noNonNullAssertion: length check above guarantees index exists
		result |= a[i]! ^ b[i]!;
	}
	return result === 0;
}

/**
 * Encode a number as big-endian bytes
 * Uses DataView for 1/2/4 bytes, manual loop for other lengths
 */
export function encodeNumber(value: number, byteLength: number): Uint8Array {
	const bytes = new Uint8Array(byteLength);
	const view = new DataView(bytes.buffer);
	if (byteLength === 1) {
		view.setUint8(0, value);
	} else if (byteLength === 2) {
		view.setUint16(0, value);
	} else if (byteLength === 4) {
		view.setUint32(0, value);
	} else {
		let remaining = value;
		for (let i = byteLength - 1; i >= 0 && remaining > 0; i--) {
			bytes[i] = remaining & 0xff;
			remaining = Math.floor(remaining / 256);
		}
	}
	return bytes;
}

/**
 * Decode big-endian bytes to number
 * Uses DataView for 1/2/4 bytes, returns undefined for other lengths
 */
export function decodeNumber(bytes: Uint8Array): number | undefined {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	if (bytes.length === 1) {
		return view.getUint8(0);
	}
	if (bytes.length === 2) {
		return view.getUint16(0);
	}
	if (bytes.length === 4) {
		return view.getUint32(0);
	}
	return undefined;
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
