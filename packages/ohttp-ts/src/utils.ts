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
 * Uses DataView for 1/2/4 bytes, manual loop for other lengths (e.g., 12-byte nonce counter)
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
		// For arbitrary lengths (e.g., 12-byte nonce counter), fill from right
		for (let i = byteLength - 1; i >= 0 && value > 0; i--) {
			bytes[i] = value & 0xff;
			value = Math.floor(value / 256);
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
