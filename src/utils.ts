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
 * Convert Uint8Array to ArrayBuffer for use as BodyInit.
 * Creates a copy to ensure it's a plain ArrayBuffer (not SharedArrayBuffer).
 */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
	const buffer = new ArrayBuffer(data.byteLength);
	new Uint8Array(buffer).set(data);
	return buffer;
}
