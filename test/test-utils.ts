/**
 * Test utilities - not exported from main package
 */

import { AEAD_ChaCha20Poly1305 } from "hpke";

/**
 * Whether the current runtime's WebCrypto implements ChaCha20-Poly1305.
 *
 * Node 24+ supports it (experimental); browser SubtleCrypto does not. Tests
 * that exercise the WebCrypto ChaCha20 request leg are skipped where it is
 * unavailable. We probe via hpke's own AEAD so the check matches exactly what
 * the library does at runtime.
 */
export const supportsChaCha20Poly1305: boolean = await (async () => {
	try {
		const aead = AEAD_ChaCha20Poly1305();
		await aead.Seal(new Uint8Array(32), new Uint8Array(12), new Uint8Array(0), new Uint8Array(1));
		return true;
	} catch {
		return false;
	}
})();

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
 * {@link fromHex}, but throwing - known-answer tests want the bytes, not a
 * guard at every call site.
 */
export function hex(s: string): Uint8Array {
	const bytes = fromHex(s);
	if (bytes === undefined) {
		throw new Error(`invalid hex in test vector: ${s}`);
	}
	return bytes;
}
