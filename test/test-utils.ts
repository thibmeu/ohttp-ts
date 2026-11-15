/**
 * Test utilities - not exported from main package
 */

import { AEAD_ChaCha20Poly1305, type RecipientContext, type SenderContext } from "hpke";
import { type ChunkedRequestContext, senderStates } from "../src/client.js";
import { deriveChunkedResponseKeys } from "../src/encapsulation.js";
import {
	type ChunkedServerRequestContext,
	type ChunkedServerResponseContext,
	recipientStates,
} from "../src/server.js";

/** Buffer.slice() semantics without a Node dependency. */
export class ViewSlicingBytes extends Uint8Array<ArrayBuffer> {
	override slice(start?: number, end?: number): Uint8Array<ArrayBuffer> {
		return this.subarray(start, end);
	}
}

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

/** HPKE state behind a chunked request context (client or gateway side) */
export function hpkeOf(ctx: ChunkedRequestContext): {
	senderContext: SenderContext;
	enc: Uint8Array;
};
export function hpkeOf(ctx: ChunkedServerRequestContext): {
	recipientContext: RecipientContext;
	enc: Uint8Array;
};
export function hpkeOf(ctx: ChunkedRequestContext | ChunkedServerRequestContext) {
	const state =
		senderStates.get(ctx as ChunkedRequestContext) ??
		recipientStates.get(ctx as ChunkedServerRequestContext);
	if (state === undefined) throw new Error("not a chunked request context");
	return state;
}

/** Response AEAD keys for a gateway response context, re-derived from its request */
export function aeadOf(req: ChunkedServerRequestContext, res: ChunkedServerResponseContext) {
	const state = recipientStates.get(req);
	if (state === undefined) throw new Error("not a chunked request context");
	return deriveChunkedResponseKeys(
		state.suite,
		state.recipientContext,
		state.enc,
		res.responseNonce,
	);
}
