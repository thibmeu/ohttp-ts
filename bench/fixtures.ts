/**
 * Shared benchmark fixtures.
 *
 * Every bench measures the same OHTTP cipher suite (X25519 / HKDF-SHA256 /
 * AES-128-GCM, key id 0x01), so the suite, a generated key config, and one
 * client/server pair live here instead of being rebuilt in each file.
 *
 * `makeFixture` pre-builds the request/response artifacts a bench needs so the
 * measured op excludes its own setup: `decapsulateRequest` reuses a fixed
 * `encapsulatedRequest`, and `decryptResponse` reuses a fixed
 * `encryptedResponse`. These ops are stateless (fresh recipient context / fresh
 * derived keys per call), so repeating them on the same fixture is valid.
 */

import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";
import { randomBytes } from "./util.js";

export const suite = new CipherSuite(
	KEM_DHKEM_X25519_HKDF_SHA256,
	KDF_HKDF_SHA256,
	AEAD_AES_128_GCM,
);

export const keyConfig = await KeyConfig.generate(suite, 0x01);

export const client = new OHTTPClient(suite, keyConfig);
export const server = new OHTTPServer([keyConfig]);

export interface Fixture {
	/** The plaintext request/response body. */
	readonly payload: Uint8Array;
	/** A prebuilt encapsulated request (header + enc + ciphertext). */
	readonly encapsulatedRequest: Uint8Array;
	/** Client context for decrypting the response. */
	readonly clientCtx: Awaited<ReturnType<typeof client.encapsulate>>["context"];
	/** Server context for encrypting the response. */
	readonly serverCtx: Awaited<ReturnType<typeof server.decapsulate>>["context"];
	/** A prebuilt encrypted response. */
	readonly encryptedResponse: Uint8Array;
}

/** Build the per-size fixtures shared by the single-shot benches. */
export async function makeFixture(bytes: number): Promise<Fixture> {
	const payload = randomBytes(bytes);
	const { encapsulatedRequest, context: clientCtx } = await client.encapsulate(payload);
	const { context: serverCtx } = await server.decapsulate(encapsulatedRequest);
	const encryptedResponse = await serverCtx.encryptResponse(payload);
	return { payload, encapsulatedRequest, clientCtx, serverCtx, encryptedResponse };
}
