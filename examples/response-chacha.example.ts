// Copyright (c) 2024
// Licensed under the MIT license

// Example: OHTTP with a ChaCha20-Poly1305 response.
//
// OHTTP responses are not HPKE: the response key is derived with HKDF over an
// HPKE-exported secret and then used with a raw AEAD. By default that AEAD is
// resolved from the suite, using hpke's WebCrypto-backed factory. In browsers
// and Cloudflare Workers, where WebCrypto lacks ChaCha20-Poly1305, pass a
// non-WebCrypto factory via `responseCrypto` — exactly how mlkem.example.ts
// swaps the KEM.
//
// Install: npm add @panva/hpke-noble

import { AEAD_ChaCha20Poly1305, KDF_HKDF_SHA256 } from "@panva/hpke-noble";
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { AeadId, KdfId, KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

export async function chachaResponseOHTTP(): Promise<boolean> {
	// [ Everybody ] agree on DHKEM(X25519), HKDF-SHA256, ChaCha20-Poly1305.
	const suite = new CipherSuite(
		KEM_DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_ChaCha20Poly1305,
	);

	// Route response HKDF + AEAD through @panva/hpke-noble so it works without
	// WebCrypto ChaCha20 support. Partial overrides are allowed; here we set both.
	const responseCrypto = { kdf: KDF_HKDF_SHA256, aead: AEAD_ChaCha20Poly1305 };

	// [ Gateway ] creates a key configuration and a server.
	const keyConfig = await KeyConfig.generate(suite, 0x01, [
		{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.ChaCha20Poly1305 },
	]);
	const gateway = new OHTTPServer([keyConfig], { responseCrypto });

	// [ Client ] fetches the public key configuration and creates a client.
	const publicKeyConfig = KeyConfig.serialize(keyConfig);
	const client = new OHTTPClient(suite, KeyConfig.parse(publicKeyConfig), { responseCrypto });

	// Online protocol (RFC 9458 Figure 1)
	const request = new TextEncoder().encode(
		"GET /resource HTTP/1.1\r\nHost: target.example\r\n\r\n",
	);
	const { encapsulatedRequest, context } = await client.encapsulate(request);

	const { request: decryptedRequest, context: serverContext } =
		await gateway.decapsulate(encapsulatedRequest);

	const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello over ChaCha20");
	const encapsulatedResponse = await serverContext.encryptResponse(response);

	const decryptedResponse = await context.decryptResponse(encapsulatedResponse);

	const requestMatch =
		new TextDecoder().decode(decryptedRequest) === new TextDecoder().decode(request);
	const responseMatch =
		new TextDecoder().decode(decryptedResponse) === new TextDecoder().decode(response);

	return requestMatch && responseMatch;
}
