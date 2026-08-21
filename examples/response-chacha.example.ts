// Copyright (c) 2024
// Licensed under the MIT license

// Example: one key configuration serving AES-128-GCM and ChaCha20-Poly1305,
// the shape RFC 9458 Appendix A publishes. One suite per pair, one key pair for
// all of them, and the request header says which pair it used.
//
// OHTTP responses are not HPKE: the key comes from HKDF over an HPKE-exported
// secret and feeds a raw AEAD, resolved from the suite via hpke's WebCrypto
// factories. Browsers and Cloudflare Workers lack ChaCha20-Poly1305 there, so
// pass a factory per AEAD served via `responseCrypto`.
//
// Install: npm add @panva/hpke-noble

import { AEAD_ChaCha20Poly1305 } from "@panva/hpke-noble";
import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

export async function chachaResponseOHTTP(): Promise<boolean> {
	// [ Gateway ] serves DHKEM(X25519) + HKDF-SHA256 with either AEAD. Same KEM
	// both times, which is what lets one key pair serve both.
	const aesSuite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const chachaSuite = new CipherSuite(
		KEM_DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_ChaCha20Poly1305,
	);

	const keyConfig = await KeyConfig.generate([aesSuite, chachaSuite], 0x01);
	// ChaCha20 responses go through @panva/hpke-noble, AES ones keep WebCrypto.
	const gateway = new OHTTPServer([keyConfig], {
		responseCrypto: { aead: [AEAD_AES_128_GCM, AEAD_ChaCha20Poly1305] },
	});

	// [ Clients ] fetch the same published configuration and each pick a pair.
	const published = KeyConfig.parse(KeyConfig.serialize(keyConfig));
	const clients = [
		new OHTTPClient(aesSuite, published),
		new OHTTPClient(chachaSuite, published, {
			responseCrypto: { aead: AEAD_ChaCha20Poly1305 },
		}),
	];

	const request = new TextEncoder().encode(
		"GET /resource HTTP/1.1\r\nHost: target.example\r\n\r\n",
	);
	const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");

	for (const client of clients) {
		// Online protocol (RFC 9458 Figure 1), once per advertised pair.
		const { encapsulatedRequest, context } = await client.encapsulate(request);

		const { request: decryptedRequest, context: serverContext } =
			await gateway.decapsulate(encapsulatedRequest);

		const encapsulatedResponse = await serverContext.encryptResponse(response);
		const decryptedResponse = await context.decryptResponse(encapsulatedResponse);

		const requestMatch =
			new TextDecoder().decode(decryptedRequest) === new TextDecoder().decode(request);
		const responseMatch =
			new TextDecoder().decode(decryptedResponse) === new TextDecoder().decode(response);
		if (!requestMatch || !responseMatch) {
			return false;
		}
	}

	console.log(
		"Published pairs under key 0x01:",
		published.symmetricAlgorithms.map((a) => `kdf ${a.kdfId} / aead ${a.aeadId}`).join(", "),
	);
	return true;
}
