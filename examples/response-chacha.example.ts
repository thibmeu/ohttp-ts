// Copyright (c) 2024
// Licensed under the MIT license

// Example: one key configuration serving AES-128-GCM and ChaCha20-Poly1305,
// the shape RFC 9458 Appendix A publishes.
//
// A key configuration may advertise several (KDF, AEAD) pairs under one key
// identifier. The gateway passes one suite per pair, all sharing a KEM, and one
// key pair covers them: the request header names the pair it used and the
// gateway decrypts with the matching suite.
//
// OHTTP responses are not HPKE: the response key is derived with HKDF over an
// HPKE-exported secret and then used with a raw AEAD. By default that AEAD is
// resolved from the suite, using hpke's WebCrypto-backed factory. In browsers
// and Cloudflare Workers, where WebCrypto lacks ChaCha20-Poly1305, pass a
// non-WebCrypto factory via `responseCrypto` - exactly how mlkem.example.ts
// swaps the KEM. A gateway serving two AEADs passes one factory per AEAD, since
// which one a response uses is decided by the request, not by the server.
//
// Install: npm add @panva/hpke-noble

import { AEAD_ChaCha20Poly1305 } from "@panva/hpke-noble";
import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

export async function chachaResponseOHTTP(): Promise<boolean> {
	// [ Gateway ] serves DHKEM(X25519) + HKDF-SHA256 with either AEAD. Both
	// suites take their KEM from the same place, which is what lets one key pair
	// serve both.
	const aesSuite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const chachaSuite = new CipherSuite(
		KEM_DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_ChaCha20Poly1305,
	);

	const keyConfig = await KeyConfig.generate([aesSuite, chachaSuite], 0x01);
	// One factory per AEAD served. Responses for the ChaCha20 pair go through
	// @panva/hpke-noble, so the gateway needs no WebCrypto ChaCha20 support;
	// responses for the AES pair keep the WebCrypto path.
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
