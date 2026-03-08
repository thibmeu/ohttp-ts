// Copyright (c) 2024
// Licensed under the MIT license

import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { AeadId, KdfId, KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

// Follows RFC 9458 Oblivious HTTP

async function setup() {
	// [ Gateway ] creates key configuration
	const suite = new CipherSuite(
		KEM_DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
	);
	const keyConfig = await KeyConfig.generate(suite, 0x01, [
		{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
	]);
	const gateway = new OHTTPServer([keyConfig]);

	// [ Client ] fetches gateway's public key configuration
	const publicKeyConfig = KeyConfig.serialize(keyConfig);
	const clientKeyConfig = KeyConfig.parse(publicKeyConfig);
	const client = new OHTTPClient(suite, clientKeyConfig);

	return { gateway, client };
}

export async function obliviousHTTP(): Promise<boolean> {
	// Protocol Setup
	//
	// [ Everybody ] agree to use Oblivious HTTP with DHKEM(X25519), HKDF-SHA256, AES-128-GCM
	const { gateway, client } = await setup();

	// Online Protocol (RFC 9458 Figure 1)
	//
	// +---------+       +----------+      +----------+    +----------+
	// | Client  |       | Relay    |      | Gateway  |    | Target   |
	// |         |       | Resource |      | Resource |    | Resource |
	// +----+----+       +----+-----+      +-----+----+    +----+-----+
	//      |                 |                  |              |
	//      | Relay           |                  |              |
	//      | Request         |                  |              |
	//      | [+ Encapsulated |                  |              |
	//      |    Request ]    |                  |              |
	const request = new TextEncoder().encode("GET /resource HTTP/1.1\r\nHost: target.example\r\n\r\n");
	const { encapsulatedRequest, context } = await client.encapsulate(request);
	//      +---------------->| Gateway          |              |
	//      |                 | Request          |              |
	//      |                 | [+ Encapsulated  |              |
	//      |                 |    Request ]     |              |
	//      |                 +----------------->| Request      |
	const { request: decryptedRequest, context: serverContext } =
		await gateway.decapsulate(encapsulatedRequest);
	//      |                 |                  +------------->|
	//      |                 |                  |              |
	//      |                 |                  |     Response |
	//      |                 |          Gateway |<-------------+
	//      |                 |         Response |              |
	//      |                 |  [+ Encapsulated |              |
	//      |                 |       Response ] |              |
	const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");
	const encapsulatedResponse = await serverContext.encryptResponse(response);
	//      |           Relay |<-----------------+              |
	//      |        Response |                  |              |
	//      | [+ Encapsulated |                  |              |
	//      |      Response ] |                  |              |
	//      |<----------------+                  |              |
	//      |                 |                  |              |
	const decryptedResponse = await context.decryptResponse(encapsulatedResponse);

	const requestMatch =
		new TextDecoder().decode(decryptedRequest) === new TextDecoder().decode(request);
	const responseMatch =
		new TextDecoder().decode(decryptedResponse) === new TextDecoder().decode(response);

	return requestMatch && responseMatch;
}
