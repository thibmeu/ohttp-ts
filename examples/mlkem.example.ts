// Copyright (c) 2024
// Licensed under the MIT license

// Example: Post-Quantum OHTTP with ML-KEM-768
//
// This example shows how to use @panva/hpke-noble for post-quantum
// key encapsulation with ML-KEM (FIPS 203).
//
// Install: pnpm add @panva/hpke-noble

import { AEAD_AES_128_GCM, KDF_HKDF_SHA256, KEM_ML_KEM_768 } from "@panva/hpke-noble";
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

// Follows RFC 9458 Oblivious HTTP with ML-KEM-768 (FIPS 203)

async function setup() {
	// [ Gateway ] creates key configuration with ML-KEM-768
	// ML-KEM-768 provides NIST Level 3 security (128-bit post-quantum)
	const suite = new CipherSuite(KEM_ML_KEM_768, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const keyConfig = await KeyConfig.generate(suite, 0x01);
	// A real gateway publishes several keys during a migration, so serve both.
	const legacySuite = new CipherSuite(
		KEM_DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
	);
	const legacyKeyConfig = await KeyConfig.generate(legacySuite, 0x02);
	const gateway = new OHTTPServer([keyConfig, legacyKeyConfig]);

	// [ Client ] fetches gateway's application/ohttp-keys blob
	// Note: ML-KEM-768 public keys are 1184 bytes (vs 32 bytes for X25519)
	const publicKeyConfig = KeyConfig.serializeMultiple([keyConfig, legacyKeyConfig]);

	// parseMultiple reports what the gateway published; select decides which of
	// those this suite can use. Reaching for [0] would pick by the gateway's
	// order, not by what the client implements.
	const configs = KeyConfig.parseMultiple(publicKeyConfig);
	const client = new OHTTPClient(suite, KeyConfig.select(suite, configs));

	return { gateway, client, publicKeyConfig };
}

export async function postQuantumOHTTP(): Promise<boolean> {
	// Protocol Setup
	//
	// [ Everybody ] agree to use Oblivious HTTP with ML-KEM-768, HKDF-SHA256, AES-128-GCM
	// ML-KEM-768 provides quantum-resistant key encapsulation
	const { gateway, client, publicKeyConfig } = await setup();

	console.log("ML-KEM-768 public key config size:", publicKeyConfig.byteLength, "bytes");

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
	const request = new TextEncoder().encode(
		"GET /quantum-safe HTTP/1.1\r\nHost: target.example\r\n\r\n",
	);
	const { encapsulatedRequest, context } = await client.encapsulate(request);

	// Note: ML-KEM-768 ciphertexts are 1088 bytes (vs 32 bytes for X25519)
	console.log("Encapsulated request size:", encapsulatedRequest.byteLength, "bytes");

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
	const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nQuantum-safe response");
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
