// Copyright (c) 2024
// Licensed under the MIT license

import { CipherSuite } from "hpke";
import { AEAD_AES_128_GCM, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "@panva/hpke-noble";
import {
	AeadId,
	ChunkedOHTTPClient,
	ChunkedOHTTPServer,
	KdfId,
	KeyConfig,
} from "../src/index.js";

// Follows draft-ietf-ohai-chunked-ohttp-08

async function setup() {
	const suite = new CipherSuite(
		KEM_DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
	);
	const keyConfig = await KeyConfig.generate(suite, 0x01, [
		{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
	]);

	// Use custom chunk size for demonstration
	const gateway = new ChunkedOHTTPServer([keyConfig], { maxChunkSize: 64 });
	const client = new ChunkedOHTTPClient(suite, keyConfig, { maxChunkSize: 64 });

	return { gateway, client };
}

export async function chunkedOHTTP(): Promise<boolean> {
	// Protocol Setup
	//
	// [ Everybody ] agree to use Chunked Oblivious HTTP
	const { gateway, client } = await setup();

	// Online Protocol (draft-08 Figure 1)
	//
	// Client                        Relay                       Gateway
	//   |                             |                             |
	//   |          Relay Request      |                             |
	//   |   [+ Encapsulated Request   |                             |
	//   |           (chunk 1 ... N) ] |                             |
	const request = new TextEncoder().encode(
		"POST /upload HTTP/1.1\r\n\r\n" + "X".repeat(200), // Large enough to chunk
	);
	const { encapsulatedRequest, createResponseContext } = await client.encapsulate(request);
	//   +---------------------------->|       Gateway Request       |
	//   |                             |   [+ Encapsulated Request   |
	//   |                             |           (chunk 1 ... N) ] |
	//   |                             +---------------------------->|
	//   |                             |                             |
	const { request: decryptedRequest, createResponseContext: serverCreateResponse } =
		await gateway.decapsulate(encapsulatedRequest);
	//   |                             |                             |
	//   |                             |        Gateway Response     |
	//   |                             |  [+ Encapsulated Response   |
	//   |                             |           (chunk 1 ... M) ] |
	const response = new TextEncoder().encode(
		"HTTP/1.1 200 OK\r\n\r\n" + "Y".repeat(150), // Large enough to chunk
	);
	const responseCtx = await serverCreateResponse();
	const encapsulatedResponse = await gateway.encapsulateResponse(responseCtx, response);
	//   |        Relay Response       |<----------------------------+
	//   |  [+ Encapsulated Response   |                             |
	//   |           (chunk 1 ... M) ] |                             |
	//   |<----------------------------+                             |
	//   |                             |                             |
	const decryptedResponse = await client.decapsulateResponse(
		createResponseContext,
		encapsulatedResponse,
	);

	const requestMatch =
		new TextDecoder().decode(decryptedRequest) === new TextDecoder().decode(request);
	const responseMatch =
		new TextDecoder().decode(decryptedResponse) === new TextDecoder().decode(response);

	return requestMatch && responseMatch;
}
