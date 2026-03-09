// Copyright (c) 2024
// Licensed under the MIT license

/**
 * Chunked OHTTP with HTTP Request/Response API
 *
 * Demonstrates the high-level API that handles Binary HTTP encoding/decoding
 * automatically, providing a clean Request/Response interface.
 */

import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { AeadId, ChunkedOHTTPClient, ChunkedOHTTPServer, KdfId, KeyConfig } from "../src/index.js";

async function setup() {
	const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const keyConfig = await KeyConfig.generate(suite, 0x01, [
		{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
	]);

	const gateway = new ChunkedOHTTPServer([keyConfig]);
	const client = new ChunkedOHTTPClient(suite, keyConfig);

	return { gateway, client };
}

/**
 * Example: Simple JSON API request through chunked OHTTP
 */
export async function chunkedHttpApi(): Promise<boolean> {
	const { gateway, client } = await setup();

	// Client creates a normal HTTP Request
	const originalRequest = new Request("https://api.example.com/v1/data", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: "Bearer secret-token",
		},
		body: JSON.stringify({ query: "What is OHTTP?", limit: 10 }),
	});

	// Client encapsulates the request for the relay
	// This automatically:
	// 1. Encodes the Request to streaming Binary HTTP
	// 2. Encrypts using chunked OHTTP
	const { request: relayRequest, context } = await client.encapsulateRequest(
		originalRequest,
		"https://relay.example.com/ohttp",
	);

	// In production: send relayRequest to relay, relay forwards to gateway
	// Here we simulate direct delivery to gateway

	// Gateway decapsulates the request
	// This automatically:
	// 1. Decrypts chunked OHTTP
	// 2. Decodes streaming Binary HTTP to Request
	const { request: innerRequest, context: serverContext } =
		await gateway.decapsulateRequest(relayRequest);

	// Verify the request was correctly reconstructed
	const reconstructedBody = await innerRequest.json();
	const requestValid =
		innerRequest.method === "POST" &&
		innerRequest.url === "https://api.example.com/v1/data" &&
		innerRequest.headers.get("Content-Type") === "application/json" &&
		innerRequest.headers.get("Authorization") === "Bearer secret-token" &&
		reconstructedBody.query === "What is OHTTP?" &&
		reconstructedBody.limit === 10;

	// Gateway processes request and creates response
	const serverResponse = new Response(
		JSON.stringify({
			answer: "OHTTP provides request privacy through relay architecture",
			sources: 3,
		}),
		{
			status: 200,
			headers: { "Content-Type": "application/json" },
		},
	);

	// Gateway encapsulates the response
	const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);

	// In production: gateway sends to relay, relay sends to client
	// Here we simulate direct delivery

	// Client decapsulates the response
	const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

	// Verify the response
	const responseBody = await finalResponse.json();
	const responseValid =
		finalResponse.status === 200 &&
		finalResponse.headers.get("Content-Type") === "application/json" &&
		responseBody.answer.includes("OHTTP") &&
		responseBody.sources === 3;

	return requestValid && responseValid;
}

/**
 * Example: Large file upload through chunked OHTTP
 */
export async function chunkedHttpLargeBody(): Promise<boolean> {
	const { gateway, client } = await setup();

	// Simulate a large upload (100KB)
	const largePayload = "X".repeat(100 * 1024);

	const originalRequest = new Request("https://storage.example.com/upload", {
		method: "PUT",
		headers: { "Content-Type": "application/octet-stream" },
		body: largePayload,
	});

	// The chunked OHTTP will automatically split this into encrypted chunks
	const { request: relayRequest, context } = await client.encapsulateRequest(
		originalRequest,
		"https://relay.example.com/ohttp",
	);

	const { request: innerRequest, context: serverContext } =
		await gateway.decapsulateRequest(relayRequest);

	// Verify large body was transmitted correctly
	const receivedBody = await innerRequest.text();
	const uploadValid = receivedBody === largePayload;

	// Server responds
	const serverResponse = new Response(null, { status: 204 });
	const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);
	const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

	return uploadValid && finalResponse.status === 204;
}
