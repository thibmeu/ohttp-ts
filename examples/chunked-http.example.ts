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
	const { init, context } = await client.encapsulateRequest(originalRequest);

	// init is a RequestInit ready to use with fetch() or new Request()
	// In production: const relayResponse = await fetch("https://relay.example.com/ohttp", init);
	const relayRequest = new Request("https://relay.example.com/ohttp", init);

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
 * Example: Streaming large body through chunked OHTTP
 *
 * Demonstrates that the body streams through without full buffering.
 * The client/gateway can start processing before the entire body arrives.
 *
 * Note: Chunk boundaries are NOT preserved through the streaming pipeline.
 * Data flows through multiple transforms (chunker, encryption, BHTTP, decryption)
 * and chunks get reassembled. Only total content integrity is guaranteed.
 */
export async function chunkedHttpLargeBody(): Promise<boolean> {
	const { gateway, client } = await setup();

	// Create a streaming source that yields chunks incrementally
	// Each 10KB chunk is filled with a repeating pattern for verification
	const chunkCount = 10;
	const chunkSize = 10 * 1024; // 10KB per chunk = 100KB total
	let chunksProduced = 0;
	let byteIndex = 0;

	const sourceStream = new ReadableStream<Uint8Array>({
		pull(controller) {
			if (chunksProduced >= chunkCount) {
				controller.close();
				return;
			}
			// Fill chunk with sequential byte values (mod 256) for verification
			const chunk = new Uint8Array(chunkSize);
			for (let i = 0; i < chunkSize; i++) {
				chunk[i] = (byteIndex + i) % 256;
			}
			byteIndex += chunkSize;
			chunksProduced++;
			controller.enqueue(chunk);
		},
	});

	const originalRequest = new Request("https://storage.example.com/upload", {
		method: "PUT",
		headers: { "Content-Type": "application/octet-stream" },
		body: sourceStream,
		// @ts-expect-error - duplex required for streaming request bodies in Node.js
		duplex: "half",
	});

	// Encapsulate - body streams through chunked OHTTP encryption
	const { init, context } = await client.encapsulateRequest(originalRequest);

	// In production: const relayResponse = await fetch("https://relay.example.com/ohttp", init);
	const relayRequest = new Request("https://relay.example.com/ohttp", init);

	// Decapsulate - body streams through decryption
	const { request: innerRequest, context: serverContext } =
		await gateway.decapsulateRequest(relayRequest);

	// Consume the streaming body incrementally
	// This demonstrates we can process chunks as they arrive
	let totalBytes = 0;
	let receivedByteIndex = 0;
	let valid = true;

	const body = innerRequest.body;
	if (body === null) {
		return false;
	}

	// Process body as it streams - verify content byte-by-byte
	for await (const chunk of body) {
		for (let i = 0; i < chunk.length; i++) {
			if (chunk[i] !== (receivedByteIndex + i) % 256) {
				valid = false;
				break;
			}
		}
		receivedByteIndex += chunk.length;
		totalBytes += chunk.length;
	}

	const expectedTotal = chunkCount * chunkSize;
	const uploadValid = valid && totalBytes === expectedTotal;

	// Server responds with streaming body
	const responseSize = 5 * 1024;
	let responseByteIndex = 0;
	const responseStream = new ReadableStream<Uint8Array>({
		pull(controller) {
			if (responseByteIndex >= responseSize) {
				controller.close();
				return;
			}
			const remaining = responseSize - responseByteIndex;
			const chunkLen = Math.min(1024, remaining);
			const chunk = new Uint8Array(chunkLen);
			for (let i = 0; i < chunkLen; i++) {
				chunk[i] = (responseByteIndex + i) % 256;
			}
			responseByteIndex += chunkLen;
			controller.enqueue(chunk);
		},
	});

	const serverResponse = new Response(responseStream, {
		status: 200,
		headers: { "Content-Type": "application/octet-stream" },
	});
	const encapsulatedResponse = await serverContext.encapsulateResponse(serverResponse);

	// Client decapsulates and consumes streaming response
	const finalResponse = await context.decapsulateResponse(encapsulatedResponse);

	let responseBytesReceived = 0;
	let responseReceivedIndex = 0;
	const responseBody = finalResponse.body;
	if (responseBody === null) {
		return false;
	}

	// Verify response content byte-by-byte
	for await (const chunk of responseBody) {
		for (let i = 0; i < chunk.length; i++) {
			if (chunk[i] !== (responseReceivedIndex + i) % 256) {
				valid = false;
				break;
			}
		}
		responseReceivedIndex += chunk.length;
		responseBytesReceived += chunk.length;
	}

	return uploadValid && valid && responseBytesReceived === responseSize;
}
