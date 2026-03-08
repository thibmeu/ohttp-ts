// Copyright (c) 2024
// Licensed under the MIT license

// Example: Using Binary HTTP (RFC 9292) with OHTTP
//
// This example shows how to use @dajiaji/bhttp to encode HTTP Request/Response
// objects before passing them to ohttp-ts.
//
// Install: pnpm add @dajiaji/bhttp

import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { BHttpDecoder, BHttpEncoder } from "@dajiaji/bhttp";
import { AeadId, KdfId, KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";

// Follows RFC 9458 Oblivious HTTP + RFC 9292 Binary HTTP

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

	// Binary HTTP encoder/decoder (RFC 9292)
	const encoder = new BHttpEncoder();
	const decoder = new BHttpDecoder();

	return { gateway, client, encoder, decoder };
}

export async function obliviousHTTPWithBinaryHTTP(): Promise<boolean> {
	// Protocol Setup
	//
	// [ Everybody ] agree to use Oblivious HTTP with DHKEM(X25519), HKDF-SHA256, AES-128-GCM
	// [ Everybody ] use Binary HTTP (RFC 9292) to encode HTTP messages
	const { gateway, client, encoder, decoder } = await setup();

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

	// [ Client ] creates HTTP request and encodes to Binary HTTP
	const httpRequest = new Request("https://target.example.com/api/data", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: "Bearer secret-token",
		},
		body: JSON.stringify({ query: "sensitive data" }),
	});
	const binaryRequest = await encoder.encodeRequest(httpRequest);
	const { encapsulatedRequest, context } = await client.encapsulate(binaryRequest);

	//      +---------------->| Gateway          |              |
	//      |                 | Request          |              |
	//      |                 | [+ Encapsulated  |              |
	//      |                 |    Request ]     |              |
	//      |                 +----------------->| Request      |

	// [ Gateway ] decapsulates and decodes Binary HTTP to forward
	const { request: decryptedBinary, context: serverContext } =
		await gateway.decapsulate(encapsulatedRequest);
	const forwardRequest = decoder.decodeRequest(decryptedBinary);

	//      |                 |                  +------------->|
	//      |                 |                  |              |
	//      |                 |                  |     Response |
	//      |                 |          Gateway |<-------------+
	//      |                 |         Response |              |
	//      |                 |  [+ Encapsulated |              |
	//      |                 |       Response ] |              |

	// [ Target ] processes request and returns response
	const httpResponse = new Response(JSON.stringify({ result: "success" }), {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});

	// [ Gateway ] encodes response to Binary HTTP and encapsulates
	const binaryResponse = await encoder.encodeResponse(httpResponse);
	const encapsulatedResponse = await serverContext.encryptResponse(binaryResponse);

	//      |           Relay |<-----------------+              |
	//      |        Response |                  |              |
	//      | [+ Encapsulated |                  |              |
	//      |      Response ] |                  |              |
	//      |<----------------+                  |              |
	//      |                 |                  |              |

	// [ Client ] decapsulates and decodes Binary HTTP response
	const decryptedResponse = await context.decryptResponse(encapsulatedResponse);
	const finalResponse = decoder.decodeResponse(decryptedResponse);

	// Verify round-trip
	const requestMatch =
		forwardRequest.url === httpRequest.url && forwardRequest.method === httpRequest.method;
	const responseMatch = finalResponse.status === 200;

	return requestMatch && responseMatch;
}
