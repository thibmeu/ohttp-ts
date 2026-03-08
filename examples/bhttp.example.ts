// Copyright (c) 2024
// Licensed under the MIT license

// Example: Oblivious HTTP with Request/Response API
//
// This example shows the high-level API that handles Binary HTTP encoding
// automatically. The library encodes Request/Response objects internally.

import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
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

	return { gateway, client };
}

export async function obliviousHTTPWithRequestResponse(): Promise<boolean> {
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

	// [ Client ] creates HTTP request and encapsulates it
	const httpRequest = new Request("https://target.example.com/api/data", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: "Bearer secret-token",
		},
		body: JSON.stringify({ query: "sensitive data" }),
	});

	// encapsulateRequest handles Binary HTTP encoding internally
	const { request: relayRequest, context: clientContext } = await client.encapsulateRequest(
		httpRequest,
		"https://relay.example.com/ohttp",
	);

	// relayRequest is ready to send: POST with Content-Type: message/ohttp-req

	//      +---------------->| Gateway          |              |
	//      |                 | Request          |              |
	//      |                 | [+ Encapsulated  |              |
	//      |                 |    Request ]     |              |
	//      |                 +----------------->| Request      |

	// [ Gateway ] decapsulates to get the inner HTTP request
	const { request: innerRequest, context: serverContext } =
		await gateway.decapsulateRequest(relayRequest);

	// innerRequest is the original Request object
	const body = await innerRequest.json();
	console.log("Gateway received:", innerRequest.method, innerRequest.url, body);

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

	// [ Gateway ] encapsulates the response
	const encapsulatedResponse = await serverContext.encapsulateResponse(httpResponse);

	// encapsulatedResponse is ready to return: 200 with Content-Type: message/ohttp-res

	//      |           Relay |<-----------------+              |
	//      |        Response |                  |              |
	//      | [+ Encapsulated |                  |              |
	//      |      Response ] |                  |              |
	//      |<----------------+                  |              |
	//      |                 |                  |              |

	// [ Client ] decapsulates to get the inner HTTP response
	const innerResponse = await clientContext.decapsulateResponse(encapsulatedResponse);

	// innerResponse is the original Response object
	const responseBody = await innerResponse.json();
	console.log("Client received:", innerResponse.status, responseBody);

	// Verify round-trip
	const requestMatch =
		innerRequest.url === httpRequest.url && innerRequest.method === httpRequest.method;
	const responseMatch = innerResponse.status === 200;

	return requestMatch && responseMatch;
}
