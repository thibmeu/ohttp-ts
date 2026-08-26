import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { ChunkedOHTTPClient, ChunkedOHTTPServer, KeyConfig } from "../src/index.ts";

export async function readmeQuickStart(): Promise<unknown> {
	const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const keyConfig = await KeyConfig.generate(suite, 0x01);
	const gateway = new ChunkedOHTTPServer([keyConfig]);
	const publicConfig = KeyConfig.parse(KeyConfig.serialize(keyConfig));
	const client = new ChunkedOHTTPClient(suite, publicConfig);

	const originalRequest = new Request("https://target.example/api", {
		method: "POST",
		body: JSON.stringify({ data: "sensitive" }),
	});
	const { init, context: clientContext } = await client.encapsulateRequest(originalRequest);
	const relayRequest = new Request("https://gateway.example/ohttp", init);
	const { request: innerRequest, context: gatewayContext } =
		await gateway.decapsulateRequest(relayRequest);
	const innerResponse = new Response(JSON.stringify({ received: await innerRequest.json() }), {
		headers: { "Content-Type": "application/json" },
	});
	const encapsulatedResponse = await gatewayContext.encapsulateResponse(innerResponse);
	const response = await clientContext.decapsulateResponse(encapsulatedResponse);
	return response.json();
}
