# ohttp-ts

[![NPM](https://img.shields.io/npm/v/ohttp-ts?style=flat-square)](https://www.npmjs.com/package/ohttp-ts)
[![License](https://img.shields.io/npm/l/ohttp-ts?style=flat-square)](LICENSE)

TypeScript implementation of [Oblivious HTTP (RFC 9458)](https://www.rfc-editor.org/rfc/rfc9458.html) with streaming support.

## Features

- **RFC 9458** - Oblivious HTTP
- **Chunked OHTTP** - Streaming extension ([draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt))
- **WebCrypto** - Works in browsers, Cloudflare Workers, Node.js 22+

## Installation

```bash
npm install ohttp-ts hpke
```

## Quick Start

```typescript
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer, KdfId, AeadId } from "ohttp-ts";

// Gateway: generate key configuration
const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const keyConfig = await KeyConfig.generate(suite, 0x01, [
  { kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);
const gateway = new OHTTPServer([keyConfig]);

// Client: fetch and parse gateway's public key
const publicKeyBytes = KeyConfig.serialize(keyConfig);
const clientKeyConfig = KeyConfig.parse(publicKeyBytes);
const client = new OHTTPClient(suite, clientKeyConfig);

// Client: encapsulate HTTP request
const httpRequest = new Request("https://target.example/api", {
  method: "POST",
  body: JSON.stringify({ data: "sensitive" }),
});
const { request: relayRequest, context } = await client.encapsulateRequest(
  httpRequest,
  "https://relay.example/ohttp",
);

// Send to relay: fetch(relayRequest)

// Gateway: decapsulate request
const { request: innerRequest, context: serverContext } = await gateway.decapsulateRequest(relayRequest);
// innerRequest is the original Request object

// Gateway: encapsulate response
const httpResponse = new Response(JSON.stringify({ result: "ok" }), { status: 200 });
const encapsulatedResponse = await serverContext.encapsulateResponse(httpResponse);

// Client: decapsulate response
const innerResponse = await context.decapsulateResponse(encapsulatedResponse);
// innerResponse is the original Response object
```

### Protocol Flow

```
+---------+       +-------+       +---------+    +--------+
| Client  |       | Relay |       | Gateway |    | Target |
+---------+       +-------+       +---------+    +--------+
     |                |                |             |
     | Encapsulated   |                |             |
     | Request        |                |             |
     +--------------->| Forward        |             |
     |                +--------------->| Decrypt &   |
     |                |                | Forward     |
     |                |                +------------>|
     |                |                |             |
     |                |                |<------------+
     |                |                | Encrypt     |
     |                |<---------------+ Response    |
     |<---------------+                |             |
     | Decapsulated   |                |             |
     | Response       |                |             |
```

## Binary HTTP

OHTTP encapsulates [Binary HTTP (RFC 9292)](https://www.rfc-editor.org/rfc/rfc9292.html) messages. The high-level API (`encapsulateRequest`, `decapsulateRequest`, etc.) handles encoding automatically.

For advanced use cases, the low-level bytes API is also available:

```typescript
// Low-level API: work with raw Binary HTTP bytes
const { encapsulatedRequest, context } = await client.encapsulate(binaryHttpBytes);
const { request: binaryBytes, context: serverCtx } = await gateway.decapsulate(encapsulatedRequest);
```

See [`examples/bhttp.example.ts`](examples/bhttp.example.ts) for a complete example.

## Examples

| Example | Description |
|---------|-------------|
| [`ohttp.example.ts`](examples/ohttp.example.ts) | Basic OHTTP round-trip |
| [`chunked.example.ts`](examples/chunked.example.ts) | Streaming with chunked OHTTP |
| [`bhttp.example.ts`](examples/bhttp.example.ts) | Request/Response API |
| [`mlkem.example.ts`](examples/mlkem.example.ts) | Post-quantum with ML-KEM-768 |

## Post-Quantum Support

For post-quantum key encapsulation (ML-KEM), use `@panva/hpke-noble`:

```bash
npm install @panva/hpke-noble
```

```typescript
import { CipherSuite } from "hpke";
import { KEM_ML_KEM_768, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from "@panva/hpke-noble";

const suite = new CipherSuite(KEM_ML_KEM_768, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
// Use with KeyConfig.generate(), OHTTPClient, OHTTPServer as usual
```

## Security Considerations

**Not audited.** Use at your own risk.

- **Replay protection** is out of scope (RFC 9458 Section 6.5)
- **Decryption errors are opaque** to prevent oracle attacks

## License

MIT
