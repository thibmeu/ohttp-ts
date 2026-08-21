# ohttp-ts

[![NPM](https://img.shields.io/npm/v/ohttp-ts?style=flat-square)](https://www.npmjs.com/package/ohttp-ts)
[![License](https://img.shields.io/npm/l/ohttp-ts?style=flat-square)](LICENSE)

TypeScript implementation of [Oblivious HTTP (RFC 9458)](https://www.rfc-editor.org/rfc/rfc9458.html) with streaming support.

## Features

- **RFC 9458** - Oblivious HTTP
- **Chunked OHTTP** - Streaming extension ([draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt))
- **WebCrypto** - Works in browsers, Cloudflare Workers, and Node.js
- **Pluggable crypto** - Supply your own response KDF/AEAD factories for any other environment or cryptographic constraint (see [Response Encryption](#response-encryption))

## Installation

```bash
npm install ohttp-ts hpke
```

Or via CDN (no install):

```javascript
import { KeyConfig, OHTTPClient, OHTTPServer } from "https://esm.sh/ohttp-ts";
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from "https://esm.sh/hpke";
```

## Quick Start

```typescript
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer } from "ohttp-ts";

// Gateway: generate key configuration
const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
// The config advertises the suite's own (KDF, AEAD) pair; that is the only pair
// the gateway can decrypt with, so there is nothing to pass.
const keyConfig = await KeyConfig.generate(suite, 0x01);
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
const { init, context } = await client.encapsulateRequest(httpRequest);

// Send to relay
const relayResponse = await fetch("https://relay.example/ohttp", init);

// Gateway: decapsulate request (received from relay)
const { request: innerRequest, context: serverContext } = await gateway.decapsulateRequest(relayRequest);
// relayRequest is what the relay receives and forwards to the gateway
// innerRequest is the original Request object

// Gateway: encapsulate response
const httpResponse = new Response(JSON.stringify({ result: "ok" }), { status: 200 });
const encapsulatedResponse = await serverContext.encapsulateResponse(httpResponse);

// Client: decapsulate response
const innerResponse = await context.decapsulateResponse(relayResponse);
// innerResponse is the original Response object
```

### Gateway Key Configuration

`KeyConfig.parse` reads a single serialized config, which is what the Quick Start
passes it. A gateway's `application/ohttp-keys` resource is a *list*, and it may
name algorithms this client does not implement - during a post-quantum
migration, for instance. Use `parseMultiple` to read the list and `select` to
pick a config the client's suite can actually use:

```typescript
const response = await fetch("https://gateway.example/.well-known/ohttp-gateway");
const configs = KeyConfig.parseMultiple(new Uint8Array(await response.arrayBuffer()));

// Configs naming algorithms this library lacks are skipped, so `configs` may be
// empty. `select` throws UnsupportedCipherSuite when none match the suite -
// re-fetch, try another suite, or fall back to a direct request.
const client = new OHTTPClient(suite, KeyConfig.select(suite, configs));
```

Do not reach for `configs[0]`: it picks by the gateway's order, not by what the
client implements, and hands you a config for the wrong KEM as readily as the
right one.

On the gateway side, one key configuration can advertise several `(KDF, AEAD)`
pairs under a single key identifier, as RFC 9458 Appendix A does. Pass the
suites it should serve, all sharing one KEM, and the advertised algorithms are
derived from them:

```typescript
const keyConfig = await KeyConfig.generate(
  [
    new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM),
    new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305),
  ],
  0x01,
);
const gateway = new OHTTPServer([keyConfig]);
```

One key pair covers every suite, since it belongs to the KEM they share. Each
request header names the pair it used and the gateway decrypts with the matching
suite. A config can only advertise what its suites can open, so the gateway
cannot publish a pair it will then reject.

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

This library encapsulates and decapsulates; it never sends anything. Each hop
is a `fetch()` you make yourself, which is what keeps relay and gateway
authentication - mTLS, bearer tokens, whatever your deployment needs - out of
the library and under your control.

## Binary HTTP

OHTTP encapsulates [Binary HTTP (RFC 9292)](https://www.rfc-editor.org/rfc/rfc9292.html) messages. The high-level API (`encapsulateRequest`, `decapsulateRequest`, etc.) handles encoding automatically.

For advanced use cases, the low-level bytes API is also available:

```typescript
// Low-level API: work with raw Binary HTTP bytes
const { encapsulatedRequest, context } = await client.encapsulate(binaryHttpBytes);
const { request: binaryBytes, context: serverCtx } = await gateway.decapsulate(encapsulatedRequest);
```

See [`examples/bhttp.example.ts`](examples/bhttp.example.ts) for a complete example.

### Chunked OHTTP (Streaming)

Use chunked OHTTP when:
- **Large payloads** (>1MB) that would exceed memory limits
- **Incremental sources** - data arrives over time (file uploads, network streams)
- **Early processing** - need to start processing before full body arrives
- **Memory-constrained** - Workers (128MB), mobile, edge

Use normal OHTTP when:
- **Small payloads** (<100KB)
- **Need full body** - JSON.parse(), image processing, etc.
- **Latency-sensitive** - streaming has async overhead

```typescript
// Normal: ~3x payload memory, faster for in-memory data
const client = new OHTTPClient(suite, keyConfig);

// Chunked: ~64KB constant memory, better for large/streaming data
const client = new ChunkedOHTTPClient(suite, keyConfig);
```

For streaming large requests/responses, use `ChunkedOHTTPClient`/`ChunkedOHTTPServer`:

```typescript
import { ChunkedOHTTPClient, ChunkedOHTTPServer, type StreamingRequestInit } from "ohttp-ts";

// Setup (same key configuration as above)
const gateway = new ChunkedOHTTPServer([keyConfig]);
const client = new ChunkedOHTTPClient(suite, keyConfig);

// Client: encapsulate streaming request
// StreamingRequestInit supplies the duplex the DOM lib types still lack
const uploadInit: StreamingRequestInit = {
  method: "POST",
  body: largeReadableStream,
  duplex: "half",
};
const streamingRequest = new Request("https://target.example/upload", uploadInit);
const { init, context } = await client.encapsulateRequest(streamingRequest);

// Send to relay (init includes duplex: "half" for streaming)
const relayResponse = await fetch("https://relay.example/ohttp", init);

// Gateway: decapsulate (body streams through)
// relayRequest is what the relay receives and forwards to the gateway
const { request: innerRequest, context: serverContext } =
  await gateway.decapsulateRequest(relayRequest);

// Process body incrementally
for await (const chunk of innerRequest.body!) {
  // Process chunk without buffering entire body
}

// Gateway: stream response back
const streamingResponse = new Response(responseStream, { status: 200 });
const encapsulatedResponse = await serverContext.encapsulateResponse(streamingResponse);

// Client: decapsulate and consume streaming response
const finalResponse = await context.decapsulateResponse(relayResponse);
for await (const chunk of finalResponse.body!) {
  // Process chunk as it arrives
}
```

**Note**: Request/Response bodies stream through without full buffering. Only the BHTTP preamble (method/status, headers) is buffered before the body can flow.

For the low-level bytes API, see [`examples/chunked.example.ts`](examples/chunked.example.ts).

## Examples

| Example | Description |
|---------|-------------|
| [`ohttp.example.ts`](examples/ohttp.example.ts) | Basic OHTTP round-trip |
| [`chunked-http.example.ts`](examples/chunked-http.example.ts) | Streaming Request/Response API |
| [`chunked.example.ts`](examples/chunked.example.ts) | Low-level bytes API |
| [`bhttp.example.ts`](examples/bhttp.example.ts) | Request/Response API (non-streaming) |
| [`mlkem.example.ts`](examples/mlkem.example.ts) | Post-quantum with ML-KEM-768 |
| [`response-chacha.example.ts`](examples/response-chacha.example.ts) | ChaCha20-Poly1305 response via a custom crypto factory |

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

A gateway migrating to ML-KEM publishes both keys for a while, so read its list
with `KeyConfig.parseMultiple` and pick with `KeyConfig.select` rather than
assuming which one comes first. See [Gateway Key Configuration](#gateway-key-configuration)
and `examples/mlkem.example.ts`.

## Response Encryption

OHTTP responses are not HPKE: the response key is derived with HKDF over an
HPKE-exported secret and then used with a raw AEAD ([RFC 9458 Section 4.4](https://www.rfc-editor.org/rfc/rfc9458.html#name-encapsulation-of-responses)). By
default these primitives are resolved from the suite using hpke's built-in
(WebCrypto-backed) factories.

Pass non-WebCrypto factories via the `responseCrypto` option (the same pattern
as swapping the KEM above) when the default doesn't fit.
Bellow is an example to set ChaCha20-Poly1305 implementation:

```typescript
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { AEAD_ChaCha20Poly1305, KDF_HKDF_SHA256 } from "@panva/hpke-noble";

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305);
const responseCrypto = { aead: AEAD_ChaCha20Poly1305 };

const gateway = new OHTTPServer([keyConfig], { responseCrypto });
const client = new OHTTPClient(suite, clientKeyConfig, { responseCrypto });
```

The override is byte-compatible with the default factory, so a client and
gateway may use a different implementation for the same algorithm.

A gateway serving several AEADs under one key identifier passes one factory per
algorithm, since which one a response uses is decided by the request header, not
by the server:

```typescript
const gateway = new OHTTPServer([keyConfig], {
  responseCrypto: { aead: [AEAD_AES_128_GCM, AEAD_ChaCha20Poly1305] },
});
```

An override with no factory for an algorithm this side serves throws
`UnsupportedCipherSuite` rather than falling back, so a missing entry surfaces
instead of quietly ignoring what you passed.

## Security Considerations

**Not audited.** Use at your own risk.

- **Replay protection** is out of scope ([RFC 9458 Section 6.5](https://www.rfc-editor.org/rfc/rfc9458.html#name-replay-attacks))
- **Decryption errors are opaque** to prevent oracle attacks

### Gateway error handling

Every failure is an `OHTTPError` carrying a code: `InvalidKeyConfig`,
`UnknownKeyId`, `UnsupportedCipherSuite`, `DecryptionFailed`,
`EncryptionFailed`, `InvalidMessage`, and the two chunked sequence codes. Keep
that detail for your own logs and answer the relay with a plain 400, as
[RFC 9458 Section 4.3](https://www.rfc-editor.org/rfc/rfc9458.html#name-request-decapsulation)
requires of any decapsulation failure:

```typescript
import { isOHTTPError } from "ohttp-ts";

try {
  const { request, context } = await gateway.decapsulateRequest(ohttpRequest);
  return await context.encapsulateResponse(await fetch(request));
} catch (err) {
  if (isOHTTPError(err)) return new Response(null, { status: 400 });
  throw err;
}
```

## License

MIT
