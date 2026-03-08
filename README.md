# ohttp-ts

[![NPM](https://img.shields.io/npm/v/ohttp-ts?style=flat-square)](https://www.npmjs.com/package/ohttp-ts)
[![License](https://img.shields.io/npm/l/ohttp-ts?style=flat-square)](LICENSE)

TypeScript implementation of Oblivious HTTP (OHTTP) with streaming support.

## Features

- **RFC 9458** - Oblivious HTTP (core protocol)
- **Chunked OHTTP** - Streaming extension ([draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt))
- **Incremental header** - ([draft-ietf-httpbis-incremental](https://www.ietf.org/archive/id/draft-ietf-httpbis-incremental-04.txt))
- **Multiple cipher suites** - X25519, P-256, P-384, P-521, ML-KEM-768
- **Multi-key server** - Key rotation support
- **WebCrypto** - Works in browsers, Workers, Node.js 18+

## Installation

```bash
npm install ohttp-ts hpke
# or
pnpm add ohttp-ts hpke
```

See [`examples/`](examples/) for complete examples.

## Quick Start

```typescript
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from "hpke";
import { KeyConfig, OHTTPClient, OHTTPServer, AeadId, KdfId } from "ohttp-ts";

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

// Encapsulate request
const request = new TextEncoder().encode("GET /resource HTTP/1.1\r\n\r\n");
const { encapsulatedRequest, context } = await client.encapsulate(request);

// Gateway: decapsulate and respond
const { request: decryptedRequest, context: serverContext } = 
  await gateway.decapsulate(encapsulatedRequest);
const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\nHello");
const encapsulatedResponse = await serverContext.encryptResponse(response);

// Client: decrypt response
const decryptedResponse = await context.decryptResponse(encapsulatedResponse);
```

### Protocol Flow (RFC 9458 Figure 1)

```
+---------+       +-------+       +---------+    +--------+
| Client  |       | Relay |       | Gateway |    | Target |
+----+----+       +---+---+       +----+----+    +---+----+
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

## Chunked OHTTP (Streaming)

For large payloads or streaming responses:

```typescript
import { ChunkedOHTTPClient, ChunkedOHTTPServer } from "ohttp-ts";

const gateway = new ChunkedOHTTPServer([keyConfig], { maxChunkSize: 16384 });
const client = new ChunkedOHTTPClient(suite, keyConfig, { maxChunkSize: 16384 });

// Client: encapsulate chunked request
const request = new TextEncoder().encode("POST /upload HTTP/1.1\r\n\r\n" + largeBody);
const { encapsulatedRequest, createResponseContext } = await client.encapsulate(request);

// Gateway: decapsulate and respond
const { request: decrypted, createResponseContext: serverCreateResponse } = 
  await gateway.decapsulate(encapsulatedRequest);
const responseCtx = await serverCreateResponse();
const encapsulatedResponse = await gateway.encapsulateResponse(responseCtx, response);

// Client: decrypt chunked response
const decryptedResponse = await client.decapsulateResponse(
  createResponseContext, 
  encapsulatedResponse
);
```

## API Reference

### KeyConfig

```typescript
// Generate new key pair
const keyConfig = await KeyConfig.generate(suite, keyId, algorithms);

// Derive deterministic key from seed (for testing)
const keyConfig = await KeyConfig.derive(suite, seed, keyId, algorithms);

// Parse from bytes (public config only)
const keyConfig = KeyConfig.parse(bytes);

// Parse application/ohttp-keys format (multiple configs)
const configs = KeyConfig.parseMultiple(bytes);

// Serialize to bytes
const bytes = KeyConfig.serialize(keyConfig);

// Serialize multiple to application/ohttp-keys format
const bytes = KeyConfig.serializeMultiple(configs);
```

### Algorithm IDs

```typescript
import { KemId, KdfId, AeadId } from "ohttp-ts";

// KEM algorithms
KemId.P256_HKDF_SHA256    // 0x0010
KemId.P384_HKDF_SHA384    // 0x0011
KemId.P521_HKDF_SHA512    // 0x0012
KemId.X25519_HKDF_SHA256  // 0x0020
KemId.X448_HKDF_SHA512    // 0x0021

// KDF algorithms
KdfId.HKDF_SHA256  // 0x0001
KdfId.HKDF_SHA384  // 0x0002
KdfId.HKDF_SHA512  // 0x0003

// AEAD algorithms
AeadId.AES_128_GCM      // 0x0001
AeadId.AES_256_GCM      // 0x0002
AeadId.ChaCha20Poly1305 // 0x0003 (parsing only, not implemented)
```

### Media Types

```typescript
import { MediaType } from "ohttp-ts";

MediaType.KEYS              // "application/ohttp-keys"
MediaType.REQUEST           // "message/ohttp-req"
MediaType.RESPONSE          // "message/ohttp-res"
MediaType.CHUNKED_REQUEST   // "message/ohttp-chunked-req"
MediaType.CHUNKED_RESPONSE  // "message/ohttp-chunked-res"
```

### Incremental Header

```typescript
import { Incremental } from "ohttp-ts";

// Parse header value
const isIncremental = Incremental.parse("?1");  // true

// Set on Headers object
Incremental.set(headers, true);

// Get from Headers object
const value = Incremental.get(headers);  // true | false | undefined
```

### Error Handling

```typescript
import { OHTTPError, OHTTPErrorCode, isOHTTPError } from "ohttp-ts";

try {
  await gateway.decapsulate(malformedRequest);
} catch (e) {
  if (isOHTTPError(e)) {
    switch (e.code) {
      case OHTTPErrorCode.DecryptionFailed:
        // Opaque error - no details leaked
        break;
      case OHTTPErrorCode.UnknownKeyId:
        // Key not found
        break;
    }
  }
}
```

## Development

```bash
pnpm install
pnpm build
pnpm test
pnpm bench
```

## Security Considerations

**Not audited.** Use at your own risk.

- **Replay protection** is out of scope (RFC 9458 Section 6.5). Server applications should implement anti-replay mechanisms.
- **Decryption errors are opaque** - no details leaked to prevent oracle attacks.
- **Constant-time operations** used where applicable.

## Dependencies

| Package | Purpose |
|---------|---------|
| [hpke](https://www.npmjs.com/package/hpke) | HPKE (RFC 9180) - WebCrypto |
| [@dajiaji/bhttp](https://www.npmjs.com/package/@dajiaji/bhttp) | Binary HTTP (RFC 9292) |
| [@panva/hpke-noble](https://www.npmjs.com/package/@panva/hpke-noble) | ML-KEM (post-quantum) |
| [quicvarint](https://www.npmjs.com/package/quicvarint) | QUIC variable-length integers |

## License

MIT

## Contributing

Contributions welcome. Any contribution submitted for inclusion shall be MIT licensed without additional terms.
