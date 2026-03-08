# OHTTP-TS Agent Guidelines

TypeScript implementation of Oblivious HTTP with chunked extension support.

## Specifications

| Spec | Link | Status |
|------|------|--------|
| RFC 9458 | https://www.rfc-editor.org/rfc/rfc9458.txt | Standards Track |
| Chunked OHTTP | https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt | Draft |
| Incremental | https://www.ietf.org/archive/id/draft-ietf-httpbis-incremental-04.txt | Draft |

## Architecture

```
packages/ohttp-ts/src/
├── index.ts           # unified exports
├── keyConfig.ts       # KeyConfig parse/serialize/fromSeed
├── client.ts          # OHTTPClient - request encapsulation
├── server.ts          # OHTTPServer - multi-key gateway
├── encapsulation.ts   # HPKE setup, encrypt/decrypt primitives
├── chunked.ts         # streaming chunked OHTTP (AsyncGenerator)
├── incremental.ts     # Incremental header field parser
├── errors.ts          # opaque error types
└── utils.ts           # hex, constant-time compare
```

## Key Design Decisions

### Labels
- Core OHTTP: `"message/bhttp request"` / `"message/bhttp response"` (RFC 9458 §4.3-4.4)
- Chunked OHTTP: `"message/bhttp chunked request"` / `"message/bhttp chunked response"` (draft-08 §6.1-6.2)
- Custom labels supported via `requestLabel`/`responseLabel` options

### Cipher Suites
Default supported (RFC 9458 §3.1):
- KEM: X25519 (0x0020), X448 (0x0021), ML-KEM-768 (TBD via @panva/hpke-noble)
- KDF: HKDF-SHA256 (0x0001)
- AEAD: AES-128-GCM (0x0001), ChaCha20Poly1305 (0x0003)

### KeyConfig Wire Format
- `application/ohttp-keys`: 2-byte length prefix + KeyConfig (RFC 9458 §3.2)
- KeyConfig: keyId (1) + kemId (2) + publicKey (Npk) + algorithms length (2) + algorithms

### Chunked Streaming
- Use `AsyncGenerator<Uint8Array>` for chunk iteration
- Default max chunk size: 16384 bytes (per draft-08 §3)
- Configurable via constructor option
- Final chunk AAD: `"final"`
- Chunked requests SHOULD include `Incremental: ?1` header (draft-08 §3)
- AEAD limits: max 2^32 chunks per response (draft-08 §7.3 / draft-irtf-cfrg-aead-limits)

### Key Derivation
- `KeyConfig.fromSeed(seed, keyId, ...)` uses HPKE `deriveKeyPair(ikm)` for deterministic keys
- Enables reproducible test vectors with seeded PRNG

### Multi-Key Support
- `OHTTPServer` accepts array of `KeyConfig`
- Lookup by `keyId` from encapsulated request header
- Supports key rotation scenarios

### Response Nonce
- Size: `max(Nn, Nk)` where Nn=nonce length, Nk=key length (RFC 9458 §4.2)
- For AES-128-GCM: max(12, 16) = 16 bytes

### Replay Protection
- Out of scope for this library (RFC 9458 §6.5)
- Server applications should implement anti-replay (e.g., nonce tracking, date validation)

### Transport Layer
- Library handles encapsulation/decapsulation only - no HTTP transport
- User calls `fetch()` themselves with encapsulated data
- Enables relay→gateway auth (headers, mTLS) without library coupling
- User controls retries, timeouts, logging at transport layer

### Error Handling
- Decryption errors are opaque (no detail leakage)
- Single `OHTTPError` type with error codes
- Side-channel safe: constant-time operations where applicable

## Security Invariants

- Never reuse (key, nonce) pairs - counter maintained per response context
- Validate input lengths before HPKE/AEAD operations
- Reject unknown keyIds without timing leakage
- Use constant-time compare for MAC verification

## Dependencies

| Package | Purpose |
|---------|---------|
| `@dajiaji/bhttp` | Binary HTTP (RFC 9292) encode/decode |
| `hpke` | HPKE (RFC 9180) - WebCrypto based |
| `@panva/hpke-noble` | HPKE with ML-KEM (post-quantum) |
| `quicvarint` | QUIC variable-length integers (RFC 9000 §16) |

## Code Style

- **No `any`**: use `unknown` + type guards
- **No `!` assertions**: handle nullability explicitly
- **No `as` casts**: use discriminated unions / parsing
- **Constant-time**: timing-safe compare for crypto operations
- **Streaming**: prefer `AsyncGenerator` over callback APIs

## Testing

- Tests in `packages/ohttp-ts/test/`
- Use RFC 9458 Appendix A test vectors
- Use draft-08 Appendix A chunked vectors
- Deterministic tests via `KeyConfig.fromSeed()`
- Run: `pnpm test`

## Build

```sh
pnpm install
pnpm build
pnpm test
```

## Target Environments

- Browser (WebCrypto)
- Cloudflare Workers
- Node.js 18+
- Deno, Bun (untested but should work)
