# OHTTP Agent Guidelines

See [README.md](README.md) for usage, API reference, and installation.

## Specifications

| Spec | Link | Status |
|------|------|--------|
| RFC 9458 | https://www.rfc-editor.org/rfc/rfc9458.txt | Standards Track |
| Chunked OHTTP | https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt | Draft |
| Incremental | https://www.ietf.org/archive/id/draft-ietf-httpbis-incremental-04.txt | Draft |

## Architecture

```
packages/ohttp/src/
├── index.ts           # unified exports
├── keyConfig.ts       # KeyConfig parse/serialize/derive
├── client.ts          # OHTTPClient, ChunkedOHTTPClient
├── server.ts          # OHTTPServer, ChunkedOHTTPServer
├── encapsulation.ts   # HPKE setup, encrypt/decrypt primitives
├── incremental.ts     # Incremental header field parser
├── errors.ts          # opaque error types
└── utils.ts           # concat, constant-time compare
```

## Key Design Decisions

### Labels
- Core OHTTP: `"message/bhttp request"` / `"message/bhttp response"` (RFC 9458 Section 4.3-4.4)
- Chunked OHTTP: `"message/bhttp chunked request"` / `"message/bhttp chunked response"` (draft-08 Section 6.1-6.2)
- Custom labels supported via `requestLabel`/`responseLabel` options

### KeyConfig Wire Format
- `application/ohttp-keys`: 2-byte length prefix + KeyConfig (RFC 9458 Section 3.2)
- KeyConfig: keyId (1) + kemId (2) + publicKey (Npk) + algorithms length (2) + algorithms

### Chunked Streaming
- `AsyncGenerator<Uint8Array>` for chunk iteration
- Default max chunk size: 16384 bytes (draft-08 Section 3)
- Final chunk AAD: `"final"`
- AEAD limits: max 2^32 chunks per response (draft-08 Section 7.3)

### Response Nonce
- Size: `max(Nn, Nk)` where Nn=nonce length, Nk=key length (RFC 9458 Section 4.2)
- AES-128-GCM: max(12, 16) = 16 bytes

### Transport Layer
- Library handles encapsulation/decapsulation only
- User calls `fetch()` with encapsulated data
- Enables relay→gateway auth without library coupling

### Error Handling
- Decryption errors are opaque (no detail leakage)
- Single `OHTTPError` type with error codes

## Security Invariants

- Never reuse (key, nonce) pairs
- Validate input lengths before HPKE/AEAD operations
- Reject unknown keyIds without timing leakage
- Constant-time compare for MAC verification
- Replay protection out of scope (RFC 9458 Section 6.5)

## Code Style

- **No `any`**: use `unknown` + type guards
- **No `!` assertions**: handle nullability explicitly
- **No `as` casts**: use discriminated unions / parsing
- **Constant-time**: timing-safe compare for crypto operations
- **Streaming**: prefer `AsyncGenerator` over callback APIs

## Testing

- Tests in `packages/ohttp/test/`
- RFC 9458 Appendix A test vectors
- draft-08 Appendix A chunked vectors
- Deterministic tests via `KeyConfig.derive()`

## Target Environments

- Browser (WebCrypto)
- Cloudflare Workers
- Node.js 18+
- Deno, Bun (untested)
