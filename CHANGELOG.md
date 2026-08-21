# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `KeyConfig.generate`, `.derive`, and `.import` take `symmetricAlgorithms` as an optional argument, defaulting to the suite's own (KDF, AEAD) pair. A server decrypts every request with the single `suite` its key config carries, so any other pair in the list is one the gateway advertises, accepts in a request header, and then fails to open. A supplied list that is not exactly that pair is rejected with `InvalidKeyConfig`.
- Both servers reject a key config list that is empty or repeats a key identifier. Lookup is by identifier alone, so a duplicate shadows every later config sharing it and a botched rotation surfaced as `UnsupportedCipherSuite` on live requests. One consequence of these two changes: a key configuration cannot advertise several AEADs under one identifier, as RFC 9458 Appendix A does, because a server decrypts with the single suite its config carries. That configuration never worked here; it now fails at construction rather than on the first request naming the second AEAD.
- `serializeKeyConfig` rejects a `keyId` outside 0-255 and a public key whose length is not `Npk` for the KEM. `setUint8` wrote 256 as key 0, publishing a config under a key the gateway never registered, and a short public key shifted every field after it.

## [0.4.2] - 2026-08-20

### Added

- `StreamingRequestInit`, the `RequestInit & { duplex: "half" }` that a streaming request body requires. The DOM lib types still lack `duplex`, so building that `Request` needed a `@ts-expect-error`; annotating the init with this type does not.
- `KeyConfig.select` (`selectKeyConfig`), which picks the first config a `CipherSuite` can actually use. `parseKeyConfigs` reports what the gateway published; selection decides what this client can do with it. Reaching for `configs[0]` hands you whatever the gateway listed first, which may name a KEM your suite does not implement.
- The RFC 9458 and draft-08 Appendix A vectors are now known-answer tests: both specs' encapsulated requests are decapsulated, and both encapsulated responses reproduced byte for byte by feeding the spec's response nonce back in. Six transcribed values were wrong and nothing noticed, because the old assertions checked the vector file against itself rather than against the library. Round-trip tests are symmetric and cannot see a key-schedule error - both sides derive the same wrong key and agree. Corrupting the response HKDF `nonce` label now fails these two tests and nothing else; before, it failed nothing.

### Fixed

- Bytes returned by the low-level API are typed `Uint8Array<ArrayBuffer>` instead of a bare `Uint8Array`. Since TypeScript 5.7 the bare form means `Uint8Array<ArrayBufferLike>`, which the DOM `BodyInit` rejects, so `new Response(encapsulatedRequest)` failed with an error naming `URLSearchParams`. Browsers and Workers hit this; Node's `BodyInit` accepts the bare form, so it never showed up there. The `Request`/`Response` API never exposed it either. `test/types.assert.ts` pins the assignability under DOM lib.
  This also retires the internal `toArrayBuffer`, which copied a whole buffer to get something `BodyInit` would accept. The bytes now go in unchanged, dropping a full copy of the request on the client and of the response payload on the gateway.
- Both chunked and non-chunked clients accepted a key config whose KEM their `CipherSuite` does not implement, checking only the KDF and AEAD. With a real ML-KEM-768 config that surfaced as an hpke `DeserializeError` from `encapsulate` rather than an `OHTTPError` from the constructor; where the two KEMs share a public key length it did not surface at all, and the client sent a header advertising a KEM it had not used. Both constructors now reject the mismatch with `UnsupportedCipherSuite`, via the same `supportsKeyConfig` predicate `KeyConfig.select` uses.

### Changed

- `examples/` is typechecked. `tsconfig.bench.json` becomes `tsconfig.node.json` and covers both; the examples ran through `tsx`, which strips types without checking them.
- Property tests get a 30s timeout, up from the 5s default. `props-framing` timed out under parallel load while passing on its own.
- `parseKeyConfigs` skips configs naming a KEM, KDF, or AEAD this library does not implement instead of rejecting the whole list, so a gateway adding one does not take down the entries a client can still use. Structural damage - bad length, truncation, trailing bytes - still rejects the list, since malformed bytes may be tampering rather than registry evolution. `parseKeyConfig` runs its structural checks before deciding a config is merely unsupported, so a config that is both damaged and unimplementable is rejected rather than skipped. An all-unsupported list now returns `[]`; pair it with `KeyConfig.select`, which throws `UnsupportedCipherSuite`.
- `parseKeyConfig` throws `UnsupportedCipherSuite`, not `InvalidKeyConfig`, for a KEM it does not implement or a config whose every symmetric algorithm it lacks. Callers matching on `InvalidKeyConfig` for those cases need updating.
- `parseKeyConfig` keeps a config's implemented `(KDF, AEAD)` pairs when it lacks another, rather than dropping the config, per RFC 9458 Section 3.1.
- The chunked client and server throw `RangeError` for a `maxChunkSize` that is not a positive integer, or a `maxFrameSize` below one AEAD tag. A `maxChunkSize` of 0 hung `createChunkerTransform` on zero-length reads; a non-integer silently disabled chunking. `RangeError` rather than `OHTTPError`: this is API misuse, not a protocol condition a peer can trigger.

### Security

- The incremental chunked response contexts claimed their chunk counter *after* awaiting the AEAD call, so two `sealChunk` calls issued before the first resolved both sealed at the same counter, reusing an (AEAD key, nonce) pair. AES-GCM does not survive that. `openChunk` had the same shape, failing the second concurrent call and leaving the counter misaligned for every chunk after it. Both now claim the counter synchronously, as the streaming transforms already did. `openFinalChunk` now marks the context finished synchronously as well, so a concurrent `openChunk` cannot land on the final chunk's counter. Sequential callers are unaffected and the wire format is unchanged.

## [0.4.1] - 2026-08-19

### Added

- Workers CI: the suite runs in workerd (`npm run test:workers`). The three ChaCha20-Poly1305 tests skip there; workerd's WebCrypto has none.
- `check:treeshake`, in CI. It bundles the constant, framing, and key config exports out of `dist/index.mjs` and fails if an unexpected dependency survives.
- `typecheck`, in CI. It had never run there.

### Changed

- Updated bhttp-ts to 0.5.1 and quicvarint to 0.2.1. Packaging only, both ship their source once instead of inlining it into every sourcemap. No published JS changed.
- Improved tree shaking to reduce downstream build size. A client or server export now bundles to 17.6 kB (5.3 kB gzipped), the constant exports reach no dependency at all. The published package drops from 104.8 to 85.2 kB packed, 522.6 to 404.9 kB unpacked.
- Dropped `engines: node >=24`. Nothing needed it.
- The chunked contexts now key their HPKE and AEAD state on module-private symbols instead of `_`-prefixed properties, so the crypto state no longer appears on the published types.

### Fixed

- The chunked seal and open contexts reject a chunk after the final one with `ChunkSequenceError` instead of producing a message the peer would reject.

## [0.4.0] - 2026-08-18

### Added

- `maxFrameSize` option on the chunked client and server, with `DEFAULT_MAX_FRAME_SIZE`. The decrypt path previously buffered whatever a peer declared — a non-final frame length is read from the wire before any authentication runs, and the final chunk carries no length at all — so an unauthenticated peer could pin ~2 GiB, or stream indefinitely after the 0-length marker. Both are now capped, rejecting over-limit frames with `ChunkLimitExceeded`. The default derives from `maxChunkSize` plus the 16-byte AEAD tag, so a peer pair is never configured to reject frames it is willing to send.

### Changed

- The four buffer-path chunked methods (`ChunkedOHTTPClient.encapsulate` / `decapsulateResponse`, `ChunkedOHTTPServer.decapsulate` / `encapsulateResponse`) now run through the same streaming transforms as the Request/Response API, so per-chunk AEAD calls overlap instead of serializing one per `await`. Wire format is unchanged.
- Bumped `bhttp-ts` 0.4.5 → 0.5.0 and `quicvarint` 0.1.7 → 0.2.0. Holding `quicvarint` at 0.1.7 installed two copies, and the 0.1.7 build's `read()` returns wrapped, sometimes negative, values for 8-byte varints above `MAX`.
- Bumped `hpke` 1.1.2 → 1.1.4
- Migrated to TypeScript 7 and bumped dev dependencies
- `npm run check:package` runs `publint` and `attw --pack` against the packed tarball, checking the exports map and that the `.d.mts`/`.d.cts` pair resolves for both CJS and ESM consumers

## [0.3.5] - 2026-06-11

### Changed

- Chunked streaming decryption keeps a small window of AEAD opens in flight rather than one per `await`, overlapping the per-call WebCrypto latency that otherwise serializes the stream. Output order is preserved, and rejections are captured at issue time so an abandoned window never surfaces an unhandled rejection.
- Bumped `hpke` 1.1.1 → 1.1.2 and `bhttp-ts` 0.4.4 → 0.4.5 for performance
- Consolidated the benchmark suite into one set (deterministic `overlap`/`alloc` benches, vitest benches, and a `trace` export), with shared fixtures and a `bench/README.md`

## [0.3.4] - 2026-06-08

### Changed

- Bumped `bhttp-ts` 0.4.3 → 0.4.4, whose decoder now accepts the truncated messages allowed by RFC 9292 Section 3.8

### Fixed

- Chunked OHTTP decryption now rejects two malformed inputs that draft-ietf-ohai-chunked-ohttp-08 requires erroring on: a stream that ends without a final (0-length prefix) chunk, and a non-final chunk that decrypts to zero-length plaintext. Both were previously accepted as valid.

## [0.3.3] - 2026-06-07

### Fixed

- Chunked OHTTP decryption no longer fails when a frame — in particular the final chunk — arrives split across multiple stream reads (e.g. TCP/TLS-sized `fetch()` body chunks). The final chunk, which is delimited by end-of-stream, is now buffered until end-of-stream before being decrypted instead of decrypted eagerly on a possibly-truncated buffer.

### Changed

- Bumped `bhttp-ts` 0.4.2 → 0.4.3, making the streaming decoder O(n) instead of O(n²) on many small pushes (the chunked OHTTP decode path)
- Streaming encrypt/decrypt and chunker transforms now use an offset-cursor buffer (O(n) instead of O(n²) on fragmented input or when many frames are buffered at once), emit the frame length prefix and ciphertext without copying the ciphertext, and pass decoder views directly to AEAD open — reducing allocations on the chunked OHTTP hot path
- Byte-level chunked `encapsulate`/`decapsulate` and request/response splitting now use zero-copy `subarray` views instead of `slice` copies, including the per-chunk buffer advance that was previously O(n²)

### Added

- `bench/streaming.bench.ts` — isolates the streaming transform layer (chunker + encrypt/decrypt) from the KEM to measure per-chunk plumbing cost across realistic and fragmented read patterns

## [0.3.2] - 2026-06-06

### Added

- `sideEffects: false` to enable tree-shaking in consumer bundlers

### Changed

- Replaced the vendored `bhttp-js` tarball with the published [`bhttp-ts`](https://www.npmjs.com/package/bhttp-ts) package, declared as a runtime dependency and externalized from the bundle (roughly halves the published bundle size)
- Bumped `hpke` 1.1.0 → 1.1.1 and `quicvarint` 0.1.6 → 0.1.7
- Pinned `tsdown` build tooling to an exact version

### Removed

- Vendored `bhttp-js-0.4.0.tgz` tarball and `file:` dependency

## [0.3.1] - 2026-06-03

### Added

- Pluggable response crypto via HPKE factories

### Changed

- Bumped `hpke` 1.0.6 → 1.1.0
- Migrated build tooling from tsup to tsdown
- Bumped dev dependencies

## [0.3.0] - 2026-03-17

### Added

- Bun runtime support via X25519 WebCrypto polyfill
- CI testing across Node, Bun, and browser runtimes

### Changed

- **Breaking:** `encapsulateRequest` now returns `RequestInit` instead of `Request`
- Switched package manager from pnpm to npm
- Switched to Node 24
- Updated dependencies

## [0.2.4] - 2026-03-11

### Fixed

- Bundle `bhttp-js` into dist to avoid `file:` dependency issues when installing from npm
- Handle undefined `SharedArrayBuffer` in browsers without COOP/COEP headers

## [0.2.3] - 2026-03-11

### Fixed

- Browser compatibility: handle undefined `SharedArrayBuffer` in browsers without COOP/COEP headers

## [0.2.2] - 2026-03-10

### Fixed

- Include the `vendor/` directory in the published npm package, fixing `file:` dependency resolution

## [0.2.1] - 2026-03-10

### Added

- Request/Response API for chunked OHTTP

### Changed

- Stream chunked OHTTP bodies via `TransformStream`
- Vendored `bhttp-js` and removed the `@dajiaji/bhttp` dependency

### Fixed

- BHTTP decoder dropped chunks when the decoder returned multiple content events

## [0.2.0] - 2026-03-08

### Added

- Request/Response API: high-level `encapsulateRequest` / `decapsulateRequest` for HTTP messages
- Automatic Binary HTTP encoding via `@dajiaji/bhttp`

### Changed

- **Breaking:** `@dajiaji/bhttp` is now a required dependency (peer dependency removed)

## [0.1.0] - 2026-03-08

### Added

- RFC 9458 Oblivious HTTP (core protocol)
- Chunked OHTTP streaming (draft-ietf-ohai-chunked-ohttp-08)
- Incremental header support (draft-ietf-httpbis-incremental-04)
- Multiple cipher suites: X25519, P-256, P-384, P-521
- Multi-key server for key rotation
- WebCrypto-based implementation for browsers, Workers, and Node.js 22+
