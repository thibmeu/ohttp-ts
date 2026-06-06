# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
