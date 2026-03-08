# ohttp-ts

[![NPM](https://img.shields.io/npm/v/ohttp-ts?style=plastic)](https://www.npmjs.com/package/ohttp-ts)
[![NPM](https://img.shields.io/npm/l/ohttp-ts?style=plastic)](LICENSE)

Oblivious HTTP implementation in TypeScript.

**Specification:** Compliant with IETF [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.txt) and [draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.txt).

**Support:**
- Oblivious HTTP (RFC 9458)
- Chunked OHTTP streaming (draft-08)
- Incremental header (draft-ietf-httpbis-incremental)
- Multiple cipher suites (X25519, P-256, P-384, P-521)

**Usage:**

Examples are in the [examples folder](examples).

```typescript
// RFC 9458 Figure 1
//
// +---------+       +-------+       +---------+    +--------+
// | Client  |       | Relay |       | Gateway |    | Target |
// +----+----+       +---+---+       +----+----+    +---+----+
//      |                |                |             |
const request = new TextEncoder().encode("GET /resource HTTP/1.1\r\n\r\n");
const { encapsulatedRequest, context } = await client.encapsulate(request);
//      +--------------->|                |             |
//      |                +--------------->|             |
const { request: decryptedRequest, context: serverContext } =
    await gateway.decapsulate(encapsulatedRequest);
//      |                |                +------------>|
//      |                |                |<------------+
const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\n\r\n");
const encapsulatedResponse = await serverContext.encryptResponse(response);
//      |                |<---------------+             |
//      |<---------------+                |             |
const decryptedResponse = await context.decryptResponse(encapsulatedResponse);
//      |                |                |             |
```

### Development

| Task       | Command          |
|------------|------------------|
| Install    | `pnpm install`   |
| Build      | `pnpm build`     |
| Test       | `pnpm test`      |
| Lint       | `pnpm lint`      |
| Examples   | `npx tsx examples/index.ts` |

### Security Considerations

This software has not been audited. Please use at your sole discretion.

Replay protection is out of scope (RFC 9458 §6.5). Server applications should implement anti-replay mechanisms.

### License

This project is under the MIT license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be MIT licensed as above, without any additional terms or conditions.
