/**
 * OHTTP throughput benchmarks (single-shot, non-chunked).
 *
 * Isolates each hot path so a change can be attributed:
 *  - encapsulateRequest  : client KEM SetupSender + Seal over the whole body
 *  - decapsulateRequest  : server KEM SetupRecipient + Open  (the server hot path)
 *  - encryptResponse     : HKDF Extract/Expand + raw AEAD Seal (response path)
 *  - decryptResponse     : HKDF Extract/Expand + raw AEAD Open
 *  - round-trip          : everything above, with a fresh ephemeral key each op
 *
 * Two payload sizes pick out the two regimes:
 *  - 1KB  : public-key setup dominates
 *  - 1MB  : bulk AEAD dominates
 *
 * Run: npm run bench            (Node)
 *      npm run bench:browser    (Chromium, same file)
 * For allocation deltas of these paths see `npm run bench:alloc`; for the
 * crypto.subtle call breakdown see `npm run bench:overlap`.
 */

import { bench, describe } from "vitest";
import { client, type Fixture, makeFixture, server } from "./fixtures.ts";
import { BENCH_OPTS } from "./options.ts";

// Two regimes: setup-dominated (1KB) and AEAD-dominated (1MB).
const SIZES = [
	["1KB", 1_024],
	["1MB", 1_048_576],
] as const;

const fixtures = new Map<string, Fixture>();
for (const [label, n] of SIZES) fixtures.set(label, await makeFixture(n));

describe("encapsulateRequest (client)", () => {
	for (const [label] of SIZES) {
		const f = fixtures.get(label)!;
		bench(label, async () => void (await client.encapsulate(f.payload)), BENCH_OPTS);
	}
});

describe("decapsulateRequest (server)", () => {
	for (const [label] of SIZES) {
		const f = fixtures.get(label)!;
		bench(label, async () => void (await server.decapsulate(f.encapsulatedRequest)), BENCH_OPTS);
	}
});

describe("encryptResponse (server)", () => {
	for (const [label] of SIZES) {
		const f = fixtures.get(label)!;
		bench(label, async () => void (await f.serverCtx.encryptResponse(f.payload)), BENCH_OPTS);
	}
});

describe("decryptResponse (client)", () => {
	for (const [label] of SIZES) {
		const f = fixtures.get(label)!;
		bench(
			label,
			async () => void (await f.clientCtx.decryptResponse(f.encryptedResponse)),
			BENCH_OPTS,
		);
	}
});

describe("full round-trip", () => {
	for (const [label] of SIZES) {
		const f = fixtures.get(label)!;
		bench(
			label,
			async () => {
				const { encapsulatedRequest, context } = await client.encapsulate(f.payload);
				const { context: sctx } = await server.decapsulate(encapsulatedRequest);
				await context.decryptResponse(await sctx.encryptResponse(f.payload));
			},
			BENCH_OPTS,
		);
	}
});
