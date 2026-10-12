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

import { test } from "vitest";
import { client, type Fixture, makeFixture, server } from "./fixtures.ts";
import { BENCH_OPTS } from "./options.ts";

// Two regimes: setup-dominated (1KB) and AEAD-dominated (1MB).
const SIZES = [
	["1KB", 1_024],
	["1MB", 1_048_576],
] as const;

const fixtures = new Map<string, Fixture>();
for (const [label, n] of SIZES) fixtures.set(label, await makeFixture(n));

const groups: Array<[string, (f: Fixture) => Promise<unknown>]> = [
	["encapsulateRequest (client)", (f) => client.encapsulate(f.payload)],
	["decapsulateRequest (server)", (f) => server.decapsulate(f.encapsulatedRequest)],
	["encryptResponse (server)", (f) => f.serverCtx.encryptResponse(f.payload)],
	["decryptResponse (client)", (f) => f.clientCtx.decryptResponse(f.encryptedResponse)],
	[
		"full round-trip",
		async (f) => {
			const { encapsulatedRequest, context } = await client.encapsulate(f.payload);
			const { context: sctx } = await server.decapsulate(encapsulatedRequest);
			await context.decryptResponse(await sctx.encryptResponse(f.payload));
		},
	],
];

for (const [name, op] of groups) {
	test(name, async ({ bench }) => {
		await bench.compare(
			...SIZES.map(([label]) => {
				const f = fixtures.get(label)!;
				return bench(label, async () => void (await op(f)));
			}),
			BENCH_OPTS,
		);
	});
}
