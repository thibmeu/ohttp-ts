/**
 * Batched OHTTP timing benchmarks for workerd.
 *
 * workerd intentionally exposes a coarse clock. Each measured iteration runs a
 * sequential batch large enough to cross multiple clock ticks. The reported hz
 * is batches/second; multiply it by the batch size in the label for ops/second.
 *
 * Run: npm run bench:workers
 */

import { bench, describe } from "vitest";
import { client, type Fixture, makeFixture, server } from "./fixtures.ts";
import { BENCH_OPTS } from "./options.ts";

const CASES = [
	["1KB", 1_024, 32],
	["1MB", 1_048_576, 4],
] as const;

const fixtures = new Map<string, Fixture>();
for (const [label, bytes] of CASES) fixtures.set(label, await makeFixture(bytes));

async function repeat(count: number, op: () => Promise<unknown>): Promise<void> {
	for (let i = 0; i < count; i++) await op();
}

describe("workerd OHTTP throughput (reported hz is batches/sec)", () => {
	for (const [label, , batch] of CASES) {
		const fixture = fixtures.get(label)!;
		const name = (op: string) => `${op} ${label} ×${batch}`;

		bench(
			name("encapsulateRequest"),
			() => repeat(batch, () => client.encapsulate(fixture.payload)),
			BENCH_OPTS,
		);
		bench(
			name("decapsulateRequest"),
			() => repeat(batch, () => server.decapsulate(fixture.encapsulatedRequest)),
			BENCH_OPTS,
		);
		bench(
			name("encryptResponse"),
			() => repeat(batch, () => fixture.serverCtx.encryptResponse(fixture.payload)),
			BENCH_OPTS,
		);
		bench(
			name("decryptResponse"),
			() => repeat(batch, () => fixture.clientCtx.decryptResponse(fixture.encryptedResponse)),
			BENCH_OPTS,
		);
		bench(
			name("round-trip"),
			() =>
				repeat(batch, async () => {
					const { encapsulatedRequest, context } = await client.encapsulate(fixture.payload);
					const { context: serverContext } = await server.decapsulate(encapsulatedRequest);
					await context.decryptResponse(await serverContext.encryptResponse(fixture.payload));
				}),
			BENCH_OPTS,
		);
	}
});
