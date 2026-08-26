/**
 * Concurrency throughput benchmark.
 *
 * Single-op latency is at its floor; what matters for a server is throughput
 * when many OHTTP operations are in flight at once. WebCrypto dispatches every
 * `crypto.subtle` call to libuv's threadpool, so throughput rises with in-flight
 * concurrency until the per-call main-thread dispatch saturates, then flattens.
 *
 * Each iteration runs a fixed batch of `BATCH` ops at in-flight concurrency `c`,
 * so `hz × BATCH` is throughput (ops/sec) and is comparable across `c`: the
 * point where it stops rising is the effective ceiling. 1KB payloads keep this
 * per-call/threadpool-bound (where concurrency matters); large payloads are
 * AEAD-CPU-bound, a different regime.
 *
 * Run: npm run bench:concurrency   (or part of `npm run bench`)
 */

import { bench, describe } from "vitest";
import { client, makeFixture, server } from "./fixtures.ts";
import { BENCH_OPTS } from "./options.ts";

const { payload, encapsulatedRequest } = await makeFixture(1_024);

const BATCH = 64;
const LEVELS = [1, 2, 4, 8, 16, 32];

/** Run BATCH ops total, at most `c` in flight at any time. hz × BATCH = ops/sec. */
async function batched(c: number, op: () => Promise<unknown>): Promise<void> {
	for (let i = 0; i < BATCH; i += c) {
		const wave: Array<Promise<unknown>> = [];
		for (let j = 0; j < Math.min(c, BATCH - i); j++) wave.push(op());
		await Promise.all(wave);
	}
}

async function roundTrip(): Promise<void> {
	const { encapsulatedRequest: enc, context } = await client.encapsulate(payload);
	const { context: sctx } = await server.decapsulate(enc);
	await context.decryptResponse(await sctx.encryptResponse(payload));
}

describe(`decapsulateRequest ×${BATCH} @ concurrency (server hot path, 1KB)`, () => {
	for (const c of LEVELS) {
		bench(`c=${c}`, () => batched(c, () => server.decapsulate(encapsulatedRequest)), BENCH_OPTS);
	}
});

describe(`full round-trip ×${BATCH} @ concurrency (1KB)`, () => {
	for (const c of LEVELS) {
		bench(`c=${c}`, () => batched(c, roundTrip), BENCH_OPTS);
	}
});
