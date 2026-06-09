/**
 * Deterministic crypto-overlap meter — the loop driver for concurrency work.
 *
 * Why this exists: ohttp-ts is bound by the FIXED overhead of many awaited
 * `crypto.subtle` calls (each WebCrypto op is dispatched to the libuv threadpool,
 * default size 4). The repo's other benches can't guide concurrency work:
 *   - bench:profile measures CPU self-time — overlapping two awaits doesn't change
 *     self-time, so it shows nothing.
 *   - bench:alloc measures bytes — overlap is allocation-neutral (slightly worse).
 *   - bench / *.bench.ts measure wall-clock — too noisy to resolve a small overlap.
 *
 * This meter instruments every `crypto.subtle` call (start/end via performance.now)
 * and, per operation, reports DETERMINISTIC structure that survives machine noise:
 *
 *   calls        how many subtle calls the op makes, by kind. The #1 lever for
 *                per-call-overhead-bound code is FEWER calls (batch / cache keys /
 *                bigger AEAD chunks) — Node's own guidance. This column finds them.
 *   maxConc      peak simultaneous in-flight calls. ==1 with calls>1 means the op
 *                is fully serial: every call awaited before the next.
 *   serial       Σ of each call's duration (the cost if run strictly one-by-one).
 *   covered      wall time during which >=1 crypto call was in flight (interval union).
 *   overlap%     (serial - covered) / serial — how much latency concurrency ALREADY
 *                saves. 0% = no overlap exploited.
 *   idle         span - covered — time inside the op's crypto span with NO crypto in
 *                flight (main-thread JS, or threadpool queueing).
 *
 * Reading it for an optimisation loop:
 *   - maxConc==1 and calls>1  -> look for INDEPENDENT calls to Promise.all (but verify
 *     they don't form a data-dependency chain; most of OHTTP's schedule does).
 *   - high `calls`            -> the real lever: cut the call count (cache imported
 *     CryptoKeys, fewer/larger AEAD ops). Threadpool concurrency can't help past
 *     UV_THREADPOOL_SIZE anyway.
 *   - high overlap% already   -> concurrency is spent; move to call-count / algorithm.
 *
 * Run: npm run bench:overlap
 *      UV_THREADPOOL_SIZE=8 npm run bench:overlap   (to test threadpool effects)
 */

import { AEAD_AES_128_GCM } from "hpke";
import { sealResponseChunk } from "../src/encapsulation.js";
import { client, makeFixture, server } from "./fixtures.js";
import { randomBytes } from "./util.js";

// --- crypto.subtle instrumentation -----------------------------------------

interface Call {
	name: string;
	t0: number;
	t1: number;
}

let recording: Call[] | null = null;

(function patchSubtle() {
	const subtle = crypto.subtle as unknown as Record<string, unknown>;
	const proto = Object.getPrototypeOf(crypto.subtle);
	const names = Object.getOwnPropertyNames(proto).filter(
		(n) => n !== "constructor" && typeof (subtle[n] as unknown) === "function",
	);
	for (const name of names) {
		const orig = (subtle[name] as (...a: unknown[]) => unknown).bind(crypto.subtle);
		subtle[name] = (...args: unknown[]) => {
			if (!recording) return orig(...args);
			const call: Call = { name, t0: performance.now(), t1: 0 };
			recording.push(call);
			const settle = () => {
				call.t1 = performance.now();
			};
			return Promise.resolve(orig(...args)).then(
				(r) => {
					settle();
					return r;
				},
				(e) => {
					settle();
					throw e;
				},
			);
		};
	}
})();

// --- metrics ----------------------------------------------------------------

function coverage(calls: Call[]): number {
	if (calls.length === 0) return 0;
	const iv = calls.map((c) => [c.t0, c.t1] as const).sort((a, b) => a[0] - b[0]);
	let total = 0;
	let [cs, ce] = iv[0]!;
	for (let i = 1; i < iv.length; i++) {
		const [a, b] = iv[i]!;
		if (a > ce) {
			total += ce - cs;
			cs = a;
			ce = b;
		} else if (b > ce) {
			ce = b;
		}
	}
	return total + (ce - cs);
}

function maxConcurrency(calls: Call[]): number {
	const ev: Array<[number, number]> = [];
	for (const c of calls) {
		ev.push([c.t0, 1], [c.t1, -1]);
	}
	ev.sort((a, b) => a[0] - b[0] || a[1] - b[1]); // close (-1) before open (+1) at ties
	let cur = 0;
	let max = 0;
	for (const [, d] of ev) {
		cur += d;
		if (cur > max) max = d > 0 ? cur : max;
	}
	return max;
}

const median = (xs: number[]): number => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;

const WARMUP = 3;
const RUNS = 9;

async function meter(label: string, fn: () => Promise<unknown>): Promise<void> {
	for (let i = 0; i < WARMUP; i++) await fn();

	const serials: number[] = [];
	const covers: number[] = [];
	const spans: number[] = [];
	let calls: Call[] = [];
	for (let i = 0; i < RUNS; i++) {
		recording = [];
		await fn();
		calls = recording;
		recording = null;
		const t0 = Math.min(...calls.map((c) => c.t0));
		const t1 = Math.max(...calls.map((c) => c.t1));
		serials.push(calls.reduce((s, c) => s + (c.t1 - c.t0), 0));
		covers.push(coverage(calls));
		spans.push(t1 - t0);
	}

	const hist = new Map<string, number>();
	for (const c of calls) hist.set(c.name, (hist.get(c.name) ?? 0) + 1);
	const histStr = [...hist.entries()].map(([n, c]) => `${n}×${c}`).join(" ");

	const serial = median(serials);
	const cov = median(covers);
	const span = median(spans);
	const overlapPct = serial > 0 ? ((serial - cov) / serial) * 100 : 0;
	const idle = span - cov;
	const ms = (n: number) => `${n.toFixed(3)}ms`;

	console.log(
		`${label.padEnd(26)} calls=${String(calls.length).padStart(2)} maxConc=${maxConcurrency(calls)}  ` +
			`serial=${ms(serial).padStart(9)} covered=${ms(cov).padStart(9)} overlap=${overlapPct.toFixed(0).padStart(3)}%  ` +
			`idle=${ms(idle).padStart(9)}`,
	);
	console.log(`${" ".repeat(28)}${histStr}`);
}

// --- run --------------------------------------------------------------------

const { UV_THREADPOOL_SIZE } = process.env;
console.log(`UV_THREADPOOL_SIZE=${UV_THREADPOOL_SIZE ?? "(default 4)"}  node=${process.version}\n`);

for (const [size, bytes] of [
	["1KB", 1_024],
	["1MB", 1_048_576],
] as const) {
	const { payload, encapsulatedRequest, clientCtx, serverCtx, encryptedResponse } =
		await makeFixture(bytes);

	await meter(`encapsulateRequest ${size}`, () => client.encapsulate(payload));
	await meter(`decapsulateRequest ${size}`, () => server.decapsulate(encapsulatedRequest));
	await meter(`encryptResponse ${size}`, () => serverCtx.encryptResponse(payload));
	await meter(`decryptResponse ${size}`, () => clientCtx.decryptResponse(encryptedResponse));
	console.log();
}

// --- chunked response path: per-chunk seals, serial vs windowed concurrency --
// Each chunk's seal is independent (counter-derived nonce, fixed key, no
// chaining), so a window of seals can run concurrently. The streaming transform
// seals serially today (concurrency 1); compare against 4 to see whether the
// per-chunk dispatch overlaps.
const aead = AEAD_AES_128_GCM();
const aeadKey = crypto.getRandomValues(new Uint8Array(16));
const baseNonce = crypto.getRandomValues(new Uint8Array(12));
const big = randomBytes(512 * 1024);

async function chunkedSeal(
	payload: Uint8Array,
	chunkSize: number,
	concurrency: number,
): Promise<void> {
	const n = Math.ceil(payload.length / chunkSize);
	for (let i = 0; i < n; i += concurrency) {
		const wave: Array<Promise<unknown>> = [];
		for (let j = i; j < Math.min(i + concurrency, n); j++) {
			const chunk = payload.subarray(j * chunkSize, Math.min((j + 1) * chunkSize, payload.length));
			wave.push(sealResponseChunk(aead, aeadKey, baseNonce, j, chunk, j === n - 1));
		}
		await Promise.all(wave);
	}
}

for (const [label, chunkSize] of [
	["16KB", 16_384],
	["256B", 256],
] as const) {
	for (const concurrency of [1, 4]) {
		await meter(`chunkedSeal 512KB/${label} c=${concurrency}`, () =>
			chunkedSeal(big, chunkSize, concurrency),
		);
	}
}
