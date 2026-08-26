/**
 * Deterministic perf metrics, for CI regression comments.
 *
 * Wall-clock is not gateable here: most of an op is spent awaiting async
 * WebCrypto, and a shared CI runner is far noisier than the quiet box
 * `bench/README.md` already warns about. So this reports only numbers that
 * reproduce exactly, run to run and machine to machine:
 *
 *   copied  bytes memcpy'd, counted by patching `Uint8Array.prototype.set`.
 *           That is the primitive `concat` (and hpke) copies through, so a
 *           regression like "the payload is now copied twice" shows up as a
 *           doubling. It does NOT see `.slice()`, so treat it as a floor.
 *   calls   `crypto.subtle` calls by kind. ohttp-ts is bound by the fixed
 *           per-call dispatch cost, so the call count is the lever
 *           (see bench/overlap.ts).
 *
 * Both survive a loaded runner, which is the whole point.
 *
 * Run: npm run metrics                       JSON to stdout
 *      npm run metrics -- report a.json ...  markdown diff, last file is HEAD
 */

import { readFile } from "node:fs/promises";

const origSet = Uint8Array.prototype.set;
let copied = 0;
let counting = false;
Uint8Array.prototype.set = function set(this: Uint8Array, src: never, off?: number) {
	if (counting) copied += (src as ArrayLike<number>).length ?? 0;
	return origSet.call(this, src, off as never);
};

const subtleCalls: string[] = [];
(function patchSubtle() {
	const subtle = crypto.subtle as unknown as Record<string, unknown>;
	const proto = Object.getPrototypeOf(crypto.subtle);
	for (const name of Object.getOwnPropertyNames(proto).filter(
		(n) => n !== "constructor" && typeof (subtle[n] as unknown) === "function",
	)) {
		const orig = (subtle[name] as (...a: unknown[]) => unknown).bind(crypto.subtle);
		subtle[name] = (...args: unknown[]) => {
			if (counting) subtleCalls.push(name);
			return orig(...args);
		};
	}
})();

interface OpMetrics {
	copied: number;
	calls: Record<string, number>;
}
type Metrics = Record<string, OpMetrics>;

/** One clean run of `fn`, with a warm-up first so one-time setup isn't counted. */
async function measure(fn: () => Promise<unknown>): Promise<OpMetrics> {
	await fn();
	copied = 0;
	subtleCalls.length = 0;
	counting = true;
	await fn();
	counting = false;

	const calls: Record<string, number> = {};
	for (const name of subtleCalls) calls[name] = (calls[name] ?? 0) + 1;
	return { copied, calls };
}

async function collect(): Promise<Metrics> {
	// Imported late so the patches above are in place first.
	const { client, keyConfig, makeFixture, server, suite } = await import("../bench/fixtures.ts");
	const { ChunkedOHTTPClient, ChunkedOHTTPServer } = await import("../src/index.ts");

	// Built here rather than taken from fixtures.ts, so this tool runs against any
	// checkout that exports the shared suite/key — including one whose fixtures
	// predate the chunked pair.
	const chunkedClient = new ChunkedOHTTPClient(suite, keyConfig);
	const chunkedServer = new ChunkedOHTTPServer([keyConfig]);

	const f1k = await makeFixture(1_024);
	const f1m = await makeFixture(1_048_576);

	const cenc1k = (await chunkedClient.encapsulate(f1k.payload)).encapsulatedRequest;
	const { encapsulatedRequest: cenc1m, createResponseContext } = await chunkedClient.encapsulate(
		f1m.payload,
	);
	const cres = await (await chunkedServer.decapsulate(cenc1m)).createResponseContext();
	const cresponse = await chunkedServer.encapsulateResponse(cres, f1m.payload);

	const ops: Array<[string, () => Promise<unknown>]> = [
		["encapsulate 1KB", () => client.encapsulate(f1k.payload)],
		["encapsulate 1MB", () => client.encapsulate(f1m.payload)],
		["decapsulate 1KB", () => server.decapsulate(f1k.encapsulatedRequest)],
		["decapsulate 1MB", () => server.decapsulate(f1m.encapsulatedRequest)],
		["encryptResponse 1MB", () => f1m.serverCtx.encryptResponse(f1m.payload)],
		["decryptResponse 1MB", () => f1m.clientCtx.decryptResponse(f1m.encryptedResponse)],
		["chunked encapsulate 1KB", () => chunkedClient.encapsulate(f1k.payload)],
		["chunked encapsulate 1MB", () => chunkedClient.encapsulate(f1m.payload)],
		["chunked decapsulate 1KB", () => chunkedServer.decapsulate(cenc1k)],
		["chunked decapsulate 1MB", () => chunkedServer.decapsulate(cenc1m)],
		["chunked encapsulateResponse 1MB", () => chunkedServer.encapsulateResponse(cres, f1m.payload)],
		[
			"chunked decapsulateResponse 1MB",
			() => chunkedClient.decapsulateResponse(createResponseContext, cresponse),
		],
	];

	const out: Metrics = {};
	for (const [name, fn] of ops) out[name] = await measure(fn);
	return out;
}

// --- report ----------------------------------------------------------------

function fmtBytes(n: number): string {
	if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
	if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${n} B`;
}

/** `+12%` / `-50%` / `=` — the sign is what a reviewer scans for. */
function delta(base: number, head: number): string {
	if (base === head) return "=";
	if (base === 0) return "new";
	const pct = ((head - base) / base) * 100;
	return `${pct > 0 ? "+" : ""}${pct.toFixed(0)}%`;
}

/** Markdown rows for regressions only; unchanged metrics are noise in a PR review. */
function report(labelled: Array<[string, Metrics]>): string {
	const head = labelled.at(-1);
	if (head === undefined) throw new Error("report needs at least one metrics file");
	const [, headM] = head;
	const bases = labelled.slice(0, -1);

	const rows: string[] = [];
	for (const op of Object.keys(headM)) {
		const h = headM[op];
		if (h === undefined) continue;
		for (const [baseLabel, baseM] of bases) {
			const b = baseM[op];
			if (b === undefined) continue;
			const changes: string[] = [];
			if (h.copied > b.copied) {
				changes.push(
					`bytes passed to \`Uint8Array.set\`: ${fmtBytes(b.copied)} → ${fmtBytes(h.copied)} (${delta(b.copied, h.copied)})`,
				);
			}
			for (const [kind, count] of Object.entries(h.calls)) {
				const before = b.calls[kind] ?? 0;
				if (count > before) changes.push(`\`${kind}\` calls: ${before} → ${count}`);
			}
			if (changes.length > 0) rows.push(`| ${op} | ${baseLabel} | ${changes.join("<br>")} |`);
		}
	}

	if (rows.length === 0) return "";
	return [
		"### Regressions to check",
		"",
		"| operation | baseline | measured increase |",
		"|---|---|---|",
		...rows,
	].join("\n");
}

// --- entry -----------------------------------------------------------------

const [mode, ...files] = process.argv.slice(2);

if (mode === "report") {
	const labelled: Array<[string, Metrics]> = [];
	for (const spec of files) {
		// `label=path`, falling back to the filename.
		const eq = spec.indexOf("=");
		const [label, path] =
			eq === -1 ? [spec.replace(/\.json$/, ""), spec] : [spec.slice(0, eq), spec.slice(eq + 1)];
		labelled.push([label, JSON.parse(await readFile(path, "utf8")) as Metrics]);
	}
	const output = report(labelled);
	if (output !== "") console.log(output);
} else {
	console.log(JSON.stringify(await collect(), null, "\t"));
}
