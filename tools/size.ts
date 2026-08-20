/**
 * Install size and per-export bundle cost (Node-only dev tool).
 *
 * What does this package cost to install, and what does each export cost a
 * consumer who bundles it? Both questions are answered from the built dist,
 * so the numbers are the ones a downstream project actually sees.
 *
 * Run: npm run size            install + per-export table
 *      npm run size -- --html  also write size.html (treemap of `everything`)
 */

import { execFileSync } from "node:child_process";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";

/** The subset of `npm pack --json` this tool reads. */
interface Pack {
	name: string;
	version: string;
	size: number;
	unpackedSize: number;
	files: { path: string; size: number }[];
}

const ENTRY = "./dist/index.mjs";
const kb = (n: number) => `${(n / 1024).toFixed(1)} kB`;
const pad = (s: string | number, n: number) => String(s).padStart(n);

// ── install size ────────────────────────────────────────────────────────────
// npm pack is the source of truth: it applies "files", .npmignore and all.
const [pack] = JSON.parse(
	execFileSync("npm", ["pack", "--dry-run", "--json"], { encoding: "utf8" }),
) as Pack[];
if (!pack) throw new Error("npm pack returned no tarball");

const KINDS: [RegExp, string][] = [
	[/\.map$/, "sourcemaps"],
	[/\.d\.[cm]ts$/, "types"],
	[/^src\//, "source (for sourcemaps)"],
	[/\.[cm]js$/, "code"],
];
const buckets = new Map<string, number>();
for (const f of pack.files) {
	const kind = KINDS.find(([re]) => re.test(f.path))?.[1] ?? "other";
	buckets.set(kind, (buckets.get(kind) ?? 0) + f.size);
}
console.log(
	`\n${pack.name}@${pack.version}  ${kb(pack.size)} tarball, ${kb(pack.unpackedSize)} unpacked\n`,
);
for (const [kind, size] of [...buckets].sort((a, b) => b[1] - a[1]))
	console.log(
		`  ${pad(kb(size), 9)}  ${pad(`${((size / pack.unpackedSize) * 100).toFixed(0)}%`, 4)}  ${kind}`,
	);

// A sourcemap that inlines sourcesContent ships the source twice per format.
for (const f of pack.files.filter((f) => f.path.endsWith(".map"))) {
	const { sourcesContent } = JSON.parse(readFileSync(f.path, "utf8")) as {
		sourcesContent?: (string | null)[];
	};
	const inlined = (sourcesContent ?? []).reduce((a, s) => a + (s?.length ?? 0), 0);
	if (inlined > 0) console.log(`  ${pad(kb(inlined), 9)}        └ inlined sources in ${f.path}`);
}

// ── per-export cost to a consumer ───────────────────────────────────────────
// Each entry is bundled alone, so the number is what that export drags in:
// its own code plus every dependency it reaches.
const EXPORTS = Object.keys(await import(new URL(ENTRY, `file://${process.cwd()}/`).href)).filter(
	(n) => n !== "default",
);
const cases: [string, string[]][] = [
	...EXPORTS.map((n): [string, string[]] => [n, [n]]),
	["(everything)", EXPORTS],
];

const bundle = async (names: string[]) => {
	const result = await build({
		// console.log keeps the imports live; without a use esbuild drops them all.
		stdin: {
			contents: `import {${names}} from "${ENTRY}";console.log(${names})`,
			resolveDir: ".",
			loader: "js",
		},
		bundle: true,
		format: "esm",
		target: "es2022",
		minify: true,
		write: false,
		metafile: true,
		logLevel: "silent",
	});
	const out = Object.values(result.metafile.outputs)[0];
	const file = result.outputFiles[0];
	if (!out || !file) throw new Error("esbuild produced no output");
	return { out, contents: file.contents, metafile: result.metafile };
};

const pkg = (p: string) => {
	if (!p.includes("node_modules")) return "(self)";
	const r = p.replace(/.*node_modules\//, "");
	return r.startsWith("@") ? r.split("/").slice(0, 2).join("/") : r.split("/")[0];
};

console.log("\n  bundled     gzip   export / dependencies reached");
const rows: [string, number, number, string[]][] = [];
for (const [label, names] of cases) {
	const { out, contents } = await bundle(names);
	const deps = new Set<string>();
	for (const [p, { bytesInOutput }] of Object.entries(out.inputs))
		if (bytesInOutput && p.includes("node_modules")) deps.add(pkg(p) ?? p);
	rows.push([label, out.bytes, gzipSync(contents).length, [...deps]]);
}
const [everything] = rows.splice(rows.length - 1);
rows.sort((a, b) => b[1] - a[1]);
for (const [label, bytes, gz, deps] of everything ? [...rows, everything] : rows)
	console.log(
		`  ${pad(kb(bytes), 9)}  ${pad(kb(gz), 8)}   ${label}${deps.length ? `  → ${deps.join(" ")}` : ""}`,
	);

// ── treemap ─────────────────────────────────────────────────────────────────
if (process.argv.includes("--html")) {
	const { visualizer } = await import("esbuild-visualizer");
	const { metafile } = await bundle(EXPORTS);
	writeFileSync("size.html", await visualizer(metafile, { title: `${pack.name}@${pack.version}` }));
	console.log(`\n  size.html  ${kb(statSync("size.html").size)}  (full export surface)`);
}
