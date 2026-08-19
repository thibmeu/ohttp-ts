// What does this package cost to install, and what does each export cost a
// consumer who bundles it? Both questions are answered from the built dist,
// so the numbers are the ones a downstream project actually sees.
//
//   node tools/size.mjs           install + per-export table
//   node tools/size.mjs --html    also write size.html (treemap of `everything`)
import { execFileSync } from "node:child_process";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";

const ENTRY = "./dist/index.mjs";
const kb = (n) => `${(n / 1024).toFixed(1)} kB`;
const pad = (s, n) => String(s).padStart(n);

// ── install size ────────────────────────────────────────────────────────────
// npm pack is the source of truth: it applies "files", .npmignore and all.
const pack = JSON.parse(
	execFileSync("npm", ["pack", "--dry-run", "--json"], { encoding: "utf8" }),
)[0];
const KINDS = [
	[/\.map$/, "sourcemaps"],
	[/\.d\.[cm]ts$/, "types"],
	[/^src\//, "source (for sourcemaps)"],
	[/\.[cm]js$/, "code"],
	[/./, "other"],
];
const buckets = new Map();
for (const f of pack.files) {
	const kind = KINDS.find(([re]) => re.test(f.path))[1];
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
	const { sourcesContent } = JSON.parse(readFileSync(f.path, "utf8"));
	const inlined = (sourcesContent ?? []).reduce((a, s) => a + (s?.length ?? 0), 0);
	if (inlined > 0) console.log(`  ${pad(kb(inlined), 9)}        └ inlined sources in ${f.path}`);
}

// ── per-export cost to a consumer ───────────────────────────────────────────
// Each entry is bundled alone, so the number is what that export drags in:
// its own code plus every dependency it reaches.
const EXPORTS = Object.keys(await import(new URL(ENTRY, `file://${process.cwd()}/`).href)).filter(
	(n) => n !== "default",
);
const cases = [...EXPORTS.map((n) => [n, [n]]), ["(everything)", EXPORTS]];

const bundle = (names) =>
	build({
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

const pkg = (p) => {
	if (!p.includes("node_modules")) return "(self)";
	const r = p.replace(/.*node_modules\//, "");
	return r.startsWith("@") ? r.split("/").slice(0, 2).join("/") : r.split("/")[0];
};

console.log("\n  bundled     gzip   export / dependencies reached");
const rows = [];
for (const [label, names] of cases) {
	const r = await bundle(names);
	const [out] = Object.values(r.metafile.outputs);
	const deps = new Set();
	for (const [p, { bytesInOutput }] of Object.entries(out.inputs))
		if (bytesInOutput && p.includes("node_modules")) deps.add(pkg(p));
	rows.push([label, out.bytes, gzipSync(r.outputFiles[0].contents).length, [...deps]]);
}
const [everything] = rows.splice(rows.length - 1);
rows.sort((a, b) => b[1] - a[1]);
for (const [label, bytes, gz, deps] of [...rows, everything])
	console.log(
		`  ${pad(kb(bytes), 9)}  ${pad(kb(gz), 8)}   ${label}${deps.length ? `  → ${deps.join(" ")}` : ""}`,
	);

// ── treemap ─────────────────────────────────────────────────────────────────
if (process.argv.includes("--html")) {
	const { visualizer } = await import("esbuild-visualizer");
	const r = await bundle(EXPORTS);
	writeFileSync(
		"size.html",
		await visualizer(r.metafile, { title: `${pack.name}@${pack.version}` }),
	);
	console.log(`\n  size.html  ${kb(statSync("size.html").size)}  (full export surface)`);
}
