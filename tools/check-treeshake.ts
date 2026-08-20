/**
 * Tree-shaking guard for the light exports (Node-only dev tool).
 *
 * A module-scope `new` pins its module, and with it every package that module
 * imports, into anyone importing anything else from the same file. The diff
 * that causes it looks fine; the cost only shows up in a consumer's bundle.
 *
 * Run: npm run check:treeshake
 */

import { existsSync } from "node:fs";
import { build } from "esbuild";

const ENTRY = "./dist/index.mjs";
if (!existsSync(ENTRY)) {
	console.error(`${ENTRY} is missing. Run npm run build first.`);
	process.exit(1);
}

/** [what should stay light, the dependencies it may legitimately reach] */
const ENTRIES: [string[], string[]][] = [
	[
		[
			"AeadId",
			"Incremental",
			"isOHTTPError",
			"KdfId",
			"KemId",
			"Labels",
			"MediaType",
			"OHTTPError",
			"OHTTPErrorCode",
		],
		[],
	],
	[["frameChunk", "parseFramedChunk"], ["quicvarint"]],
	[["KeyConfig"], []],
];

for (const [imports, allowed] of ENTRIES) {
	const { metafile } = await build({
		stdin: {
			contents: `import { ${imports} } from "${ENTRY}";\nconsole.log(${imports});`,
			resolveDir: ".",
			loader: "js",
		},
		bundle: true,
		format: "esm",
		target: "es2022",
		write: false,
		metafile: true,
	});
	const out = Object.values(metafile.outputs)[0];
	if (!out) throw new Error("esbuild produced no output");
	const deps = Object.entries(out.inputs)
		.filter(([path, { bytesInOutput }]) => path.includes("node_modules") && bytesInOutput > 0)
		.map(([path]) => path.replace(/.*node_modules\//, "").split("/")[0] ?? path);
	const leaked = deps.filter((d) => !allowed.includes(d));
	console.log(
		`${imports[0]}, …: ${out.bytes} B, ${[...new Set(deps)].join(" ") || "no dependencies"}`,
	);
	if (leaked.length > 0) {
		console.error(
			`  unexpected: ${[...new Set(leaked)].join(" ")}. Something these exports reach runs at module scope.`,
		);
		process.exitCode = 1;
	}
}
