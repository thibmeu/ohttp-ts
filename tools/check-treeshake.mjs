// A module-scope `new` pins its module, and with it every package that module
// imports, into anyone importing anything else from the same file. The diff
// that causes it looks fine; the cost only shows up in a consumer's bundle.
import { build } from "esbuild";

const ENTRIES = [
	// [what should stay light, the dependencies it may legitimately reach]
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
			contents: `import { ${imports} } from "./src/index.ts";\nconsole.log(${imports});`,
			resolveDir: ".",
			loader: "ts",
		},
		bundle: true,
		format: "esm",
		target: "es2022",
		write: false,
		metafile: true,
	});
	const [out] = Object.values(metafile.outputs);
	const deps = Object.entries(out.inputs)
		.filter(([path, { bytesInOutput }]) => path.includes("node_modules") && bytesInOutput > 0)
		.map(([path]) => path.replace(/.*node_modules\//, "").split("/")[0]);
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
