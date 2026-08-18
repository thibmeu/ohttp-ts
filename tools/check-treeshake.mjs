/**
 * A relay, or anything that only needs the protocol's constants and errors,
 * must not pull in the crypto and Binary HTTP dependencies. That holds only
 * while no module reachable from those exports runs a side effect at module
 * scope — a bare `new Foo()` at the top level pins the module that defines
 * `Foo`, and a bundler cannot prove otherwise.
 *
 * Bundle the lightweight exports and assert nothing from node_modules survives.
 */
import { build } from "esbuild";

const LIGHTWEIGHT = [
	"AeadId",
	"Incremental",
	"isOHTTPError",
	"KdfId",
	"KemId",
	"Labels",
	"MediaType",
	"OHTTPError",
	"OHTTPErrorCode",
];

const result = await build({
	stdin: {
		contents: `import { ${LIGHTWEIGHT.join(", ")} } from "./src/index.ts";\nconsole.log(${LIGHTWEIGHT.join(", ")});\n`,
		resolveDir: ".",
		loader: "ts",
	},
	bundle: true,
	format: "esm",
	target: "es2022",
	write: false,
	metafile: true,
});

const [output] = Object.values(result.metafile.outputs);
const leaked = Object.entries(output.inputs)
	.filter(([path, { bytesInOutput }]) => path.includes("node_modules") && bytesInOutput > 0)
	.map(([path, { bytesInOutput }]) => `  ${path} (${bytesInOutput} bytes)`);

if (leaked.length > 0) {
	console.error(
		`The lightweight exports pull in ${leaked.length} dependency module(s):\n${leaked.join("\n")}\n\n` +
			"Something they reach constructs a value at module scope. Move it into its own module.",
	);
	process.exit(1);
}

console.log(`Lightweight exports bundle to ${output.bytes} bytes, no dependencies.`);
