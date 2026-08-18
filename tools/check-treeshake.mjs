/**
 * A module-scope side effect pins whatever module runs it, and a bundler cannot
 * prove otherwise: one stray `new Foo()` next to a constant drags all of Foo's
 * package into anyone importing that constant. It is invisible in review and
 * only shows up in a consumer's bundle.
 *
 * So bundle the entry points that should stay light and check what survives.
 */
import { build } from "esbuild";

const ENTRIES = [
	{
		// A relay routes bytes: it needs the media types and the error taxonomy.
		what: "constants and errors",
		imports: [
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
		allowed: [],
	},
	{
		// Framing is varint work, and quicvarint is the varint implementation.
		what: "framing primitives",
		imports: ["frameChunk", "parseFramedChunk"],
		allowed: ["quicvarint"],
	},
	{
		// keyConfig.ts imports hpke for types only; a value import would cost 5.8 kB.
		what: "key configuration",
		imports: ["KeyConfig"],
		allowed: [],
	},
];

let failed = false;

for (const { what, imports, allowed } of ENTRIES) {
	const result = await build({
		stdin: {
			contents: `import { ${imports.join(", ")} } from "./src/index.ts";\nconsole.log(${imports.join(", ")});\n`,
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
	const pulled = Object.entries(output.inputs)
		.filter(([path, { bytesInOutput }]) => path.includes("node_modules") && bytesInOutput > 0)
		.map(([path, { bytesInOutput }]) => ({
			name: path.replace(/.*node_modules\//, "").split("/")[0],
			bytes: bytesInOutput,
		}));

	const leaked = pulled.filter(({ name }) => !allowed.includes(name));
	const summary =
		pulled.map(({ name, bytes }) => `${name} ${bytes} B`).join(", ") || "no dependencies";
	console.log(`${what}: ${output.bytes} B, ${summary}`);

	for (const { name, bytes } of leaked) {
		console.error(`  ${name} (${bytes} B) should not be reachable from these exports.`);
		failed = true;
	}
}

if (failed) {
	console.error(
		"\nSomething these exports reach runs at module scope. Move it into its own module.",
	);
	process.exit(1);
}
