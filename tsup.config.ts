import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm", "cjs"],
	dts: true,
	clean: true,
	sourcemap: true,
	target: "es2022",
	minify: false,
	splitting: false,
	// Bundle bhttp-js since it's vendored and file: deps don't work when published
	noExternal: ["bhttp-js"],
});
