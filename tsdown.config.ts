import { defineConfig } from "tsdown";

export default defineConfig({
	format: ["esm"],
	target: "es2022",
	// Maps without inlined sourcesContent, paired with src/ in "files": the
	// source ships once instead of once per format, and debuggers still resolve
	// it through the relative paths in the map.
	sourcemap: true,
	outputOptions: { sourcemapExcludeSources: true },
});
