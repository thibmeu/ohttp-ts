import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [
		cloudflareTest({
			miniflare: {
				compatibilityDate: "2026-08-01",
			},
		}),
	],
	test: {
		include: ["test/**/*.test.ts"],
		setupFiles: ["./test/props-setup.ts"],
		// Property tests run 200 cases each; the 5s default trips them under
		// parallel load even though each passes on its own.
		testTimeout: 30_000,
	},
});
