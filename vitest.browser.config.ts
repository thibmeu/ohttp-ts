import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		setupFiles: ["./test/props-setup.ts"],
		// Property tests run 200 cases each; the 5s default trips them under
		// parallel load even though each passes on its own.
		testTimeout: 30_000,
		browser: {
			enabled: true,
			provider: playwright(),
			instances: [{ browser: "chromium" }],
		},
	},
});
