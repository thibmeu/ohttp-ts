import { describe, expect, it } from "vitest";
import * as constants from "../src/constants.js";
import * as incremental from "../src/incremental.js";
import { Incremental, KeyConfig, Labels } from "../src/index.js";
import * as keyConfig from "../src/keyConfig.js";

/**
 * The rest of the suite imports `src/*.js` directly, so nothing exercises the
 * public entry's own namespace objects. A typo or a rename in the barrel would
 * otherwise only show up in a consumer's build.
 */
describe("public entry namespaces", () => {
	it.each([
		["KeyConfig", KeyConfig, keyConfig],
		["Incremental", Incremental, incremental],
		["Labels", Labels, constants],
	] as const)("%s re-exports live values", (_name, namespace, module) => {
		const values = Object.values(namespace);
		expect(values.length).toBeGreaterThan(0);
		for (const value of values) {
			expect(value).toBeDefined();
			// Every member must be the same binding the source module exports,
			// not a stale copy or a lookalike.
			expect(Object.values(module)).toContain(value);
		}
	});
});
