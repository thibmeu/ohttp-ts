import { describe, expect, it } from "vitest";
import { isMediaType, MediaType } from "../src/constants.js";

describe("isMediaType", () => {
	it("matches type and subtype case-insensitively", () => {
		expect(isMediaType("Message/OHTTP-Req", MediaType.REQUEST)).toBe(true);
	});

	it("rejects parameters", () => {
		expect(isMediaType("message/ohttp-req; version=1", MediaType.REQUEST)).toBe(false);
	});
});
