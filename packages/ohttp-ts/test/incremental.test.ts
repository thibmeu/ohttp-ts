import { describe, expect, it } from "vitest";
import {
	INCREMENTAL_HEADER,
	createIncrementalHeaders,
	getIncremental,
	parseIncremental,
	serializeIncremental,
	setIncremental,
} from "../src/incremental.js";

describe("serializeIncremental", () => {
	it("serializes true as ?1", () => {
		expect(serializeIncremental(true)).toBe("?1");
	});

	it("serializes false as ?0", () => {
		expect(serializeIncremental(false)).toBe("?0");
	});
});

describe("parseIncremental", () => {
	it("parses ?1 as true", () => {
		expect(parseIncremental("?1")).toBe(true);
	});

	it("parses ?0 as false", () => {
		expect(parseIncremental("?0")).toBe(false);
	});

	it("handles leading/trailing whitespace", () => {
		expect(parseIncremental("  ?1  ")).toBe(true);
		expect(parseIncremental("\t?0\t")).toBe(false);
	});

	it("handles parameters after semicolon", () => {
		// Per RFC 9651, parameters can follow the value
		expect(parseIncremental("?1;foo=bar")).toBe(true);
		expect(parseIncremental("?0;baz")).toBe(false);
	});

	it("returns undefined for invalid values", () => {
		expect(parseIncremental("")).toBeUndefined();
		expect(parseIncremental("true")).toBeUndefined();
		expect(parseIncremental("false")).toBeUndefined();
		expect(parseIncremental("1")).toBeUndefined();
		expect(parseIncremental("0")).toBeUndefined();
		expect(parseIncremental("?")).toBeUndefined();
		expect(parseIncremental("?2")).toBeUndefined();
		expect(parseIncremental("?11")).toBeUndefined();
		expect(parseIncremental("??1")).toBeUndefined();
	});

	it("returns undefined for non-boolean structured field types", () => {
		// Integer
		expect(parseIncremental("42")).toBeUndefined();
		// String
		expect(parseIncremental('"hello"')).toBeUndefined();
		// Token
		expect(parseIncremental("foo")).toBeUndefined();
	});
});

describe("createIncrementalHeaders", () => {
	it("creates headers with Incremental: ?1 by default", () => {
		const headers = createIncrementalHeaders();
		expect(headers.get(INCREMENTAL_HEADER)).toBe("?1");
	});

	it("creates headers with Incremental: ?1 when true", () => {
		const headers = createIncrementalHeaders(true);
		expect(headers.get(INCREMENTAL_HEADER)).toBe("?1");
	});

	it("creates headers with Incremental: ?0 when false", () => {
		const headers = createIncrementalHeaders(false);
		expect(headers.get(INCREMENTAL_HEADER)).toBe("?0");
	});
});

describe("getIncremental", () => {
	it("returns true for Incremental: ?1", () => {
		const headers = new Headers();
		headers.set(INCREMENTAL_HEADER, "?1");
		expect(getIncremental(headers)).toBe(true);
	});

	it("returns false for Incremental: ?0", () => {
		const headers = new Headers();
		headers.set(INCREMENTAL_HEADER, "?0");
		expect(getIncremental(headers)).toBe(false);
	});

	it("returns undefined when header not present", () => {
		const headers = new Headers();
		expect(getIncremental(headers)).toBeUndefined();
	});

	it("returns undefined for invalid values", () => {
		const headers = new Headers();
		headers.set(INCREMENTAL_HEADER, "invalid");
		expect(getIncremental(headers)).toBeUndefined();
	});
});

describe("setIncremental", () => {
	it("sets Incremental: ?1 on existing headers", () => {
		const headers = new Headers();
		headers.set("Content-Type", "application/octet-stream");

		setIncremental(headers, true);

		expect(headers.get(INCREMENTAL_HEADER)).toBe("?1");
		expect(headers.get("Content-Type")).toBe("application/octet-stream");
	});

	it("overwrites existing Incremental header", () => {
		const headers = new Headers();
		headers.set(INCREMENTAL_HEADER, "?1");

		setIncremental(headers, false);

		expect(headers.get(INCREMENTAL_HEADER)).toBe("?0");
	});
});

describe("INCREMENTAL_HEADER constant", () => {
	it("equals 'Incremental'", () => {
		expect(INCREMENTAL_HEADER).toBe("Incremental");
	});
});
