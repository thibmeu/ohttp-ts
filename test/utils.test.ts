import { describe, expect, it } from "vitest";
import { concat } from "../src/utils.js";
import { fromHex, toHex } from "./test-utils.js";

describe("toHex", () => {
	it("encodes empty array", () => {
		expect(toHex(new Uint8Array([]))).toBe("");
	});

	it("encodes single byte", () => {
		expect(toHex(new Uint8Array([0x00]))).toBe("00");
		expect(toHex(new Uint8Array([0xff]))).toBe("ff");
		expect(toHex(new Uint8Array([0x0a]))).toBe("0a");
	});

	it("encodes multiple bytes", () => {
		expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe("deadbeef");
	});
});

describe("fromHex", () => {
	it("decodes empty string", () => {
		expect(fromHex("")).toEqual(new Uint8Array([]));
	});

	it("decodes valid hex", () => {
		expect(fromHex("deadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
		expect(fromHex("DEADBEEF")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
	});

	it("returns undefined for odd length", () => {
		expect(fromHex("abc")).toBeUndefined();
	});

	it("returns undefined for invalid characters", () => {
		expect(fromHex("ghij")).toBeUndefined();
		expect(fromHex("ab cd")).toBeUndefined();
	});
});

describe("concat", () => {
	it("concatenates empty arrays", () => {
		expect(concat()).toEqual(new Uint8Array([]));
	});

	it("concatenates single array", () => {
		const arr = new Uint8Array([1, 2, 3]);
		expect(concat(arr)).toEqual(arr);
	});

	it("concatenates an array of many parts", () => {
		const parts = Array.from({ length: 100_000 }, () => new Uint8Array([1]));
		expect(concat(parts)).toHaveLength(parts.length);
	});

	it("concatenates multiple arrays", () => {
		const a = new Uint8Array([1, 2]);
		const b = new Uint8Array([3, 4, 5]);
		const c = new Uint8Array([6]);
		expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
	});
});
