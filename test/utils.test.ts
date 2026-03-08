import { describe, expect, it } from "vitest";
import { concat } from "../src/utils.js";
import {
	constantTimeEqual,
	decodeNumber,
	encodeNumber,
	encodeString,
	fromHex,
	toHex,
	xor,
} from "./test-utils.js";

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

describe("constantTimeEqual", () => {
	it("returns true for equal arrays", () => {
		const a = new Uint8Array([1, 2, 3, 4]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(constantTimeEqual(a, b)).toBe(true);
	});

	it("returns false for different arrays", () => {
		const a = new Uint8Array([1, 2, 3, 4]);
		const b = new Uint8Array([1, 2, 3, 5]);
		expect(constantTimeEqual(a, b)).toBe(false);
	});

	it("returns false for different lengths", () => {
		const a = new Uint8Array([1, 2, 3]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(constantTimeEqual(a, b)).toBe(false);
	});

	it("handles empty arrays", () => {
		expect(constantTimeEqual(new Uint8Array([]), new Uint8Array([]))).toBe(true);
	});

	it("detects difference at any position", () => {
		const base = new Uint8Array([0, 0, 0, 0]);
		for (let i = 0; i < 4; i++) {
			const different = new Uint8Array([0, 0, 0, 0]);
			different[i] = 1;
			expect(constantTimeEqual(base, different)).toBe(false);
		}
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

	it("concatenates multiple arrays", () => {
		const a = new Uint8Array([1, 2]);
		const b = new Uint8Array([3, 4, 5]);
		const c = new Uint8Array([6]);
		expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
	});
});

describe("encodeNumber", () => {
	it("encodes single byte", () => {
		expect(encodeNumber(0, 1)).toEqual(new Uint8Array([0x00]));
		expect(encodeNumber(255, 1)).toEqual(new Uint8Array([0xff]));
	});

	it("encodes two bytes big-endian", () => {
		expect(encodeNumber(0x0102, 2)).toEqual(new Uint8Array([0x01, 0x02]));
		expect(encodeNumber(0xffff, 2)).toEqual(new Uint8Array([0xff, 0xff]));
	});

	it("encodes four bytes with zero padding", () => {
		expect(encodeNumber(1, 4)).toEqual(new Uint8Array([0x00, 0x00, 0x00, 0x01]));
	});

	it("encodes arbitrary length for nonce counter", () => {
		// 12-byte encoding for AEAD nonce XOR
		expect(encodeNumber(1, 12)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
		expect(encodeNumber(0x0102, 12)).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]));
	});
});

describe("decodeNumber", () => {
	it("decodes single byte", () => {
		expect(decodeNumber(new Uint8Array([0xff]))).toBe(255);
	});

	it("decodes two bytes big-endian", () => {
		expect(decodeNumber(new Uint8Array([0x01, 0x02]))).toBe(0x0102);
	});

	it("decodes four bytes big-endian", () => {
		expect(decodeNumber(new Uint8Array([0x00, 0x00, 0x00, 0x01]))).toBe(1);
		expect(decodeNumber(new Uint8Array([0x12, 0x34, 0x56, 0x78]))).toBe(0x12345678);
	});

	it("returns undefined for unsupported lengths", () => {
		expect(decodeNumber(new Uint8Array([]))).toBeUndefined();
		expect(decodeNumber(new Uint8Array(3))).toBeUndefined();
		expect(decodeNumber(new Uint8Array(5))).toBeUndefined();
		expect(decodeNumber(new Uint8Array(12))).toBeUndefined();
	});
});

describe("xor", () => {
	it("XORs equal length arrays", () => {
		const a = new Uint8Array([0xff, 0x00, 0xaa]);
		const b = new Uint8Array([0x0f, 0xf0, 0x55]);
		expect(xor(a, b)).toEqual(new Uint8Array([0xf0, 0xf0, 0xff]));
	});

	it("throws for different lengths", () => {
		const a = new Uint8Array([1, 2]);
		const b = new Uint8Array([1, 2, 3]);
		expect(() => xor(a, b)).toThrow();
	});

	it("XOR with zeros is identity", () => {
		const a = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		const zeros = new Uint8Array(4);
		expect(xor(a, zeros)).toEqual(a);
	});

	it("XOR with self is zeros", () => {
		const a = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		expect(xor(a, a)).toEqual(new Uint8Array(4));
	});
});

describe("encodeString", () => {
	it("encodes ASCII string", () => {
		expect(encodeString("hello")).toEqual(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]));
	});

	it("encodes empty string", () => {
		expect(encodeString("")).toEqual(new Uint8Array([]));
	});
});
