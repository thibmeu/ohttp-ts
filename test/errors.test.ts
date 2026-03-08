import { describe, expect, it } from "vitest";
import { OHTTPError, OHTTPErrorCode, isOHTTPError } from "../src/errors.js";

describe("OHTTPError", () => {
	it("creates error with code", () => {
		const error = new OHTTPError(OHTTPErrorCode.DecryptionFailed);
		expect(error.code).toBe("DECRYPTION_FAILED");
		expect(error.name).toBe("OHTTPError");
		expect(error.message).toBe("OHTTP error: DECRYPTION_FAILED");
	});

	it("is instance of Error", () => {
		const error = new OHTTPError(OHTTPErrorCode.InvalidKeyConfig);
		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(OHTTPError);
	});

	it("has opaque message without details", () => {
		// Verify messages don't leak sensitive info
		const decryptError = new OHTTPError(OHTTPErrorCode.DecryptionFailed);
		expect(decryptError.message).not.toContain("key");
		expect(decryptError.message).not.toContain("nonce");
		expect(decryptError.message).not.toContain("ciphertext");
	});

	it("supports all error codes", () => {
		const codes = Object.values(OHTTPErrorCode);
		expect(codes.length).toBeGreaterThan(0);

		for (const code of codes) {
			const error = new OHTTPError(code);
			expect(error.code).toBe(code);
		}
	});
});

describe("isOHTTPError", () => {
	it("returns true for OHTTPError", () => {
		const error = new OHTTPError(OHTTPErrorCode.InvalidMessage);
		expect(isOHTTPError(error)).toBe(true);
	});

	it("returns false for regular Error", () => {
		const error = new Error("test");
		expect(isOHTTPError(error)).toBe(false);
	});

	it("returns false for non-error values", () => {
		expect(isOHTTPError(null)).toBe(false);
		expect(isOHTTPError(undefined)).toBe(false);
		expect(isOHTTPError("error")).toBe(false);
		expect(isOHTTPError({ code: "DECRYPTION_FAILED" })).toBe(false);
	});
});
