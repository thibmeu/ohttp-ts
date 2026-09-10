import { AEAD_AES_128_GCM, type RecipientContext, type SenderContext } from "hpke";
import { describe, expect, it } from "vitest";
import {
	collectStream,
	createRequestDecryptTransform,
	createRequestEncryptTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
} from "../src/streaming.js";

describe("streaming crypto pipeline", () => {
	it.for(["request encrypt", "response encrypt", "request decrypt", "response decrypt"])(
		"should emit completed %s output while the producer pauses without closing",
		{ timeout: 1000 },
		async (kind, { onTestFinished }) => {
			// Arrange: two plaintext chunks, or one complete non-final frame.
			const encrypt = kind.endsWith("encrypt");
			const result = new Uint8Array(encrypt ? 17 : 1).fill(7);
			const transform = cryptoTransform(kind, async () => result);
			const writer = transform.writable.getWriter();
			const reader = transform.readable.getReader();
			void writer.closed.catch(() => {});
			onTestFinished(() => reader.cancel());

			// Act: keep the producer open until the output has been read.
			const first = reader.read();
			await writer.write(
				encrypt ? new Uint8Array([1]) : new Uint8Array([17, ...new Uint8Array(17)]),
			);
			if (encrypt) await writer.write(new Uint8Array([2]));

			// Assert: no further input or close is needed to release the result.
			await expect(first).resolves.toEqual({
				done: false,
				value: encrypt ? new Uint8Array([17]) : result,
			});
			if (encrypt) await expect(reader.read()).resolves.toEqual({ done: false, value: result });
		},
	);

	it("should cap crypto concurrency at four and preserve order through close", async () => {
		// Arrange: hold the first four seals, then finish them in reverse order.
		const releases: Array<() => void> = [];
		let calls = 0;
		const transform = cryptoTransform("response encrypt", () => {
			const value = new Uint8Array(17).fill(++calls);
			return calls > 4
				? Promise.resolve(value)
				: new Promise((resolve) => releases.push(() => resolve(value)));
		});
		const source = new ReadableStream<Uint8Array>({
			start(controller) {
				for (let i = 0; i < 5; i++) controller.enqueue(new Uint8Array([i]));
				controller.close();
			},
		});

		// Act: downstream is reading, but crypto cannot finish yet.
		const output = collectStream(source.pipeThrough(transform));
		await expect.poll(() => calls).toBe(4);
		for (const release of releases.reverse()) release();

		// Assert: the final seal also respects the ceiling and FIFO output order.
		expect(await output).toEqual(
			new Uint8Array(
				[1, 2, 3, 4, 5].flatMap((i) => [i === 5 ? 0 : 17, ...new Uint8Array(17).fill(i)]),
			),
		);
	});
});

describe("collectStream", () => {
	it("collects more chunks than the argument limit", async () => {
		let remaining = 250_001;
		const byte = new Uint8Array([1]);
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) {
				if (remaining-- > 0) controller.enqueue(byte);
				else controller.close();
			},
		});

		const result = await collectStream(stream);

		expect(result).toHaveLength(250_001);
	});
});

// Helpers

function cryptoTransform(kind: string, operation: () => Promise<Uint8Array>) {
	const aead = { ...AEAD_AES_128_GCM(), Seal: operation, Open: operation };
	const key = new Uint8Array(16);
	const nonce = new Uint8Array(12);
	switch (kind) {
		case "request encrypt":
			return createRequestEncryptTransform({ Seal: operation } as SenderContext);
		case "request decrypt":
			return createRequestDecryptTransform({ Open: operation } as RecipientContext);
		case "response encrypt":
			return createResponseEncryptTransform(aead, key, nonce);
		default:
			return createResponseDecryptTransform(aead, key, nonce);
	}
}
