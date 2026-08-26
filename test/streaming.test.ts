import { describe, expect, it } from "vitest";
import { collectStream } from "../src/streaming.js";

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
