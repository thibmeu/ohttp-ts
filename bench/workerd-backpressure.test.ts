/** Backpressure diagnostic executed inside workerd by the Workers Vitest plugin. */

import { describe, expect, it } from "vitest";
import { measuredSource } from "./backpressure-probe.ts";
import { chunkedClient } from "./fixtures.ts";

const PAYLOAD_SIZE = 32 * 1024 * 1024;
const SOURCE_CHUNK_SIZE = 64 * 1024;
const OBSERVATION_MS = 1_000;

describe("workerd streaming backpressure", () => {
	it("should report bounded plaintext read-ahead while the network is stalled", async () => {
		// Arrange
		const source = measuredSource(PAYLOAD_SIZE, SOURCE_CHUNK_SIZE);
		const request = new Request("https://target.example/upload", {
			method: "POST",
			body: source.stream,
		});

		// Act
		const { init } = await chunkedClient.encapsulateRequest(request);
		const networkBody = init.body;
		expect(networkBody).toBeInstanceOf(ReadableStream);
		await new Promise((resolve) => setTimeout(resolve, OBSERVATION_MS));

		const bytesRead = source.bytesRead();
		console.log("workerd stalled-stream backpressure", {
			payloadBytes: PAYLOAD_SIZE,
			sourceChunkBytes: SOURCE_CHUNK_SIZE,
			observationMs: OBSERVATION_MS,
			plaintextBytesRead: bytesRead,
			sourcePulls: source.pulls(),
			readAheadPercent: (bytesRead / PAYLOAD_SIZE) * 100,
		});

		// Assert
		expect(bytesRead).toBeLessThan(PAYLOAD_SIZE);
		await (networkBody as ReadableStream).cancel("benchmark complete");
	});
});
