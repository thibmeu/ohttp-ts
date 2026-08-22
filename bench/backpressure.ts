/**
 * Streaming backpressure benchmark (Node-only).
 *
 * Models a network that accepts the RequestInit but does not consume its body.
 * A backpressure-preserving pipeline should pull only a bounded amount from the
 * plaintext source. An eager adapter instead drains the source and retains the
 * encrypted output in its own ReadableStream queue.
 *
 * The primary signal is `plaintext read ahead`: it is counted at the source
 * during an explicit observation window. ArrayBuffer/RSS deltas are included
 * as supporting diagnostics only.
 *
 * Run: npm run bench:backpressure
 *      SIZE=67108864 CHUNK=65536 OBSERVE_MS=2000 npm run bench:backpressure
 */

import { chunkedClient } from "./fixtures.js";

declare const gc: (() => void) | undefined;

const payloadSize = readPositiveInteger("SIZE", 32 * 1024 * 1024);
const sourceChunkSize = readPositiveInteger("CHUNK", 64 * 1024);
const observationMs = readPositiveInteger("OBSERVE_MS", 1_000);

interface SourceProbe {
	readonly stream: ReadableStream<Uint8Array>;
	readonly bytesRead: () => number;
	readonly pulls: () => number;
}

function measuredSource(totalBytes: number, chunkSize: number): SourceProbe {
	let produced = 0;
	let pullCount = 0;

	return {
		stream: new ReadableStream<Uint8Array>({
			pull(controller) {
				if (produced >= totalBytes) {
					controller.close();
					return;
				}

				const size = Math.min(chunkSize, totalBytes - produced);
				// Allocate distinct backing stores so eager read-ahead creates real
				// memory pressure instead of repeatedly enqueueing the same buffer.
				const chunk = new Uint8Array(size);
				chunk[0] = pullCount & 0xff;
				produced += size;
				pullCount++;
				controller.enqueue(chunk);
			},
		}),
		bytesRead: () => produced,
		pulls: () => pullCount,
	};
}

function memory(): NodeJS.MemoryUsage {
	gc?.();
	gc?.();
	return process.memoryUsage();
}

function formatBytes(bytes: number): string {
	const sign = bytes < 0 ? "-" : "";
	const value = Math.abs(bytes);
	if (value >= 1024 * 1024) return `${sign}${(value / 1024 / 1024).toFixed(2)} MiB`;
	if (value >= 1024) return `${sign}${(value / 1024).toFixed(1)} KiB`;
	return `${sign}${value} B`;
}

function readPositiveInteger(name: string, fallback: number): number {
	const raw = process.env[name];
	if (raw === undefined) return fallback;
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new RangeError(`${name} must be a positive integer, got ${raw}`);
	}
	return value;
}

async function main(): Promise<void> {
	if (!gc) throw new Error("run with --expose-gc (use `npm run bench:backpressure`)");

	const source = measuredSource(payloadSize, sourceChunkSize);
	const request = new Request("https://target.example/upload", {
		method: "POST",
		body: source.stream,
		duplex: "half",
	} as RequestInit & { duplex: "half" });
	const before = memory();

	// The simulated network receives the body but deliberately does not read it.
	const { init } = await chunkedClient.encapsulateRequest(request);
	const networkBody = init.body;
	if (!(networkBody instanceof ReadableStream)) {
		throw new TypeError("encapsulated request body is not a ReadableStream");
	}
	await new Promise((resolve) => setTimeout(resolve, observationMs));

	const after = process.memoryUsage();
	const readAhead = source.bytesRead();
	const readAheadRatio = readAhead / payloadSize;

	console.log("Chunked request backpressure under a stalled network\n");
	console.log(`payload:                    ${formatBytes(payloadSize)}`);
	console.log(`source chunk:               ${formatBytes(sourceChunkSize)}`);
	console.log(`stalled observation:        ${observationMs} ms`);
	console.log(`network bytes consumed:     0 B`);
	console.log(`plaintext read ahead:       ${formatBytes(readAhead)}`);
	console.log(`source pulls:               ${source.pulls()}`);
	console.log(`payload read-ahead ratio:   ${(readAheadRatio * 100).toFixed(1)}%`);
	console.log(
		`ArrayBuffer delta:          ${formatBytes(after.arrayBuffers - before.arrayBuffers)}`,
	);
	console.log(`RSS delta:                  ${formatBytes(after.rss - before.rss)}`);
	console.log(
		readAhead === payloadSize
			? "\nResult: the complete plaintext source was drained before the network requested a byte."
			: "\nResult: plaintext production remained bounded while the network was stalled.",
	);

	// Release all queued ciphertext and propagate cancellation to the source.
	await networkBody.cancel("benchmark complete");
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
