/**
 * Incremental Processing Benchmark
 *
 * Demonstrates streaming's advantage when:
 * 1. Source produces data slowly (network)
 * 2. Consumer can process data incrementally
 *
 * Example: Search indexing where each chunk can be processed independently
 */

import { performance } from "node:perf_hooks";
import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { AeadId, ChunkedOHTTPClient, ChunkedOHTTPServer, KdfId, KeyConfig } from "../src/index.js";

async function setup() {
	const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const keyConfig = await KeyConfig.generate(suite, 0x01, [
		{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
	]);
	return { suite, keyConfig };
}

function createSlowStream(
	totalSize: number,
	chunkSize: number,
	delayMs: number,
): ReadableStream<Uint8Array> {
	let produced = 0;
	return new ReadableStream({
		async pull(controller) {
			if (produced >= totalSize) {
				controller.close();
				return;
			}
			await new Promise((r) => setTimeout(r, delayMs));
			const size = Math.min(chunkSize, totalSize - produced);
			controller.enqueue(new Uint8Array(size).fill(produced % 256));
			produced += size;
		},
	});
}

// Simulate CPU work (e.g., parsing, indexing)
function simulateWork(ms: number): void {
	const end = performance.now() + ms;
	while (performance.now() < end) {
		// busy wait
	}
}

async function main() {
	console.log("Incremental Processing Benchmark");
	console.log("=================================\n");
	console.log("Scenario: Server receives data over slow network,");
	console.log("processes each chunk (e.g., indexing, parsing).\n");

	const { suite, keyConfig } = await setup();
	const client = new ChunkedOHTTPClient(suite, keyConfig);
	const server = new ChunkedOHTTPServer([keyConfig]);

	const totalSize = 100 * 1024; // 100KB
	const chunkSize = 10 * 1024; // 10KB chunks
	const networkDelay = 50; // 50ms per chunk (simulates slow network)
	const processTime = 10; // 10ms to process each chunk

	const numChunks = Math.ceil(totalSize / chunkSize);
	const theoreticalNetworkTime = numChunks * networkDelay;
	const theoreticalProcessTime = numChunks * processTime;

	console.log(`Config:`);
	console.log(`  Total size: ${totalSize / 1024}KB`);
	console.log(`  Chunk size: ${chunkSize / 1024}KB`);
	console.log(`  Chunks: ${numChunks}`);
	console.log(`  Network delay: ${networkDelay}ms/chunk`);
	console.log(`  Process time: ${processTime}ms/chunk`);
	console.log(`  Theoretical network time: ${theoreticalNetworkTime}ms`);
	console.log(`  Theoretical process time: ${theoreticalProcessTime}ms`);
	console.log();

	// Buffered approach: wait for all data, then process
	console.log("=== Buffered (wait for all, then process) ===");
	{
		const stream = createSlowStream(totalSize, chunkSize, networkDelay);
		const chunks: Uint8Array[] = [];

		const t0 = performance.now();
		let networkDone = 0;

		// Collect all data first
		for await (const chunk of stream) {
			chunks.push(chunk);
		}
		networkDone = performance.now() - t0;

		// Then process
		for (const chunk of chunks) {
			simulateWork(processTime);
		}
		const total = performance.now() - t0;

		console.log(`  Network complete: ${networkDone.toFixed(0)}ms`);
		console.log(`  Total (network + process): ${total.toFixed(0)}ms`);
		console.log(`  Expected: ~${theoreticalNetworkTime + theoreticalProcessTime}ms (sequential)\n`);
	}

	// Streaming approach: process while receiving
	console.log("=== Streaming (process while receiving) ===");
	{
		const stream = createSlowStream(totalSize, chunkSize, networkDelay);

		const request = new Request("https://example.com/api", {
			method: "POST",
			body: stream,
			// @ts-expect-error duplex required
			duplex: "half",
		});

		const t0 = performance.now();
		const firstChunkTimes: number[] = [];

		const { request: encReq } = await client.encapsulateRequest(request, "https://relay/");
		const { request: decReq } = await server.decapsulateRequest(encReq);

		// Process each chunk as it arrives
		if (decReq.body) {
			for await (const chunk of decReq.body) {
				firstChunkTimes.push(performance.now() - t0);
				simulateWork(processTime);
			}
		}
		const total = performance.now() - t0;

		console.log(`  First chunk processed: ${firstChunkTimes[0]?.toFixed(0) ?? "N/A"}ms`);
		console.log(`  Total: ${total.toFixed(0)}ms`);
		console.log(`  Expected: ~${theoreticalNetworkTime + processTime}ms (overlapped)\n`);
	}

	console.log("=== Analysis ===");
	console.log(
		`Buffered: Must wait ${theoreticalNetworkTime}ms for network, then ${theoreticalProcessTime}ms to process`,
	);
	console.log(`          Total: ~${theoreticalNetworkTime + theoreticalProcessTime}ms`);
	console.log(`Streaming: Network and processing overlap. Only last chunk adds full process time.`);
	console.log(`           Total: ~${theoreticalNetworkTime + processTime}ms`);
	console.log(`           Saves: ~${theoreticalProcessTime - processTime}ms`);
}

main();
