/**
 * Time-to-First-Byte (TTFB) benchmark: Normal OHTTP vs Chunked OHTTP
 *
 * Measures how quickly the first byte of decrypted content is available.
 * This showcases streaming's key advantage: you can start processing
 * before the entire body is encrypted/decrypted.
 *
 * Run with: npx tsx bench/ttfb.bench.ts
 */

import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import {
	AeadId,
	ChunkedOHTTPClient,
	ChunkedOHTTPServer,
	KdfId,
	KeyConfig,
	OHTTPClient,
	OHTTPServer,
} from "../src/index.js";

function formatMs(ms: number): string {
	if (ms < 1) return `${(ms * 1000).toFixed(0)}µs`;
	return `${ms.toFixed(2)}ms`;
}

// Random payload generator
function randomBytes(size: number): Uint8Array {
	const buf = new Uint8Array(size);
	const chunkSize = 65_536;
	for (let offset = 0; offset < size; offset += chunkSize) {
		const len = Math.min(chunkSize, size - offset);
		crypto.getRandomValues(buf.subarray(offset, offset + len));
	}
	return buf;
}

interface TTFBResult {
	name: string;
	bodySize: string;
	ttfbMs: number;
	totalMs: number;
	ttfbFormatted: string;
	totalFormatted: string;
}

/**
 * Normal OHTTP: Must wait for entire body to be decrypted before any access
 */
async function benchNormalOHTTP(
	client: OHTTPClient,
	server: OHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<TTFBResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const startTime = performance.now();

	// Client encapsulates
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);

	// Server decapsulates - TTFB is when we can access the first byte
	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);

	// For normal OHTTP, we must read the entire body to get any byte
	// This is the fundamental limitation - no streaming access
	const body = await innerReq.arrayBuffer();
	const ttfbTime = performance.now();
	const _firstByte = new Uint8Array(body)[0]; // Access first byte

	// Complete the round-trip for fairness
	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	const finalRes = await context.decapsulateResponse(encRes);
	await finalRes.arrayBuffer();

	const totalTime = performance.now();

	return {
		name: "normal OHTTP",
		bodySize: label,
		ttfbMs: ttfbTime - startTime,
		totalMs: totalTime - startTime,
		ttfbFormatted: formatMs(ttfbTime - startTime),
		totalFormatted: formatMs(totalTime - startTime),
	};
}

/**
 * Chunked OHTTP with buffered consumption (like calling .arrayBuffer())
 */
async function benchChunkedBuffered(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<TTFBResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const startTime = performance.now();

	// Client encapsulates
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);

	// Server decapsulates
	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);

	// Buffered: wait for entire body like normal OHTTP
	const body = await innerReq.arrayBuffer();
	const ttfbTime = performance.now();
	const _firstByte = new Uint8Array(body)[0];

	// Complete round-trip
	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	const finalRes = await context.decapsulateResponse(encRes);
	await finalRes.arrayBuffer();

	const totalTime = performance.now();

	return {
		name: "chunked buffered",
		bodySize: label,
		ttfbMs: ttfbTime - startTime,
		totalMs: totalTime - startTime,
		ttfbFormatted: formatMs(ttfbTime - startTime),
		totalFormatted: formatMs(totalTime - startTime),
	};
}

/**
 * Chunked OHTTP with streaming consumption - read first chunk immediately
 */
async function benchChunkedStreaming(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<TTFBResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const startTime = performance.now();

	// Client encapsulates
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);

	// Server decapsulates
	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);

	// Streaming: read just the first chunk
	const reader = innerReq.body!.getReader();
	const { value: firstChunk } = await reader.read();
	const ttfbTime = performance.now();
	const _firstByte = firstChunk![0]; // Access first byte

	// Consume rest of body
	while (true) {
		const { done } = await reader.read();
		if (done) break;
	}

	// Complete round-trip
	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	const finalRes = await context.decapsulateResponse(encRes);

	// Stream response too
	const resReader = finalRes.body!.getReader();
	while (true) {
		const { done } = await resReader.read();
		if (done) break;
	}

	const totalTime = performance.now();

	return {
		name: "chunked streaming",
		bodySize: label,
		ttfbMs: ttfbTime - startTime,
		totalMs: totalTime - startTime,
		ttfbFormatted: formatMs(ttfbTime - startTime),
		totalFormatted: formatMs(totalTime - startTime),
	};
}

/**
 * Simulates a slow network source that delivers chunks with delays.
 * This is where streaming shines - you can process early chunks while
 * later chunks are still arriving.
 */
async function benchSlowSourceStreaming(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	totalSize: number,
	chunkSize: number,
	delayMs: number,
	label: string,
): Promise<TTFBResult> {
	// Create a slow streaming source that simulates network delivery
	const numChunks = Math.ceil(totalSize / chunkSize);
	let chunksDelivered = 0;

	const slowStream = new ReadableStream<Uint8Array>({
		async pull(controller) {
			if (chunksDelivered >= numChunks) {
				controller.close();
				return;
			}

			// Simulate network delay for each chunk
			if (chunksDelivered > 0) {
				await new Promise((resolve) => setTimeout(resolve, delayMs));
			}

			const thisChunkSize = Math.min(chunkSize, totalSize - chunksDelivered * chunkSize);
			const chunk = new Uint8Array(thisChunkSize);
			crypto.getRandomValues(chunk);
			controller.enqueue(chunk);
			chunksDelivered++;
		},
	});

	const req = new Request("https://example.com/api", {
		method: "POST",
		body: slowStream,
		// @ts-expect-error Node.js requires duplex for streaming bodies
		duplex: "half",
	});

	const startTime = performance.now();

	// Client encapsulates - starts immediately, encrypts as chunks arrive
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);

	// Server decapsulates - can start decrypting before all chunks arrive
	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);

	// Read first chunk - this is TTFB
	const reader = innerReq.body!.getReader();
	const { value: firstChunk } = await reader.read();
	const ttfbTime = performance.now();
	const _firstByte = firstChunk![0];

	// Consume rest
	while (true) {
		const { done } = await reader.read();
		if (done) break;
	}

	// Simple response for completeness
	const res = new Response("ok", { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	const finalRes = await context.decapsulateResponse(encRes);
	await finalRes.text();

	const totalTime = performance.now();

	// Calculate theoretical minimum TTFB (time for first chunk to arrive + processing)
	const theoreticalMinTTFB = 0; // First chunk has no delay

	return {
		name: `streaming (${delayMs}ms/chunk)`,
		bodySize: label,
		ttfbMs: ttfbTime - startTime,
		totalMs: totalTime - startTime,
		ttfbFormatted: formatMs(ttfbTime - startTime),
		totalFormatted: formatMs(totalTime - startTime),
	};
}

/**
 * For comparison: what if we had to buffer the entire slow source first?
 * This simulates what would happen without streaming.
 */
async function benchSlowSourceBuffered(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	totalSize: number,
	chunkSize: number,
	delayMs: number,
	label: string,
): Promise<TTFBResult> {
	const startTime = performance.now();

	// First, buffer the entire "slow" source (simulating non-streaming)
	const numChunks = Math.ceil(totalSize / chunkSize);
	const chunks: Uint8Array[] = [];

	for (let i = 0; i < numChunks; i++) {
		if (i > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}
		const thisChunkSize = Math.min(chunkSize, totalSize - i * chunkSize);
		const chunk = new Uint8Array(thisChunkSize);
		crypto.getRandomValues(chunk);
		chunks.push(chunk);
	}

	// Now create request with buffered body
	const fullBody = new Uint8Array(totalSize);
	let offset = 0;
	for (const chunk of chunks) {
		fullBody.set(chunk, offset);
		offset += chunk.length;
	}

	const req = new Request("https://example.com/api", {
		method: "POST",
		body: fullBody,
	});

	// Client encapsulates
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);

	// Server decapsulates
	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);

	// Read first byte
	const reader = innerReq.body!.getReader();
	const { value: firstChunk } = await reader.read();
	const ttfbTime = performance.now();
	const _firstByte = firstChunk![0];

	// Consume rest
	while (true) {
		const { done } = await reader.read();
		if (done) break;
	}

	// Response
	const res = new Response("ok", { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	const finalRes = await context.decapsulateResponse(encRes);
	await finalRes.text();

	const totalTime = performance.now();

	return {
		name: `buffered (${delayMs}ms/chunk)`,
		bodySize: label,
		ttfbMs: ttfbTime - startTime,
		totalMs: totalTime - startTime,
		ttfbFormatted: formatMs(ttfbTime - startTime),
		totalFormatted: formatMs(totalTime - startTime),
	};
}

async function main() {
	console.log("TTFB Benchmark: Normal OHTTP vs Chunked OHTTP");
	console.log("==============================================");
	console.log();
	console.log("TTFB = Time until first decrypted byte is accessible");
	console.log("Total = Time for complete round-trip");
	console.log();

	const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
	const keyConfig = await KeyConfig.generate(suite, 0x01, [
		{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
	]);

	const client = new OHTTPClient(suite, keyConfig);
	const server = new OHTTPServer([keyConfig]);
	const chunkedClient = new ChunkedOHTTPClient(suite, keyConfig);
	const chunkedServer = new ChunkedOHTTPServer([keyConfig]);

	const sizes = [
		{ size: 100 * 1024, label: "100KB" },
		{ size: 1024 * 1024, label: "1MB" },
		{ size: 10 * 1024 * 1024, label: "10MB" },
	];

	const results: TTFBResult[] = [];

	for (const { size, label } of sizes) {
		console.log(`Testing ${label}...`);
		const payload = randomBytes(size);

		// Warmup
		await benchNormalOHTTP(client, server, payload, label);
		await benchChunkedBuffered(chunkedClient, chunkedServer, payload, label);
		await benchChunkedStreaming(chunkedClient, chunkedServer, payload, label);

		// Average of 3 runs
		const runs = 3;
		const normalRuns: TTFBResult[] = [];
		const bufferedRuns: TTFBResult[] = [];
		const streamingRuns: TTFBResult[] = [];

		for (let i = 0; i < runs; i++) {
			normalRuns.push(await benchNormalOHTTP(client, server, payload, label));
			bufferedRuns.push(await benchChunkedBuffered(chunkedClient, chunkedServer, payload, label));
			streamingRuns.push(await benchChunkedStreaming(chunkedClient, chunkedServer, payload, label));
		}

		const avg = (arr: TTFBResult[], field: "ttfbMs" | "totalMs") =>
			arr.reduce((a, b) => a + b[field], 0) / arr.length;

		results.push({
			name: "normal OHTTP",
			bodySize: label,
			ttfbMs: avg(normalRuns, "ttfbMs"),
			totalMs: avg(normalRuns, "totalMs"),
			ttfbFormatted: formatMs(avg(normalRuns, "ttfbMs")),
			totalFormatted: formatMs(avg(normalRuns, "totalMs")),
		});

		results.push({
			name: "chunked buffered",
			bodySize: label,
			ttfbMs: avg(bufferedRuns, "ttfbMs"),
			totalMs: avg(bufferedRuns, "totalMs"),
			ttfbFormatted: formatMs(avg(bufferedRuns, "ttfbMs")),
			totalFormatted: formatMs(avg(bufferedRuns, "totalMs")),
		});

		results.push({
			name: "chunked streaming",
			bodySize: label,
			ttfbMs: avg(streamingRuns, "ttfbMs"),
			totalMs: avg(streamingRuns, "totalMs"),
			ttfbFormatted: formatMs(avg(streamingRuns, "ttfbMs")),
			totalFormatted: formatMs(avg(streamingRuns, "totalMs")),
		});
	}

	console.log();
	console.log("Results (average of 3 runs):");

	// Group by size
	for (const { label } of sizes) {
		console.log(`\n${label}:`);
		const sizeResults = results.filter((r) => r.bodySize === label);

		const streamingTTFB = sizeResults.find((r) => r.name === "chunked streaming")!.ttfbMs;
		const normalTTFB = sizeResults.find((r) => r.name === "normal OHTTP")!.ttfbMs;

		console.table(
			sizeResults.map((r) => ({
				Method: r.name,
				TTFB: r.ttfbFormatted,
				Total: r.totalFormatted,
				"TTFB % of Total": `${((r.ttfbMs / r.totalMs) * 100).toFixed(1)}%`,
			})),
		);

		if (streamingTTFB < normalTTFB) {
			console.log(
				`  → Streaming TTFB is ${(normalTTFB / streamingTTFB).toFixed(1)}x faster than normal`,
			);
		}
	}

	// Summary
	console.log("\n\nSummary - TTFB Improvement with Streaming:");
	console.log("─".repeat(50));
	for (const { label } of sizes) {
		const sizeResults = results.filter((r) => r.bodySize === label);
		const streaming = sizeResults.find((r) => r.name === "chunked streaming")!;
		const normal = sizeResults.find((r) => r.name === "normal OHTTP")!;

		const ttfbSpeedup = normal.ttfbMs / streaming.ttfbMs;
		const ttfbReduction = ((normal.ttfbMs - streaming.ttfbMs) / normal.ttfbMs) * 100;

		console.log(
			`${label}: Streaming TTFB ${formatMs(streaming.ttfbMs)} vs Normal ${formatMs(normal.ttfbMs)}`,
		);
		console.log(
			`       ${ttfbSpeedup.toFixed(1)}x faster TTFB (${ttfbReduction.toFixed(0)}% reduction)`,
		);
	}

	// Now test with slow source - this is where streaming shines!
	console.log("\n\n" + "=".repeat(60));
	console.log("SLOW SOURCE TEST - Simulating network latency");
	console.log("=".repeat(60));
	console.log();
	console.log("This demonstrates streaming's real benefit: processing");
	console.log("early data while later data is still in transit.");
	console.log();

	const slowTestConfig = {
		totalSize: 100 * 1024, // 100KB total
		chunkSize: 10 * 1024, // 10KB chunks
		delayMs: 50, // 50ms between chunks (simulates ~200KB/s network)
	};

	console.log(
		`Config: ${slowTestConfig.totalSize / 1024}KB total, ${slowTestConfig.chunkSize / 1024}KB chunks, ${slowTestConfig.delayMs}ms delay`,
	);
	console.log(`Expected chunks: ${Math.ceil(slowTestConfig.totalSize / slowTestConfig.chunkSize)}`);
	console.log(
		`Theoretical total network time: ${(Math.ceil(slowTestConfig.totalSize / slowTestConfig.chunkSize) - 1) * slowTestConfig.delayMs}ms`,
	);
	console.log();

	// Run slow source tests
	const slowStreamingResult = await benchSlowSourceStreaming(
		chunkedClient,
		chunkedServer,
		slowTestConfig.totalSize,
		slowTestConfig.chunkSize,
		slowTestConfig.delayMs,
		"100KB slow",
	);

	const slowBufferedResult = await benchSlowSourceBuffered(
		chunkedClient,
		chunkedServer,
		slowTestConfig.totalSize,
		slowTestConfig.chunkSize,
		slowTestConfig.delayMs,
		"100KB slow",
	);

	console.log("Slow Source Results:");
	console.table([
		{
			Method: slowStreamingResult.name,
			TTFB: slowStreamingResult.ttfbFormatted,
			Total: slowStreamingResult.totalFormatted,
			"TTFB % of Total": `${((slowStreamingResult.ttfbMs / slowStreamingResult.totalMs) * 100).toFixed(1)}%`,
		},
		{
			Method: slowBufferedResult.name,
			TTFB: slowBufferedResult.ttfbFormatted,
			Total: slowBufferedResult.totalFormatted,
			"TTFB % of Total": `${((slowBufferedResult.ttfbMs / slowBufferedResult.totalMs) * 100).toFixed(1)}%`,
		},
	]);

	const ttfbImprovement = slowBufferedResult.ttfbMs / slowStreamingResult.ttfbMs;
	console.log();
	console.log(`→ Streaming TTFB is ${ttfbImprovement.toFixed(1)}x faster than buffered!`);
	console.log(`  Streaming: First byte available in ${slowStreamingResult.ttfbFormatted}`);
	console.log(
		`  Buffered:  Must wait ${slowBufferedResult.ttfbFormatted} for all data to arrive first`,
	);
}

main().catch(console.error);
