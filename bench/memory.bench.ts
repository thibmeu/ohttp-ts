/**
 * Memory usage comparison: normal OHTTP vs chunked OHTTP
 *
 * Measures heap memory during encryption/decryption operations.
 * Run with: npx tsx --expose-gc bench/memory.bench.ts
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

// Force GC if available (run with --expose-gc)
function forceGC() {
	if (global.gc) {
		global.gc();
	}
}

function getHeapUsed(): number {
	return process.memoryUsage().heapUsed;
}

function getBaselineHeap(): number {
	forceGC();
	forceGC(); // Double GC for stability
	return process.memoryUsage().heapUsed;
}

function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
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

interface BenchResult {
	name: string;
	bodySize: string;
	heapDelta: number;
	heapDeltaFormatted: string;
	timeMs: number;
}

async function benchNormalOHTTP(
	client: OHTTPClient,
	server: OHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<BenchResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const baseline = getBaselineHeap();
	const startTime = performance.now();
	let peakHeap = baseline;

	// Full round-trip
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const { context: sctx } = await server.decapsulateRequest(relayReq);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	await context.decapsulateResponse(encRes);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const endTime = performance.now();

	return {
		name: "normal OHTTP",
		bodySize: label,
		heapDelta: peakHeap - baseline,
		heapDeltaFormatted: formatBytes(peakHeap - baseline),
		timeMs: endTime - startTime,
	};
}

async function benchChunkedOHTTP(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<BenchResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const baseline = getBaselineHeap();
	const startTime = performance.now();
	let peakHeap = baseline;

	// Full round-trip (buffered consumption)
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	// Buffer entire request body (like example does with .json()/.text())
	await innerReq.arrayBuffer();
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const finalRes = await context.decapsulateResponse(encRes);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	// Buffer entire response body
	await finalRes.arrayBuffer();
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const endTime = performance.now();

	return {
		name: "chunked buffered",
		bodySize: label,
		heapDelta: peakHeap - baseline,
		heapDeltaFormatted: formatBytes(peakHeap - baseline),
		timeMs: endTime - startTime,
	};
}

async function benchChunkedOHTTPStreaming(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<BenchResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const baseline = getBaselineHeap();
	const startTime = performance.now();
	let peakHeap = baseline;

	// Full round-trip with streaming consumption
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	// Stream-consume request body instead of buffering
	const reqReader = innerReq.body?.getReader();
	if (reqReader) {
		while (true) {
			const { done } = await reqReader.read();
			peakHeap = Math.max(peakHeap, getHeapUsed());
			if (done) break;
		}
	}

	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const finalRes = await context.decapsulateResponse(encRes);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	// Stream-consume response body instead of buffering
	const resReader = finalRes.body?.getReader();
	if (resReader) {
		while (true) {
			const { done } = await resReader.read();
			peakHeap = Math.max(peakHeap, getHeapUsed());
			if (done) break;
		}
	}

	const endTime = performance.now();

	return {
		name: "chunked streaming",
		bodySize: label,
		heapDelta: peakHeap - baseline,
		heapDeltaFormatted: formatBytes(peakHeap - baseline),
		timeMs: endTime - startTime,
	};
}

async function benchChunkedOHTTPStreamingWithGC(
	client: ChunkedOHTTPClient,
	server: ChunkedOHTTPServer,
	payload: Uint8Array,
	label: string,
): Promise<BenchResult> {
	const req = new Request("https://example.com/api", {
		method: "POST",
		body: payload,
	});

	const baseline = getBaselineHeap();
	const startTime = performance.now();
	let peakHeap = baseline;

	// Full round-trip with streaming consumption + periodic GC
	const { request: relayReq, context } = await client.encapsulateRequest(
		req,
		"https://relay.example.com",
	);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const { request: innerReq, context: sctx } = await server.decapsulateRequest(relayReq);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	// Stream-consume request body, allowing GC between chunks
	const reqReader = innerReq.body?.getReader();
	if (reqReader) {
		let chunkCount = 0;
		while (true) {
			const { done } = await reqReader.read();
			chunkCount++;
			if (chunkCount % 100 === 0) {
				forceGC(); // Allow cleanup of processed chunks
			}
			peakHeap = Math.max(peakHeap, getHeapUsed());
			if (done) break;
		}
	}

	const res = new Response(payload, { status: 200 });
	const encRes = await sctx.encapsulateResponse(res);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	const finalRes = await context.decapsulateResponse(encRes);
	peakHeap = Math.max(peakHeap, getHeapUsed());

	// Stream-consume response body with periodic GC
	const resReader = finalRes.body?.getReader();
	if (resReader) {
		let chunkCount = 0;
		while (true) {
			const { done } = await resReader.read();
			chunkCount++;
			if (chunkCount % 100 === 0) {
				forceGC();
			}
			peakHeap = Math.max(peakHeap, getHeapUsed());
			if (done) break;
		}
	}

	const endTime = performance.now();

	return {
		name: "streaming+GC",
		bodySize: label,
		heapDelta: peakHeap - baseline,
		heapDeltaFormatted: formatBytes(peakHeap - baseline),
		timeMs: endTime - startTime,
	};
}

async function main() {
	console.log("Memory Benchmark: Normal OHTTP vs Chunked OHTTP");
	console.log("================================================");
	console.log();
	console.log("Peak heap measured during operation (lower is better)");
	console.log();

	if (!global.gc) {
		console.log("⚠️  Run with --expose-gc for accurate memory measurements");
		console.log("   Example: node --expose-gc --import tsx bench/memory.bench.ts");
		console.log();
	}

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

	const results: BenchResult[] = [];

	for (const { size, label } of sizes) {
		console.log(`Testing ${label}...`);
		const payload = randomBytes(size);

		// Warmup
		await benchNormalOHTTP(client, server, payload, label);
		await benchChunkedOHTTP(chunkedClient, chunkedServer, payload, label);
		await benchChunkedOHTTPStreaming(chunkedClient, chunkedServer, payload, label);
		await benchChunkedOHTTPStreamingWithGC(chunkedClient, chunkedServer, payload, label);

		// Actual measurements (average of 3 runs)
		const normalRuns: BenchResult[] = [];
		const chunkedRuns: BenchResult[] = [];
		const streamingRuns: BenchResult[] = [];
		const streamingGCRuns: BenchResult[] = [];

		for (let i = 0; i < 3; i++) {
			normalRuns.push(await benchNormalOHTTP(client, server, payload, label));
			chunkedRuns.push(await benchChunkedOHTTP(chunkedClient, chunkedServer, payload, label));
			streamingRuns.push(
				await benchChunkedOHTTPStreaming(chunkedClient, chunkedServer, payload, label),
			);
			streamingGCRuns.push(
				await benchChunkedOHTTPStreamingWithGC(chunkedClient, chunkedServer, payload, label),
			);
		}

		const avgNormal = {
			name: "normal OHTTP",
			bodySize: label,
			heapDelta: Math.round(normalRuns.reduce((a, b) => a + b.heapDelta, 0) / normalRuns.length),
			heapDeltaFormatted: "",
			timeMs: normalRuns.reduce((a, b) => a + b.timeMs, 0) / normalRuns.length,
		};
		avgNormal.heapDeltaFormatted = formatBytes(avgNormal.heapDelta);

		const avgChunked = {
			name: "chunked buffered",
			bodySize: label,
			heapDelta: Math.round(chunkedRuns.reduce((a, b) => a + b.heapDelta, 0) / chunkedRuns.length),
			heapDeltaFormatted: "",
			timeMs: chunkedRuns.reduce((a, b) => a + b.timeMs, 0) / chunkedRuns.length,
		};
		avgChunked.heapDeltaFormatted = formatBytes(avgChunked.heapDelta);

		const avgStreaming = {
			name: "chunked streaming",
			bodySize: label,
			heapDelta: Math.round(
				streamingRuns.reduce((a, b) => a + b.heapDelta, 0) / streamingRuns.length,
			),
			heapDeltaFormatted: "",
			timeMs: streamingRuns.reduce((a, b) => a + b.timeMs, 0) / streamingRuns.length,
		};
		avgStreaming.heapDeltaFormatted = formatBytes(avgStreaming.heapDelta);

		const avgStreamingGC = {
			name: "streaming+GC",
			bodySize: label,
			heapDelta: Math.round(
				streamingGCRuns.reduce((a, b) => a + b.heapDelta, 0) / streamingGCRuns.length,
			),
			heapDeltaFormatted: "",
			timeMs: streamingGCRuns.reduce((a, b) => a + b.timeMs, 0) / streamingGCRuns.length,
		};
		avgStreamingGC.heapDeltaFormatted = formatBytes(avgStreamingGC.heapDelta);

		results.push(avgNormal, avgChunked, avgStreaming, avgStreamingGC);
	}

	console.log();
	console.log("Results (average of 3 runs):");
	console.log();

	// Group by size
	for (const { label } of sizes) {
		console.log(`\n${label}:`);
		const sizeResults = results.filter((r) => r.bodySize === label);
		console.table(
			sizeResults.map((r) => ({
				Method: r.name,
				"Heap Delta": r.heapDeltaFormatted,
				"Time (ms)": r.timeMs.toFixed(2),
			})),
		);
	}

	// Summary table
	console.log("\nSummary (heap delta in bytes):");
	console.table(
		results.map((r) => ({
			Method: r.name,
			Size: r.bodySize,
			"Heap Delta": r.heapDeltaFormatted,
			"Time (ms)": r.timeMs.toFixed(2),
		})),
	);
}

main().catch(console.error);
