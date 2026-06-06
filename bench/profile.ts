/**
 * CPU profiler for the OHTTP hot paths (Node-only dev tool).
 *
 * Brackets each scenario's tight loop with V8's sampling CPU profiler
 * (node:inspector) and aggregates self-time by function, so startup and harness
 * noise are excluded and each hot path is attributed independently.
 *
 * Self-time spent inside WebCrypto / HKDF lands in native frames (shown as
 * "(native)") — that's the crypto cost we can't move. The JS frames in `src/…`
 * are the optimization surface: framing, copies, varint, factory churn.
 *
 * This uses node:inspector and is never shipped; the library itself stays
 * runtime-agnostic.
 *
 * Run: npm run bench:profile
 */

import { Session } from "node:inspector/promises";
import { AEAD_AES_128_GCM, CipherSuite, KDF_HKDF_SHA256, KEM_DHKEM_X25519_HKDF_SHA256 } from "hpke";
import { AeadId, KdfId, KeyConfig, OHTTPClient, OHTTPServer } from "../src/index.js";
import {
	createChunkerTransform,
	createResponseDecryptTransform,
	createResponseEncryptTransform,
} from "../src/streaming.js";

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const keyConfig = await KeyConfig.generate(suite, 0x01, [
	{ kdfId: KdfId.HKDF_SHA256, aeadId: AeadId.AES_128_GCM },
]);
const client = new OHTTPClient(suite, keyConfig);
const server = new OHTTPServer([keyConfig]);

function randomBytes(size: number): Uint8Array {
	const buf = new Uint8Array(size);
	for (let off = 0; off < size; off += 65_536) {
		crypto.getRandomValues(buf.subarray(off, Math.min(off + 65_536, size)));
	}
	return buf;
}

interface CallFrame {
	functionName: string;
	url: string;
	lineNumber: number;
}
interface ProfileNode {
	id: number;
	callFrame: CallFrame;
	hitCount?: number;
}
interface CpuProfile {
	nodes: ProfileNode[];
	samples: number[];
	timeDeltas: number[];
}

function label(f: CallFrame): string {
	const name = f.functionName || "(anonymous)";
	if (!f.url || f.url.startsWith("node:")) return `${name}  (native)`;
	// shorten url to repo-relative-ish
	const short = f.url.replace(/^.*\/ohttp-ts\//, "").replace(/^.*\/node_modules\//, "…/");
	return `${name}  ${short}:${f.lineNumber + 1}`;
}

async function profile(
	session: Session,
	iters: number,
	fn: () => Promise<unknown>,
): Promise<Array<[string, number]>> {
	for (let i = 0; i < Math.min(iters, 20); i++) await fn(); // warm up JIT

	await session.post("Profiler.start");
	for (let i = 0; i < iters; i++) await fn();
	const { profile } = (await session.post("Profiler.stop")) as { profile: CpuProfile };

	const byId = new Map<number, CallFrame>();
	for (const n of profile.nodes) byId.set(n.id, n.callFrame);

	// self time per node from timeDeltas attributed to the sampled node
	const selfById = new Map<number, number>();
	for (let i = 0; i < profile.samples.length; i++) {
		const id = profile.samples[i]!;
		const dt = profile.timeDeltas[i] ?? 0;
		selfById.set(id, (selfById.get(id) ?? 0) + dt);
	}

	// aggregate by function label
	const byFn = new Map<string, number>();
	for (const [id, us] of selfById) {
		const frame = byId.get(id);
		if (!frame) continue;
		const key = label(frame);
		byFn.set(key, (byFn.get(key) ?? 0) + us);
	}

	return [...byFn.entries()].sort((a, b) => b[1] - a[1]);
}

// streaming helpers
const aead = AEAD_AES_128_GCM();
const skey = crypto.getRandomValues(new Uint8Array(16));
const snonce = crypto.getRandomValues(new Uint8Array(12));

function streamFrom(bytes: Uint8Array, readSize: number): ReadableStream<Uint8Array> {
	let off = 0;
	return new ReadableStream<Uint8Array>({
		pull(c) {
			if (off >= bytes.length) return c.close();
			const end = Math.min(off + readSize, bytes.length);
			c.enqueue(bytes.subarray(off, end));
			off = end;
		},
	});
}
async function streamEncrypt(plaintext: Uint8Array, chunkSize: number): Promise<Uint8Array> {
	const out = streamFrom(plaintext, plaintext.length)
		.pipeThrough(createChunkerTransform(chunkSize))
		.pipeThrough(createResponseEncryptTransform(aead, skey, snonce));
	const parts: Uint8Array[] = [];
	const reader = out.getReader();
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		parts.push(value);
	}
	const buf = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
	let o = 0;
	for (const p of parts) {
		buf.set(p, o);
		o += p.length;
	}
	return buf;
}
async function streamDecrypt(framed: Uint8Array, readSize: number): Promise<void> {
	const reader = streamFrom(framed, readSize)
		.pipeThrough(createResponseDecryptTransform(aead, skey, snonce))
		.getReader();
	for (;;) {
		const { done } = await reader.read();
		if (done) break;
	}
}

async function main(): Promise<void> {
	const _1KB = randomBytes(1_024);
	const _1MB = randomBytes(1_048_576);
	const _512KB = randomBytes(512 * 1024);

	const enc1MB = await client.encapsulate(_1MB);
	const framed16 = await streamEncrypt(_512KB, 16_384);
	const framed256 = await streamEncrypt(_512KB, 256);

	const roundTrip = async (p: Uint8Array): Promise<void> => {
		const { encapsulatedRequest, context } = await client.encapsulate(p);
		const { context: sctx } = await server.decapsulate(encapsulatedRequest);
		const encRes = await sctx.encryptResponse(p);
		await context.decryptResponse(encRes);
	};

	const scenarios: Array<[string, number, () => Promise<unknown>]> = [
		["round-trip 1KB (setup-dominated)", 4000, () => roundTrip(_1KB)],
		["encapsulateRequest 1MB", 1500, () => client.encapsulate(_1MB)],
		["decapsulateRequest 1MB", 1500, () => server.decapsulate(enc1MB.encapsulatedRequest)],
		["stream encrypt 512KB / 16KB chunks", 400, () => streamEncrypt(_512KB, 16_384)],
		["stream decrypt 512KB / 16KB / 1500B reads", 400, () => streamDecrypt(framed16, 1_500)],
		["stream encrypt 512KB / 256B chunks (slow)", 60, () => streamEncrypt(_512KB, 256)],
		["stream decrypt 512KB / 256B / 64KB reads (slow)", 60, () => streamDecrypt(framed256, 65_536)],
	];

	const session = new Session();
	session.connect();
	await session.post("Profiler.enable");
	await session.post("Profiler.setSamplingInterval", { interval: 100 }); // 100µs

	const TOP = 12;
	for (const [name, iters, fn] of scenarios) {
		const ranked = await profile(session, iters, fn);
		const total = ranked.reduce((s, [, us]) => s + us, 0) || 1;
		console.log(`\n=== ${name}  (${iters} iters, ${(total / 1000).toFixed(0)}ms sampled) ===`);
		console.log(`${"self%".padStart(6)}  ${"self ms".padStart(8)}  function`);
		for (const [fn2, us] of ranked.slice(0, TOP)) {
			const pct = ((us / total) * 100).toFixed(1);
			console.log(`${pct.padStart(6)}  ${(us / 1000).toFixed(1).padStart(8)}  ${fn2}`);
		}
	}
	session.disconnect();
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
