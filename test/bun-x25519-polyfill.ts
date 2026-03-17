// Polyfill for X25519 WebCrypto support in Bun
//
// Bun does not support X25519 in its WebCrypto implementation. This preload
// patches crypto.subtle to add X25519 support using @noble/curves, which is
// already a transitive dependency via @panva/hpke-noble.
//
// Usage: bun --preload ./bun-x25519-polyfill.ts run <script>

import { x25519 } from "@noble/curves/ed25519.js";

// Only patch if X25519 is not already supported
let supported = false;
try {
	await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
	supported = true;
} catch {}

if (!supported) {
	const X25519_RAW = Symbol("x25519-raw");

	function makeKey(
		type: "public" | "private",
		extractable: boolean,
		usages: string[],
		raw: Uint8Array,
	): CryptoKey {
		return {
			type,
			algorithm: { name: "X25519" },
			extractable,
			usages,
			[X25519_RAW]: raw,
		} as unknown as CryptoKey;
	}

	function isX25519Key(key: unknown): key is CryptoKey & { [X25519_RAW]: Uint8Array } {
		return typeof key === "object" && key !== null && X25519_RAW in key;
	}

	const original = globalThis.crypto.subtle;

	const patched = new Proxy(original, {
		get(target, prop: string) {
			if (prop === "generateKey") {
				return async (
					algorithm: AlgorithmIdentifier,
					extractable: boolean,
					keyUsages: string[],
				) => {
					if ((algorithm as Algorithm).name === "X25519") {
						const { secretKey, publicKey } = x25519.keygen();
						return {
							privateKey: makeKey("private", extractable, keyUsages, secretKey),
							publicKey: makeKey("public", extractable, [], publicKey),
						};
					}
					// biome-ignore lint/complexity/noBannedTypes: delegates to native SubtleCrypto
					return (target.generateKey as Function)(algorithm, extractable, keyUsages);
				};
			}

			if (prop === "importKey") {
				return async (
					format: string,
					keyData: ArrayBuffer | Uint8Array,
					algorithm: AlgorithmIdentifier,
					extractable: boolean,
					keyUsages: string[],
				) => {
					if ((algorithm as Algorithm).name === "X25519" && format === "raw") {
						const raw = new Uint8Array(keyData as ArrayBuffer);
						const type = keyUsages.includes("deriveBits") ? "private" : "public";
						return makeKey(type, extractable, keyUsages, raw);
					}
					// biome-ignore lint/complexity/noBannedTypes: delegates to native SubtleCrypto
					return (target.importKey as Function)(format, keyData, algorithm, extractable, keyUsages);
				};
			}

			if (prop === "exportKey") {
				return async (format: string, key: CryptoKey) => {
					if (isX25519Key(key)) {
						if (format === "raw") return key[X25519_RAW].slice().buffer;
						throw new DOMException(`Unsupported export format: ${format}`, "NotSupportedError");
					}
					// biome-ignore lint/complexity/noBannedTypes: delegates to native SubtleCrypto
					return (target.exportKey as Function)(format, key);
				};
			}

			if (prop === "deriveBits") {
				return async (algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number) => {
					if (
						algorithm.name === "X25519" &&
						isX25519Key(baseKey) &&
						isX25519Key(algorithm.public)
					) {
						const shared = x25519.getSharedSecret(
							baseKey[X25519_RAW],
							algorithm.public[X25519_RAW],
						);
						return shared.slice(0, length >> 3).buffer;
					}
					// biome-ignore lint/complexity/noBannedTypes: delegates to native SubtleCrypto
					return (target.deriveBits as Function)(algorithm, baseKey, length);
				};
			}

			const value = Reflect.get(target, prop);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});

	try {
		Object.defineProperty(globalThis.crypto, "subtle", {
			value: patched,
			writable: true,
			configurable: true,
		});
	} catch {
		// If subtle is non-configurable, wrap the entire crypto object
		Object.defineProperty(globalThis, "crypto", {
			value: new Proxy(globalThis.crypto, {
				get(target, prop) {
					if (prop === "subtle") return patched;
					const value = Reflect.get(target, prop);
					return typeof value === "function" ? value.bind(target) : value;
				},
			}),
			writable: true,
			configurable: true,
		});
	}
}
