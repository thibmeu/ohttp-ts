import { BHttpDecoder, BHttpEncoder } from "bhttp-ts";

/**
 * Shared Binary HTTP encoder/decoder (stateless singletons).
 *
 * Kept out of `constants.ts` deliberately: a module-scope `new` is not
 * provably side-effect-free, so a bundler pins every module that constructs
 * one. Importing a media type should not drag in all of bhttp-ts — see
 * `tools/check-treeshake.mjs`.
 */
export const bhttp = {
	encoder: new BHttpEncoder(),
	decoder: new BHttpDecoder(),
};
