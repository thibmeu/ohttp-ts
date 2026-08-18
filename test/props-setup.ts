import fc from "fast-check";

/**
 * Default run count for property tests. Properties over pure wire-format code
 * are cheap enough to run at this count; the crypto-heavy ones opt down to
 * {@link CRYPTO_RUNS}.
 */
fc.configureGlobal({ numRuns: 200 });
