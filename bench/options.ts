/**
 * Shared vitest-bench tuning.
 *
 * Defaults (time 500ms, ~10 samples) leave these crypto benches at ±10–30% rme
 * because much of each op is spent idle awaiting async WebCrypto, so a handful
 * of samples swing wildly. Raise the time budget and warmup, and set an
 * iteration floor so even the slow small-chunk cases collect enough samples to
 * compare run-to-run.
 */
export const BENCH_OPTS = {
	time: 2000, // ms: time-bounds the fast cases into many samples
	iterations: 25, // floor: slow cases (256B chunks) still get >=25 samples
	warmupTime: 1000,
	warmupIterations: 10,
};
