# Benchmarks

ohttp-ts is crypto- and runtime-bound: most of an operation runs inside
WebCrypto, and the rest is the fixed cost of dispatching many `crypto.subtle`
calls. The benches are built around that, in three groups.

**Compass** (deterministic): find the lever. `overlap` counts the `crypto.subtle`
calls per op; `alloc` counts the bytes. Both are machine-independent, so they
hold up under load.

**Gate** (vitest): confirm a change moved the numbers. `ohttp.bench`,
`concurrency.bench`, `streaming.bench`.

**Trace** (export): see where the time goes. `trace` writes a `.cpuprofile`, a
`.heapprofile`, and a `crypto.subtle` timeline for external tools.

They all share one cipher suite (X25519 / HKDF-SHA256 / AES-128-GCM) and one
client/server pair, from `fixtures.ts`.

## The benches

| command | file | measures |
|---|---|---|
| `npm run bench` | `*.bench.ts` | vitest: every timing bench below |
| `npm run bench:concurrency` | `concurrency.bench.ts` | throughput vs in-flight concurrency |
| `npm run bench:overlap` | `overlap.ts` | `crypto.subtle` calls per op, by kind, plus overlap |
| `npm run bench:alloc` | `alloc.ts` | arrayBuffers + heap per op |
| `npm run bench:profile` | `profile.ts` | CPU self-time per function (quick text summary) |
| `npm run bench:trace` | `trace.ts` | `.cpuprofile` / `.heapprofile` / trace JSON for external tools |
| `npm run bench:browser` | `*.bench.ts` | the vitest benches under Chromium |

`ohttp.bench.ts` (single-shot ops at 1KB and 1MB) and `streaming.bench.ts` (chunk
transforms) complete the vitest set.

## Reading the numbers

Wall-clock here is noisy. Much of each op is idle, waiting on async WebCrypto, so
a few samples swing widely and a busy machine makes it worse. Treat the vitest hz
as an order-of-magnitude and throughput-shape gate, not a microsecond-precise
figure.

- Gate on a quiet machine: pin cores (`taskset -c`), set the performance
  governor, close other work. Raise `BENCH_OPTS` (time and iterations, in
  `options.ts`) for a steadier read.
- For anything you need to trust, lean on the deterministic benches. The call
  counts from `overlap` and the byte deltas from `alloc` reproduce run to run;
  the wall-clock benches tell you an effect is real, not how big it is.
- `concurrency.bench` is the most useful timing bench for a decision: server
  throughput is where fewer `crypto.subtle` calls show up, and it's less
  sample-sensitive than single-op latency.

## The loop

1. `bench:overlap` + `bench:alloc` to find a lever (a repeated `importKey`, a
   copy, a high call count).
2. Make the change.
3. `bench:concurrency` (or `bench`) on a quiet box to confirm it moved.
4. `bench:trace` when you need to see where the time or allocations go.

## Trace artifacts

`bench:trace` writes to `bench/.trace/` (gitignored). Pick the op with `OP=` and
the size with `SIZE=`:

```
OP=decapsulateRequest SIZE=1048576 npm run bench:trace
```

- `<op>.cpuprofile` opens in speedscope.app or Chrome DevTools (Performance >
  Load profile): flame graph, stacks, time-order.
- `<op>.heapprofile` opens in Chrome DevTools (Memory > Load profile): where
  bytes are allocated.
- `<op>.trace.json` opens in ui.perfetto.dev or chrome://tracing: the
  `crypto.subtle` dispatch timeline, with durations and overlap.
