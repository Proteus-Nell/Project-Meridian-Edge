# Benchmark harness

Suites B1–B5 per MVP_DOC.md §8: quantify the cost of pure-PQC crypto against
classical baselines (ML-KEM-768 vs X25519, ML-DSA-65 vs Ed25519).

> **Scope note.** B1–B3 are implemented. B4 (protocol-level: time-to-first-
> message, msgs/sec, handshake under 4× CPU throttle) and B5 (footprint:
> bundle-size delta, server RSS/session) are the MVP's designated first
> scope-cut items and are not yet built — see [Status](#status).

This directory is one of two homes for the **classical** asymmetric baselines
(X25519, Ed25519); the other is `client/src/bench/`. Both are excluded from the
`scripts/audit.py` classical-crypto gate — the baselines exist only as the
comparison yardstick, not as application crypto.

## Running

### Browser (B1/B2 latency in the JS engine, B3 sizes)

In the client terminal:

```
/bench            # all suites (B1, B2, B3)
/bench b1         # KEM latency only
/bench b3         # size overhead only
```

Human-readable tables print in the terminal; the full JSON + Markdown report is
logged to the browser console. The browser numbers are the novel finding — they
show what PQC costs in a `@noble` JS implementation, not in native C.

### Server (B1/B2 latency, native OpenSSL)

```
make bench                       # writes bench/out/{report.md,results.json}
make bench-print                 # tables to stdout
python bench/server_bench.py --iters 2000   # custom iteration count
```

The server harness uses pyca `cryptography` (OpenSSL 3.5) for **both** the PQC
and classical sides, so it's a same-library, same-backend comparison — the
library variable is removed from the measurement. (The MVP originally named
liboqs-python for the PQC side; `cryptography` 49 exposes ML-KEM/ML-DSA
natively and is already a pinned runtime dependency, so no extra dependency is
needed.)

### Tests

```
make bench-test                  # or: cd bench && python -m pytest -q
```

The client harness is tested in `client/tests/bench.test.ts` (run with the
client suite via `npm test`).

## Methodology (MVP §8)

- Warm-up iterations discarded, then median / p95 / mean over the sample set.
- Primitives: ≥ 1000 iterations (the default).
- Browser fast primitives time a batch of calls per sample to stay above the
  clamped `performance.now()` resolution; the server uses `perf_counter`
  (sub-microsecond) and needs no batching.
- Numbers are for *these implementations in these environments*, not the
  algorithms in the abstract — the browser-JS vs native-C gap is itself a
  reported finding.

## Status

| Suite | What | Status |
|---|---|---|
| B1 | KEM latency (keygen/encaps/decaps), ML-KEM-768 vs X25519 | ✓ browser + server |
| B2 | Signature latency (keygen/sign/verify), ML-DSA-65 vs Ed25519 | ✓ browser + server |
| B3 | Size overhead (keys, ciphertexts, sigs, bundle/handshake/ratchet-step) | ✓ browser (static + measured) |
| B4 | Protocol level (TTFM, msgs/sec, throttled handshake) over WSS | deferred |
| B5 | Footprint (PQC bundle-size delta, server RSS/session) | deferred |

**B5 groundwork:** the production build already isolates the classical baseline
(`@noble/curves`, ~40 kB) and the whole bench module into lazy chunks, so the
main-bundle delta attributable to the PQC libs is directly readable from
`npm run build`'s chunk sizes — the measurement B5 would formalize.
