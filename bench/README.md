# Benchmark harness

Suites B1–B5 per MVP_DOC.md §8: quantify the cost of pure-PQC crypto against
classical baselines (ML-KEM-768 vs X25519, ML-DSA-65 vs Ed25519).

All five suites are implemented — see [Status](#status) for the split across
browser and server and the deliberate methodology limitations.

This directory is one of two homes for the **classical** asymmetric baselines
(X25519, Ed25519); the other is `client/src/bench/`. Both are excluded from the
`scripts/audit.py` classical-crypto gate — the baselines exist only as the
comparison yardstick, not as application crypto.

## Running

### Browser (B1/B2 latency, B3 sizes, B4 protocol-level)

In the client terminal:

```
/bench            # all browser suites (B1, B2, B3, B4)
/bench b1         # KEM latency only
/bench b3         # size overhead only
/bench b4         # protocol level (handshake + ratchet throughput)
```

Human-readable tables print in the terminal; the full JSON + Markdown report is
logged to the browser console. The browser numbers are the novel finding — they
show what PQC costs in a `@noble` JS implementation, not in native C.

### Server (B1/B2 latency native, B5 footprint)

```
make bench                       # server B1/B2 + B5 footprint -> bench/out/, plus B5 bundle sizes
make bench-print                 # server tables to stdout
make bench-bundle                # B5 frontend bundle-size delta only
python bench/server_bench.py --iters 2000 --sessions 5000   # custom counts
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
| B4 | Protocol level (TTFM, handshake, sustained ratchet msgs/sec) | ✓ browser (`/bench b4`) |
| B5 | Footprint (PQC bundle-size delta; server heap/session) | ✓ `make bench-bundle` + server |

**Documented methodology limitations (not gaps):**

- **B4** measures the crypto/protocol cost only — network RTT is excluded (it's
  identical for classical and PQC). The "handshake under 4× CPU throttle" is a
  browser-devtools measurement: throttle the CPU in devtools and re-run, or
  multiply the handshake row by the throttle factor.
- **B5 server footprint** is a per-session Python-heap figure via `tracemalloc`
  (SessionToken object + hashed token). It excludes the DB engine and
  native/OpenSSL allocations and is not full RSS — `psutil`/`resource` aren't
  portable and aren't dependencies. It's a reproducible relative figure, not an
  absolute process-memory number.
- **B5 bundle** bundles each library alone (minified, gzipped) with Vite. The
  headline: the PQC libraries are actually *smaller* than the classical
  `@noble/curves` baseline — the PQC cost is latency (B1/B2) and wire size (B3),
  not JS footprint.
