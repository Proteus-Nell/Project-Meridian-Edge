# Benchmark harness

Suites B1–B5 quantify the cost of pure-PQC crypto against classical baselines
(ML-KEM-768 vs X25519, ML-DSA-65 vs Ed25519).

All five suites are implemented. See [Status](#status) for the split across
browser and server, and for the deliberate methodology limitations.

This directory is one of two homes for the **classical** asymmetric baselines
(X25519, Ed25519); the other is `client/src/bench/`. The `scripts/audit.py`
classical-crypto gate excludes both: these baselines exist only as the
comparison yardstick, never as application crypto.

## Running

### Browser (B1/B2 latency, B3 sizes, B4 protocol-level)

In the client terminal:

```
/bench            # all browser suites (B1, B2, B3, B4)
/bench b1         # KEM latency only
/bench b3         # size overhead only
/bench b4         # protocol level (handshake + ratchet throughput)
```

Human-readable tables print in the terminal; the full JSON and Markdown report
goes to the browser console. The browser numbers are the novel finding: they
show what PQC costs in a `@noble` JS implementation, not in native C.

### Server (B1/B2 latency native, B5 footprint)

```
make bench                       # server B1/B2 + B5 footprint -> bench/out/, plus B5 bundle sizes
make bench-print                 # server tables to stdout
make bench-bundle                # B5 frontend bundle-size delta only
python bench/server_bench.py --iters 2000 --sessions 5000   # custom counts
```

The server harness uses pyca `cryptography` (OpenSSL 3.5) for **both** the PQC
and classical sides. That makes it a same-library, same-backend comparison, so
the library variable drops out of the measurement. (The MVP originally named
liboqs-python for the PQC side; `cryptography` 49 exposes ML-KEM/ML-DSA
natively and is already a pinned runtime dependency, so no extra dependency is
needed.)

### Tests

```
make bench-test                  # or: cd bench && python -m pytest -q
```

The client harness is tested in `client/tests/bench.test.ts` (run with the
client suite via `npm test`).

## Methodology

- Warm-up iterations discarded, then median / p95 / mean over the sample set.
- Primitives: ≥ 1000 iterations (the default).
- Browser fast primitives time a batch of calls per sample to stay above the
  clamped `performance.now()` resolution; the server uses `perf_counter`
  (sub-microsecond) and needs no batching.
- Numbers cover *these implementations in these environments*, not the
  algorithms in the abstract. The browser-JS versus native-C gap is itself a
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

- **B4** measures the crypto and protocol cost only; it excludes network RTT,
  which is identical for classical and PQC. The "handshake under 4× CPU
  throttle" is a browser-devtools measurement: throttle the CPU in devtools and
  re-run, or multiply the handshake row by the throttle factor.
- **B5 server footprint** reports a per-session Python-heap figure via
  `tracemalloc` (the SessionToken object plus its hashed token). It excludes the
  DB engine and native OpenSSL allocations, and it is not full RSS, because
  `psutil` and `resource` are neither portable nor dependencies. Treat it as a
  reproducible relative figure, not an absolute process-memory number.
- **B5 bundle** bundles each library alone (minified, gzipped) with Vite. The
  headline: the PQC libraries are actually *smaller* than the classical
  `@noble/curves` baseline. The PQC cost is latency (B1/B2) and wire size (B3),
  not JS footprint.
