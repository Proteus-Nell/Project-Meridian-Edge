# Benchmark harness

Suites B1–B5 quantify the cost of pure-PQC crypto against classical baselines
(ML-KEM-768 vs X25519, ML-DSA-65 vs Ed25519).

All five suites are implemented, and `make bench-report` merges them into one
document (`bench/out/consolidated.md`). See [Status](#status) for the split
across browser and server, and for the deliberate methodology limitations.

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
/bench b4         # protocol level (handshake + both ratchet modes)
```

Human-readable tables print in the terminal. The machine-readable JSON is
offered as a **download** (`meridian-bench-<suite>.json`) and printed to the
browser console as a fallback - it is the input to the consolidation step
below, so keep it. The browser numbers are the novel finding: they show what
PQC costs in a `@noble` JS implementation, not in native C.

### Server (B1/B2 latency native, B5 footprint)

```
make bench                       # server B1/B2 + B5 footprint -> bench/out/, plus B5 bundle sizes
make bench-print                 # server tables to stdout
make bench-bundle                # B5 bundle sizes -> table + bench/out/bundle.json
python bench/server_bench.py --iters 2000 --sessions 5000   # custom counts
```

### The consolidated report (every suite in one document)

The three pipelines above write to three different places, so no single
artifact ever held all five suites. `make bench-report` merges them:

```
make bench                                            # writes results.json + bundle.json
# run /bench in the client, keep the downloaded JSON
cp ~/Downloads/meridian-bench-all.json bench/out/browser.json
make bench-report                                     # -> bench/out/consolidated.md
make bench-report BROWSER_JSON=~/Downloads/meridian-bench-all.json   # or point at it directly
```

`bench/consolidate.py` re-runs nothing. It reads `bench/out/results.json`,
`bench/out/bundle.json` and the browser JSON, and writes
`bench/out/consolidated.md` with **B1 and B2 as one table per suite, browser
beside native**, including a derived JS/native ratio per operation and a prose
statement of the gap - the browser-JS versus native-C comparison that was
previously left for a reader to compute across two documents. B3 and B4 are
browser-only and carried through - including B4's primitive breakdown, which
prices its handshake rows against the B1/B2 medians; B5 gets both halves
(bundle delta and per-session footprint) with their caveats.

If any input is missing or unreadable it **fails and says which command
produces it**, rather than emitting a report that quietly omits a suite. A
partial `/bench` run (say `/bench b1`) is rejected for the same reason.

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

- Warm-up runs discarded, then median / p95 / mean over the sample set.
- **A sample is not a call.** Each timed sample executes a *batch* of calls and
  divides, so a row runs `samples x batch` calls in total. B1/B2 default to 1000
  samples per row, which at batch 64 is 64,000 X25519 calls and at batch 32 is
  32,000 ML-KEM calls. Every suite heading states its sample and warm-up counts,
  and the timer footnote gives the batch and the resulting call count per row -
  the older "over 1000 iterations" wording named only the sample count and was
  read, reasonably, as the number of calls.
- **B4 runs fewer samples than B1/B2, by design.** One B4 sample is a whole
  handshake or ratchet step rather than a single primitive, so it caps at
  `B4_MAX_SAMPLES` = 200 samples and `B4_MAX_WARMUP` = 20 warm-up runs however
  the config is set. Those counts are carried on the result and printed above
  the table, so a reader comparing B4 with B1/B2 can see the sample sizes differ
  rather than assuming they match.
- Browser fast primitives time a batch of calls per sample to stay above the
  clamped `performance.now()` resolution; the server uses `perf_counter`
  (sub-microsecond) and needs no batching.
- Batching divides that clamp but never removes it. A browser page that is not
  cross-origin isolated reads the clock at 100 us, so every browser figure is a
  multiple of `100 us / batch` - 3.13 us for the ML-KEM rows (batch 32), 1.56 us
  for the classical rows (batch 64), and the full 100 us for B4, which times one
  operation per sample. Each browser suite prints its own floor beneath the
  table ("timer resolution: 100 us clamped; batch N = C calls per row, effective
  per-op resolution X us"), naming the ops in each batch group, so no row's
  precision or call count has to be inferred. It appears on both the terminal
  and Markdown surfaces, since the heading points at it for the per-row batch.
  The 100 us clamp is an assumption about the host, not a measurement:
  a context coarsening further (Firefox defaults to 1 ms) would make the printed
  floor optimistic.
- Browser figures are reported to **three significant figures**, not fixed
  decimal places. A fourth digit would be reporting the timer's grid rather than
  the primitive: at batch 32 the underlying samples land on 3.13 us boundaries,
  so "462.5 us" was four digits of precision drawn from one tick. It now reads
  "463 us". The server harness is unaffected - `perf_counter` is
  sub-microsecond, needs no batching, and keeps its own formatting.
- Numbers cover *these implementations in these environments*, not the
  algorithms in the abstract. The browser-JS versus native-C gap is itself a
  reported finding, and `bench/out/consolidated.md` is where it is actually
  shown: B1/B2 as one table per suite with both environments side by side, a
  JS/native ratio per operation, and a prose line stating the range.
- The consolidated report normalises units (the browser reports milliseconds,
  the server microseconds) and formats **both** columns to three significant
  figures, so neither environment reads as more precise than the other. It says
  in the report that only the browser column carries a quantisation floor. It
  also repeats each harness's sample and warm-up counts, since the merged table
  puts a 1000-sample native row beside a browser row that may have run fewer.
- B1's classical column is blank on the decaps row, in both harnesses. X25519
  has no split encaps/decaps, so a single `getSharedSecret` / `exchange()` is
  the baseline for both ML-KEM halves: it is measured once, reported on the
  encaps row, and left blank on decaps rather than printed twice, which would
  read as two measurements. The factor cell is blank for the same reason. Every
  other cell in B1/B2 is its own measurement.
- B3 labels every row `measured` or `analytic` in a trailing column, because the
  table mixes both. The four primitive rows are measured off real generated
  objects, and both handshake rows are the byte length of a real serialized KX
  envelope from `initiateKx` - not a layout sum, so they cannot drift from
  `client/src/crypto/envelope.ts` (a test pins them to the layout it documents).
  The registration-bundle and ratchet-step rows are analytic models of what
  those objects carry. The label describes the **PQC** figure: the classical
  column is analytic on every row, since there is no classical implementation of
  this protocol to measure.
- B3's classical column prices *this* protocol rebuilt on classical primitives,
  not a deployed X3DH stack. The gap is widest on the registration bundle, whose
  classical side carries 3,200 bytes of SHA-512 batch-leaf hashes purely because
  this protocol batch-signs its OPKs - 64% of its 4,992 bytes. Real X3DH has no
  leaf hashes, so measured against one the row would be nearer x40 than the x14
  shown. Both framings are in the generated note; neither is the "true" number
  on its own.
- B3's handshake rows carry the bench's fixed 37-byte message plus the 16-byte
  AEAD tag on both sides, so the columns are like-for-like. The two rows share
  one classical figure on purpose: X3DH's one-time prekey costs an extra DH
  against the ephemeral already on the wire, whereas the KEM path pays a second
  ciphertext and its routing hash - 1,152 bytes, which is the whole difference
  between the two PQC rows.
- B4 prints median, p95 **and mean** for every row, because its rate column is
  `1000 / mean` while the headline figures are the median: a table showing two
  centres has to name both. The column is headed "mean throughput" for that
  reason, and only the ratchet rows carry one - inverting a handshake latency
  into a rate reads as capacity, which this harness cannot measure. The
  accompanying footnote says what the rate is not: one single-threaded browser
  tab, crypto only, no network, no concurrency, no server. The gap between mean
  and median is the distribution's right skew, and it is worth reading: rows
  that include an ML-DSA signature have shown noticeably more of it than rows
  that do not, which is the kind of thing a median alone hides.
- B4 prints a **primitive breakdown** under its main table: the handshake rows
  priced against the B1/B2 medians, with each constituent operation, its call
  count, the predicted total and the measured median, so the residual is
  visible rather than left as arithmetic. It answers "where does the time go"
  and doubles as a soundness check - a composition that did not decompose would
  show up as an implausible residual. The counts are a hand trace of
  `client/src/crypto/kx.ts` (`initiateKx`: 2 ML-DSA verify for the SPK and OPK
  batch, 2 ML-KEM encaps, 1 ML-DSA sign; `respondKx` adds 1 verify and 2
  decaps), not an instrumented count, and the fixture bundle carries an OPK so
  both `ct2` paths run. The residual absorbs SHA-512 transcript and prekey
  hashing, HKDF, XChaCha20-Poly1305, framing and allocation.
- The breakdown appears **only when `/bench` runs every suite**, since it needs
  B1/B2 to have already produced their medians. `/bench b4` alone prints a line
  saying why it is absent. B4 does not run B1/B2 to fill the gap: that would add
  their cost to the session it is timing. Predicted totals are sums of per-op
  medians, and the median of a sum is not the sum of medians, so the report
  labels them estimates - B1/B2 also batch 32 calls per sample where B4 times
  one, so the two carry different quantisation floors.
- B4 reports the ratchet as two rows, because the KEM-step rule makes any single
  figure misleading. Alternating turns put every message at the start of a new
  turn, so each one carries a fresh KEM step - the worst case. A unidirectional
  burst (one party sending without a reply) amortises one step over
  `KEM_STEP_INTERVAL` = 10 sends and accepts no offer at all - the floor. Real
  traffic sits between the two, and the gap is what the interval buys. In the
  burst row one sample in ten carries the keygen, so its p95 sits well above its
  median by construction: that spread is the step, not noise.

## Status

Every row lands in `bench/out/consolidated.md` via `make bench-report`; the
"produced by" column is where each half is measured.

| Suite | What | Produced by |
|---|---|---|
| B1 | KEM latency (keygen/encaps/decaps), ML-KEM-768 vs X25519 | ✓ browser (`/bench b1`) + native (`make bench-server`), merged into one table |
| B2 | Signature latency (keygen/sign/verify), ML-DSA-65 vs Ed25519 | ✓ browser (`/bench b2`) + native (`make bench-server`), merged into one table |
| B3 | Size overhead (keys, ciphertexts, sigs, bundle/handshake/ratchet-step) | ✓ browser only (`/bench b3`); each row labelled measured or analytic |
| B4 | Protocol level (TTFM, handshake, ratchet msgs/sec in both KEM-step modes) | ✓ browser only (`/bench b4`); the primitive breakdown needs a full `/bench` run |
| B5 | Footprint: bundle-size delta + server heap/session | ✓ `make bench-bundle` + `make bench-server`, both halves in one section |
| — | All of the above in one document | ✓ `make bench-report` → `bench/out/consolidated.md` |

**Documented methodology limitations (not gaps):**

- **B4** measures the crypto and protocol cost only; it excludes network RTT,
  which is identical for classical and PQC. No throttled figure is reported: to
  obtain one, set a CPU throttle in browser devtools and re-run `/bench b4`.
  The harness doesn't extrapolate a throttled number from the unthrottled row.
- **B5 server footprint** reports a per-session Python-heap figure via
  `tracemalloc` (the SessionToken object plus its hashed token). It excludes the
  DB engine and native OpenSSL allocations, and it is not full RSS, because
  `psutil` and `resource` are neither portable nor dependencies. Treat it as a
  reproducible relative figure, not an absolute process-memory number.
- **B5 bundle** bundles each library alone (minified, gzipped) with Vite. The
  headline: the PQC libraries are actually *smaller* than the classical
  `@noble/curves` baseline. The PQC cost is latency (B1/B2) and wire size (B3),
  not JS footprint. These are standalone sizes, not the marginal cost of adding
  PQC to this client - shared `@noble/hashes` utilities are counted in both.
