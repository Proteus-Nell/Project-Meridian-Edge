// Benchmark harness: the pure pieces (stats, size math,
// formatting, suite parsing) are asserted exactly; the timed suites run with a
// tiny sample count just to prove they execute and shape their results.

import { describe, expect, it } from "vitest";

import { CLOCK_CLAMP_MS, summarize } from "../src/bench/harness";
import {
  B4_MAX_SAMPLES,
  B4_MAX_WARMUP,
  BENCH_MESSAGE_BYTES,
  benchB3,
  benchB4,
  DEFAULT_CONFIG,
  primitiveMedians,
} from "../src/bench/suites";
import type { PrimitiveMedians } from "../src/bench/suites";
import {
  formatBytes,
  formatFactor,
  formatMs,
  renderMarkdown,
  renderTerminal,
} from "../src/bench/report";
import { parseSuite, runBench } from "../src/bench/index";
import { KEM_STEP_INTERVAL } from "../src/crypto/ratchet";
import { ERRORS } from "../src/terminal/messages";
import { COMMAND_USAGE } from "../src/terminal/parser";

describe("summarize (methodology)", () => {
  it("computes nearest-rank median/p95, mean, and min", () => {
    const stats = summarize("t", [10, 1, 3, 5, 2, 9, 4, 8, 6, 7]);
    expect(stats.iters).toBe(10);
    expect(stats.medianMs).toBe(5); // 5th of 10 sorted
    expect(stats.p95Ms).toBe(10); // 10th of 10 sorted
    expect(stats.meanMs).toBeCloseTo(5.5, 10);
    expect(stats.minMs).toBe(1);
    expect(stats.opsPerSec).toBeCloseTo(1000 / 5.5, 6);
  });

  it("handles an empty sample set without throwing", () => {
    const stats = summarize("empty", []);
    expect(stats.iters).toBe(0);
    expect(stats.medianMs).toBe(0);
    expect(stats.opsPerSec).toBe(0);
  });

  // Batching divides the clock's clamp; it never abolishes it. Carrying the
  // residual floor on every measurement is what lets the report state it.
  it("carries the per-op timer resolution the batch leaves behind", () => {
    expect(CLOCK_CLAMP_MS).toBe(0.1); // 100 us, the non-isolated browser clamp
    expect(summarize("unbatched", [1, 2, 3]).tickMs).toBe(0.1);
    expect(summarize("batched", [1, 2, 3], 32).tickMs).toBeCloseTo(0.1 / 32, 12);
    expect(summarize("batched", [1, 2, 3], 64).tickMs).toBeCloseTo(0.1 / 64, 12);
  });
});

describe("B3 size overhead", () => {
  const result = benchB3();
  const byObject = new Map(result.rows.map((r) => [r.object, r]));

  // The KX envelope layout, transcribed from the header comment of
  // client/src/crypto/envelope.ts. The measured rows must land exactly here.
  const AEAD_TAG = 16;
  const KX_FIXED_NO_OPK = 3 + 64 + 1952 + 1088 + 3309 + 24 + 4;
  const KX_FIXED_WITH_OPK = KX_FIXED_NO_OPK + 64 + 1088;

  it("measures the FIPS primitive sizes and matches the reference factors", () => {
    expect(byObject.get("KEM/DH public key")).toMatchObject({ classicalBytes: 32, pqcBytes: 1184 });
    expect(byObject.get("KEM ciphertext / DH share")).toMatchObject({
      classicalBytes: 32,
      pqcBytes: 1088,
    });
    expect(byObject.get("Signature")).toMatchObject({ classicalBytes: 64, pqcBytes: 3309 });
    expect(byObject.get("Signature public key")).toMatchObject({
      classicalBytes: 32,
      pqcBytes: 1952,
    });
    // The reference table: ×37 pubkey, ×34 ct, ×52 sig, ×61 sig-pubkey.
    expect(formatFactor(1184, 32)).toBe("x37");
    expect(formatFactor(1088, 32)).toBe("x34");
    expect(formatFactor(3309, 64)).toBe("x52");
    expect(formatFactor(1952, 32)).toBe("x61");
  });

  it("computes composite protocol sizes analytically", () => {
    // 50-OPK bundle: 1952 + 1184 + 3309 + 50*1184 + 3309 + 50*64
    expect(byObject.get("Registration bundle (50 OPKs)")?.pqcBytes).toBe(72154);
    // KEM step header: fresh pk + ciphertext
    expect(byObject.get("Ratchet KEM step header")?.pqcBytes).toBe(1184 + 1088);
  });

  // The handshake rows used to be a byte-layout sum that had drifted from the
  // wire format by ~1.2 kB (it omitted the version/type/flags, the routing
  // hashes, the u32be length, and the whole OPK path). They are now measured
  // from a real initiateKx() envelope; this pins the measurement to the layout
  // envelope.ts documents so the two cannot silently diverge again.
  it("measures the handshake rows against envelope.ts's byte layout", () => {
    expect(byObject.get("Handshake first message (no OPK)")?.pqcBytes).toBe(
      KX_FIXED_NO_OPK + BENCH_MESSAGE_BYTES + AEAD_TAG,
    );
    expect(byObject.get("Handshake first message (with OPK)")?.pqcBytes).toBe(
      KX_FIXED_WITH_OPK + BENCH_MESSAGE_BYTES + AEAD_TAG,
    );
    // Absolute anchors: a constant moving on either side has to fail here.
    expect(KX_FIXED_NO_OPK).toBe(6444);
    expect(KX_FIXED_WITH_OPK).toBe(7596);
    // The OPK path costs exactly its routing hash plus a second ciphertext.
    const withOpk = byObject.get("Handshake first message (with OPK)")?.pqcBytes ?? 0;
    const noOpk = byObject.get("Handshake first message (no OPK)")?.pqcBytes ?? 0;
    expect(withOpk - noOpk).toBe(64 + 1088);
    // Both rows share one classical figure: X3DH's one-time prekey is another
    // DH against the ephemeral already on the wire, not another ciphertext.
    expect(byObject.get("Handshake first message (with OPK)")?.classicalBytes).toBe(
      byObject.get("Handshake first message (no OPK)")?.classicalBytes,
    );
  });

  it("labels every row as measured or analytic, and explains the classical column", () => {
    const basisOf = (object: string): string | undefined => byObject.get(object)?.basis;
    expect(basisOf("KEM/DH public key")).toBe("measured");
    expect(basisOf("KEM ciphertext / DH share")).toBe("measured");
    expect(basisOf("Signature")).toBe("measured");
    expect(basisOf("Signature public key")).toBe("measured");
    expect(basisOf("Handshake first message (no OPK)")).toBe("measured");
    expect(basisOf("Handshake first message (with OPK)")).toBe("measured");
    // Composites are priced on paper, and must never read as measurements.
    expect(basisOf("Registration bundle (50 OPKs)")).toBe("analytic");
    expect(basisOf("Ratchet KEM step header")).toBe("analytic");

    // The note has to disclose that the classical column is a model, and that
    // the bundle row's classical side carries this protocol's leaf hashes -
    // 3,200 of its 4,992 bytes - which a real X3DH bundle does not have.
    expect(result.note).toContain("analytic");
    expect(result.note).toContain("X3DH");
    expect(result.note).toContain("3,200");
    expect(result.note).toContain("x40"); // leaf-free factor, vs the x14 shown
  });

  it("renders the basis in both the terminal and Markdown tables", () => {
    const terminal = renderTerminal([result]);
    const bundleLine = terminal.find((l) => l.trim().startsWith("Registration bundle"));
    expect(bundleLine?.trimEnd().endsWith("analytic")).toBe(true);
    expect(terminal.some((l) => l.includes("PQC basis"))).toBe(true);
    expect(terminal.some((l) => l.trim().startsWith("note:"))).toBe(true);

    const markdown = renderMarkdown([result], "now");
    const mdBundle = markdown
      .split("\n")
      .find((l) => l.startsWith("| Registration bundle (50 OPKs) |"));
    expect(mdBundle?.endsWith("| analytic |")).toBe(true);
    expect(markdown).toContain("| PQC basis |");
    expect(markdown).toContain(`_${result.note ?? ""}_`);
  });
});

describe("formatting", () => {
  // Three significant figures, no more: a batched sample is still quantised to
  // CLOCK_CLAMP_MS / batch, so a fourth digit would report the timer's grid
  // rather than the primitive. The unit switches to us below 1 ms.
  it("formats milliseconds to three significant figures", () => {
    expect(formatMs(2.5)).toBe("2.50 ms");
    expect(formatMs(0.5)).toBe("500 us");
    expect(formatMs(0.0005)).toBe("0.500 us"); // trailing zeros are significant
    expect(formatMs(0)).toBe("-");
  });

  it("never advertises a fourth digit, at any scale", () => {
    // The quantised figures from the run that motivated this: batch 32 lands on
    // 3.125 us boundaries, batch 64 on 1.5625 us, and neither supports a
    // 462.5 / 448.4 style reading.
    expect(formatMs(0.4625)).toBe("463 us");
    expect(formatMs(0.4484)).toBe("448 us");
    expect(formatMs(0.003125)).toBe("3.13 us"); // one tick at batch 32
    expect(formatMs(0.0015625)).toBe("1.56 us"); // one tick at batch 64
    expect(formatMs(0.1)).toBe("100 us"); // the clamp itself
    expect(formatMs(1.55)).toBe("1.55 ms");
    expect(formatMs(18.5)).toBe("18.5 ms");
    expect(formatMs(99.95)).toBe("100 ms"); // rounds across the magnitude edge
    expect(formatMs(1234.5)).toBe("1230 ms"); // never exponential, still 3 s.f.
  });

  it("formats bytes and factors", () => {
    expect(formatBytes(1184)).toBe("1,184");
    expect(formatFactor(9, 3)).toBe("x3.0"); // < 10 keeps a decimal
    expect(formatFactor(0, 3)).toBe("x0.0");
    expect(formatFactor(5, 0)).toBe("-"); // no classical baseline
  });
});

describe("parseSuite", () => {
  it("normalizes suite arguments", () => {
    expect(parseSuite(undefined)).toBe("all");
    expect(parseSuite("B1")).toBe("b1");
    expect(parseSuite("b3")).toBe("b3");
    expect(parseSuite("all")).toBe("all");
    expect(parseSuite("B4")).toBe("b4");
    expect(parseSuite("b9")).toBeNull();
    expect(parseSuite("garbage")).toBeNull();
  });

  // The usage string and the error text are what a user reads to discover the
  // options, so neither may drift from what parseSuite actually accepts.
  it("accepts every suite the /bench usage string and E105 advertise", () => {
    const advertised = [...COMMAND_USAGE.bench.matchAll(/\b(b\d|all)\b/g)].map((m) => m[1] ?? "");
    expect(advertised).toEqual(["b1", "b2", "b3", "b4", "all"]);
    for (const suite of advertised) {
      expect(parseSuite(suite), `/bench advertises ${suite}`).not.toBeNull();
    }
    for (const suite of advertised) {
      expect(ERRORS.E105(), `E105 should name ${suite}`).toContain(suite);
    }
  });
});

describe("runBench end-to-end (tiny sample count)", () => {
  const tiny = { ...DEFAULT_CONFIG, warmup: 1, iters: 3, yieldEvery: 0 };

  it("runs B3 with no timing and produces size rows + markdown", async () => {
    const out = await runBench("b3", { generatedAt: "2026-01-01T00:00:00Z" });
    expect(out.results).toHaveLength(1);
    expect(out.results[0]?.kind).toBe("size");
    expect(out.markdown).toContain("B3 - size overhead");
    expect(out.terminalLines.join("\n")).toContain("Signature");
    expect(JSON.parse(out.json).generatedAt).toBe("2026-01-01T00:00:00Z");
  });

  it("runs a latency suite against the classical baseline", async () => {
    const out = await runBench("b1", { config: tiny });
    expect(out.results).toHaveLength(1);
    const result = out.results[0];
    expect(result?.kind).toBe("latency");
    if (result?.kind === "latency") {
      expect(result.rows).toHaveLength(3);
      expect(result.rows[0]?.pqc.iters).toBe(3);
      expect(result.rows[0]?.classical?.iters).toBe(3);
    }
  });

  // The clamp is the floor under every figure in the table; a reader who cannot
  // see it will read four significant figures out of one tick.
  it("states the measurement floor beneath each latency table", async () => {
    const out = await runBench("b1", { config: tiny });
    const result = out.results[0];
    expect(result?.kind).toBe("latency");
    if (result?.kind === "latency") {
      // Each row's tick is the clamp over its own batch, not a suite-wide one.
      for (const row of result.rows) {
        expect(row.pqc.tickMs).toBeCloseTo(CLOCK_CLAMP_MS / row.pqc.batch, 12);
      }
    }
    // B1 mixes batches: ML-KEM at 32, X25519 at 64. Both must be disclosed,
    // each naming the ops it covers.
    expect(out.markdown).toContain("Timer resolution: 100 us clamped;");
    expect(out.markdown).toContain("batch 32 = 96 calls per row"); // 3 samples
    expect(out.markdown).toContain("batch 64 = 192 calls per row");
    expect(out.markdown).toContain("effective per-op resolution 3.13 us");
    expect(out.markdown).toContain("effective per-op resolution 1.56 us");
    expect(out.markdown).toContain("ml-kem encaps");
    expect(out.markdown).toContain("x25519 derive");
    // The terminal is the primary surface, so it carries the footnote too.
    expect(out.terminalLines.some((l) => l.includes("Timer resolution:"))).toBe(true);
  });

  // "over 1000 iterations" named the sample count while a batch-64 row was
  // executing 64,000 calls. Samples and warm-up are stated in the heading, the
  // batch and resulting call count in the footnote; neither is inferred.
  it("states samples and warm-up rather than an ambiguous iteration count", async () => {
    const out = await runBench("b1", { config: tiny });
    const result = out.results[0];
    expect(result?.kind).toBe("latency");
    if (result?.kind === "latency") {
      // The declared counts must be what the rows actually recorded.
      expect(result.samples).toBe(tiny.iters);
      expect(result.warmup).toBe(tiny.warmup);
      for (const row of result.rows) {
        expect(row.pqc.iters).toBe(result.samples);
        expect(row.classical?.iters ?? result.samples).toBe(result.samples);
      }
    }
    for (const surface of [out.markdown, out.terminalLines.join("\n")]) {
      expect(surface).toContain("over 3 samples per row");
      expect(surface).toContain("after 1 discarded warm-up sample");
      expect(surface).not.toContain("warm-up samples"); // 1 is singular
      expect(surface).not.toContain("iterations");
      // B1's rows do not share a batch, so no single figure can go in the
      // heading; it has to send the reader to the per-op breakdown.
      expect(surface).toContain("see the timer footnote for the batch per row");
    }
  });

  // X25519 has no split encaps/decaps, so one getSharedSecret is the baseline
  // for both ML-KEM halves. It is measured once and reported once: printing it
  // in the decaps row too would read as a second measurement nobody took.
  it("reports the shared X25519 baseline once, leaving the decaps row blank", async () => {
    const out = await runBench("b1", { config: tiny });
    const result = out.results[0];
    expect(result?.kind).toBe("latency");
    if (result?.kind === "latency") {
      const byOp = new Map(result.rows.map((r) => [r.op, r]));
      expect(byOp.get("keygen")?.classical).toBeDefined();
      expect(byOp.get("encaps")?.classical).toBeDefined();
      expect(byOp.get("decaps")?.classical).toBeUndefined();
      // The note carries the explanation, and has to name both halves.
      expect(result.note).toContain("encaps");
      expect(result.note).toContain("decaps");
    }

    // Terminal: classical median, p95 and factor are all blank, and the column
    // alignment survives (every row splits into the same six cells).
    const terminalRow = (op: string): string[] => {
      const line = out.terminalLines.find((l) => l.trim().startsWith(op));
      expect(line, `${op} row rendered`).toBeDefined();
      return (line ?? "").trim().split(/\s{2,}/);
    };
    expect(terminalRow("decaps").slice(-3)).toEqual(["-", "-", "-"]);
    expect(terminalRow("encaps")).toHaveLength(terminalRow("decaps").length);

    // Markdown: same three blank cells, so the table stays six columns wide.
    const mdRow = out.markdown.split("\n").find((l) => l.startsWith("| decaps |"));
    expect(mdRow).toBeDefined();
    expect(mdRow?.endsWith("| - | - | - |")).toBe(true);
    expect(mdRow?.split("|")).toHaveLength(8); // 6 cells + the leading/trailing empties
  });

  it("runs the B4 protocol suite (handshake + both ratchet modes)", async () => {
    const out = await runBench("b4", { config: tiny });
    expect(out.results).toHaveLength(1);
    const result = out.results[0];
    expect(result?.kind).toBe("protocol");
    if (result?.kind === "protocol") {
      // Both ratchet modes are reported: alternating turns force a KEM step per
      // message, a unidirectional burst amortises one over KEM_STEP_INTERVAL.
      // Reporting only one of them would misstate the sustained cost.
      expect(result.rows.map((r) => r.metric)).toEqual([
        "time-to-first-message (send)",
        "handshake round-trip",
        "ratchet message (alternating turns)",
        "ratchet message (unidirectional burst)",
      ]);
      // every metric produced real samples and neither ratchet loop desynced
      expect(result.rows.every((r) => r.stats.iters === 3)).toBe(true);
      const throughput = result.rows.filter((r) => r.display === "throughput");
      expect(throughput).toHaveLength(2);
      expect(throughput.every((r) => r.stats.opsPerSec > 0)).toBe(true);
      // The note has to name the interval the two rows bracket.
      expect(result.note).toContain(`KEM_STEP_INTERVAL=${KEM_STEP_INTERVAL}`);
    }
    expect(out.markdown).toContain("B4 - protocol level");
    // B4 times one operation per sample, so its floor is the raw clamp - the
    // coarsest in the report, and the one most worth disclosing.
    expect(out.markdown).toContain("effective per-op resolution 100 us");
  });

  // The table used to pair a median and a p95 with a rate computed from the
  // MEAN, with nothing saying so, and inverted a latency into a rate that read
  // as system capacity. Both centres are now shown, and named.
  it("shows the mean beside the median and only rates the throughput rows", async () => {
    const out = await runBench("b4", { config: tiny });
    const result = out.results[0];
    expect(result?.kind).toBe("protocol");
    if (result?.kind === "protocol") {
      // The rate is mean-derived; the column header has to keep matching that.
      for (const row of result.rows) {
        expect(row.stats.opsPerSec).toBeCloseTo(1000 / row.stats.meanMs, 6);
      }
    }

    const cells = (line: string): string[] => line.trim().split(/\s{2,}/);
    const terminalRow = (metric: string): string[] => {
      const line = out.terminalLines.find((l) => l.trim().startsWith(metric));
      expect(line, `${metric} row rendered`).toBeDefined();
      return cells(line ?? "");
    };
    // metric | median | p95 | mean | mean throughput
    expect(terminalRow("metric")).toEqual([
      "metric",
      "median",
      "p95",
      "mean",
      "mean throughput",
    ]);
    // A latency row shows no rate at all, not a rate of zero or a blank guess.
    expect(terminalRow("handshake round-trip")).toHaveLength(5);
    expect(terminalRow("handshake round-trip")[4]).toBe("-");
    expect(terminalRow("time-to-first-message")[4]).toBe("-");
    // A throughput row keeps its rate, carrying its own unit.
    expect(terminalRow("ratchet message (alternating turns)")[4]).toMatch(/^[\d,]+ msg\/s$/);

    const mdRow = (metric: string): string =>
      out.markdown.split("\n").find((l) => l.startsWith(`| ${metric}`)) ?? "";
    expect(out.markdown).toContain("| metric | median | p95 | mean | mean throughput |");
    expect(mdRow("handshake round-trip").endsWith("| - |")).toBe(true);
    expect(mdRow("ratchet message (unidirectional burst)")).toMatch(/\| [\d,]+ msg\/s \|$/);

    // The rate must be disclaimed wherever it appears.
    for (const surface of [out.markdown, out.terminalLines.join("\n")]) {
      expect(surface).toContain("Mean throughput is 1000 / mean");
      expect(surface).toContain("not system capacity");
      expect(surface).toContain("single-threaded");
    }
  });

  // The B4 rows decompose into B1/B2 primitives, which is both the "where does
  // the time go" answer and a soundness check on the harness. The counts are a
  // hand trace of crypto/kx.ts, so they get pinned here.
  describe("B4 primitive breakdown", () => {
    // Round numbers, so the predicted totals are checkable by inspection:
    // ttfm      = 2*1.5 + 2*0.5 + 1*6   = 10
    // handshake = 3*1.5 + 2*0.5 + 1*6 + 2*0.6 = 12.7
    const primitives: PrimitiveMedians = {
      kemName: "ML-KEM-768",
      dsaName: "ML-DSA-65",
      encapsMs: 0.5,
      decapsMs: 0.6,
      signMs: 6,
      verifyMs: 1.5,
    };

    it("prices each handshake row from its constituent primitives", async () => {
      const result = await benchB4(tiny, primitives);
      const entries = result.breakdown;
      expect(entries).toBeDefined();
      expect(entries?.map((e) => e.metric)).toEqual([
        "time-to-first-message (send)",
        "handshake round-trip",
      ]);
      // Every priced metric must name a row that actually exists in the table.
      const metrics = new Set(result.rows.map((row) => row.metric));
      expect(entries?.every((entry) => metrics.has(entry.metric))).toBe(true);

      const counts = (metric: string): Record<string, number> =>
        Object.fromEntries(
          (entries ?? [])
            .find((entry) => entry.metric === metric)
            ?.components.map((c) => [c.label, c.count]) ?? [],
        );
      // Traced from kx.ts: initiateKx verifies the SPK and the OPK batch,
      // encapsulates to both prekeys, and signs the transcript once.
      expect(counts("time-to-first-message (send)")).toEqual({
        "ML-DSA-65 verify": 2,
        "ML-KEM-768 encaps": 2,
        "ML-DSA-65 sign": 1,
      });
      // respondKx adds exactly one signature verify and two decapsulations.
      expect(counts("handshake round-trip")).toEqual({
        "ML-DSA-65 verify": 3,
        "ML-KEM-768 encaps": 2,
        "ML-DSA-65 sign": 1,
        "ML-KEM-768 decaps": 2,
      });

      const [ttfm, handshake] = entries ?? [];
      expect(ttfm?.predictedMs).toBeCloseTo(10, 10);
      expect(handshake?.predictedMs).toBeCloseTo(12.7, 10);
      // Predicted is the sum of count x each, and measured is the row's median,
      // so the residual the report prints is exactly their difference.
      for (const entry of entries ?? []) {
        const summed = entry.components.reduce((total, c) => total + c.count * c.eachMs, 0);
        expect(entry.predictedMs).toBeCloseTo(summed, 10);
        const row = result.rows.find((r) => r.metric === entry.metric);
        expect(entry.measuredMs).toBe(row?.stats.medianMs);
      }
    });

    it("renders the breakdown as a sub-table, not extra columns", async () => {
      const result = await benchB4(tiny, primitives);
      const terminal = renderTerminal([result]).join("\n");
      const markdown = renderMarkdown([result], "now");

      // The main table keeps its five columns; the breakdown is separate.
      expect(markdown).toContain("| metric | median | p95 | mean | mean throughput |");
      for (const surface of [terminal, markdown]) {
        expect(surface).toContain("where the time goes (primitive costs from B1/B2)");
        expect(surface).toContain("predicted total");
        expect(surface).toContain("measured median");
        expect(surface).toContain("residual");
        // The caveats that keep the prediction honest.
        expect(surface).toContain("traced by hand from crypto/kx.ts");
        expect(surface).toContain("the median of a sum is not the sum of medians");
      }
      expect(markdown).toContain("| metric | component | count | each | subtotal |");
      expect(markdown).toContain("| ML-DSA-65 sign | 1 | 6.00 ms | 6.00 ms |");
      expect(markdown).toContain("| ML-KEM-768 encaps | 2 | 500 us | 1.00 ms |");
      expect(markdown).toContain("| predicted total |  |  | 10.0 ms |");
    });

    it("omits the breakdown when B1/B2 have not run, and says why", async () => {
      const alone = await runBench("b4", { config: tiny });
      const result = alone.results[0];
      expect(result?.kind).toBe("protocol");
      if (result?.kind === "protocol") {
        expect(result.breakdown).toBeUndefined();
      }
      for (const surface of [alone.markdown, alone.terminalLines.join("\n")]) {
        expect(surface).not.toContain("where the time goes");
        expect(surface).toContain("No breakdown");
        // B4 must never re-run B1/B2 to fill the gap - that would change what
        // its own timings mean.
        expect(surface).toContain("will not run B1/B2 itself");
      }
    });

    it("needs both B1 and B2 before it can price anything", async () => {
      expect(primitiveMedians([])).toBeNull();
      const b1Only = await runBench("b1", { config: tiny });
      expect(primitiveMedians(b1Only.results)).toBeNull();
      const b3Only = await runBench("b3", { config: tiny });
      expect(primitiveMedians(b3Only.results)).toBeNull();
    });
  });

  // B4 caps its counts far below B1/B2's, which used to happen silently: a
  // reader comparing the two tables was comparing different sample sizes.
  it("declares B4's sample and warm-up counts on both surfaces", async () => {
    // The caps are the reason B4's counts differ, so they are named constants
    // the report and the README can both point at, not buried literals.
    expect(B4_MAX_SAMPLES).toBe(200);
    expect(B4_MAX_WARMUP).toBe(20);
    expect(B4_MAX_SAMPLES).toBeLessThan(DEFAULT_CONFIG.iters);
    expect(B4_MAX_WARMUP).toBeLessThan(DEFAULT_CONFIG.warmup);

    const out = await runBench("b4", { config: tiny });
    const result = out.results[0];
    expect(result?.kind).toBe("protocol");
    if (result?.kind === "protocol") {
      // Declared counts are what the rows actually recorded, not a guess the
      // renderer makes from the config it was never handed.
      expect(result.samples).toBe(tiny.iters); // below the cap, so unchanged
      expect(result.warmup).toBe(tiny.warmup);
      expect(result.rows.every((r) => r.stats.iters === result.samples)).toBe(true);
    }
    for (const surface of [out.markdown, out.terminalLines.join("\n")]) {
      expect(surface).toContain("over 3 samples per row");
      expect(surface).toContain("after 1 discarded warm-up sample");
      expect(surface).not.toContain("warm-up samples"); // 1 is singular
      // Every B4 row times one operation per sample, so the heading can state
      // the batch outright rather than deferring to the footnote.
      expect(surface).toContain("each timing a batch of 1 call, so 3 calls per row");
    }
  });

  it("runs all suites in order", async () => {
    const progress: string[] = [];
    const out = await runBench("all", { config: tiny, onProgress: (m) => progress.push(m) });
    expect(out.results.map((r) => r.suite)).toEqual(["B1", "B2", "B3", "B4"]);
    expect(progress).toHaveLength(4);
    expect(renderMarkdown(out.results, "now")).toContain("# Meridian Edge benchmark report");

    // B1/B2 run before B4, so the full run is the one that can price the
    // handshake rows - and it does so from those results, never a re-run.
    expect(primitiveMedians(out.results)).not.toBeNull();
    const b4 = out.results[3];
    expect(b4?.kind).toBe("protocol");
    if (b4?.kind === "protocol") {
      expect(b4.breakdown).toHaveLength(2);
      const b1 = out.results[0];
      const b2 = out.results[1];
      if (b1?.kind === "latency" && b2?.kind === "latency") {
        // The prices come from the B1/B2 medians in this same run.
        const encaps = b1.rows.find((r) => r.op === "encaps")?.pqc.medianMs;
        const sign = b2.rows.find((r) => r.op === "sign")?.pqc.medianMs;
        const ttfm = b4.breakdown?.[0];
        expect(ttfm?.components.find((c) => c.label.endsWith("encaps"))?.eachMs).toBe(encaps);
        expect(ttfm?.components.find((c) => c.label.endsWith("sign"))?.eachMs).toBe(sign);
      }
    }
  });
});
