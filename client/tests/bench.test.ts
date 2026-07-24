// Benchmark harness: the pure pieces (stats, size math,
// formatting, suite parsing) are asserted exactly; the timed suites run with a
// tiny iteration count just to prove they execute and shape their results.

import { describe, expect, it } from "vitest";

import { summarize } from "../src/bench/harness";
import { benchB3, DEFAULT_CONFIG } from "../src/bench/suites";
import { formatBytes, formatFactor, formatMs, renderMarkdown } from "../src/bench/report";
import { parseSuite, runBench } from "../src/bench/index";
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
});

describe("B3 size overhead", () => {
  const result = benchB3();
  const byObject = new Map(result.rows.map((r) => [r.object, r]));

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
    // Handshake first message: IK + ct1 + sig + AEAD overhead(24+16)
    expect(byObject.get("Handshake first message")?.pqcBytes).toBe(1952 + 1088 + 3309 + 40);
  });
});

describe("formatting", () => {
  it("formats milliseconds across scales", () => {
    expect(formatMs(2.5)).toBe("2.500 ms");
    expect(formatMs(0.5)).toBe("500.0 us");
    expect(formatMs(0.0005)).toBe("0.50 us");
    expect(formatMs(0)).toBe("-");
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

describe("runBench end-to-end (tiny iteration count)", () => {
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
      expect(result.rows[0]?.classical.iters).toBe(3);
    }
  });

  it("runs the B4 protocol suite (handshake + ratchet throughput)", async () => {
    const out = await runBench("b4", { config: tiny });
    expect(out.results).toHaveLength(1);
    const result = out.results[0];
    expect(result?.kind).toBe("protocol");
    if (result?.kind === "protocol") {
      expect(result.rows.map((r) => r.metric)).toContain("handshake round-trip");
      // every metric produced real samples and the ratchet did not desync
      expect(result.rows.every((r) => r.stats.iters === 3)).toBe(true);
      const throughput = result.rows.find((r) => r.display === "throughput");
      expect(throughput?.stats.opsPerSec).toBeGreaterThan(0);
    }
    expect(out.markdown).toContain("B4 - protocol level");
  });

  it("runs all suites in order", async () => {
    const progress: string[] = [];
    const out = await runBench("all", { config: tiny, onProgress: (m) => progress.push(m) });
    expect(out.results.map((r) => r.suite)).toEqual(["B1", "B2", "B3", "B4"]);
    expect(progress).toHaveLength(4);
    expect(renderMarkdown(out.results, "now")).toContain("# Meridian Edge benchmark report");
  });
});
