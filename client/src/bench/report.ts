// Benchmark report formatting: turns suite results into aligned
// monospace tables for the terminal and Markdown tables for the report file,
// plus a JSON blob. Pure - no timing, no I/O.

import { CLOCK_CLAMP_MS } from "./harness";
import type { Stats } from "./harness";
import type {
  BreakdownEntry,
  LatencyResult,
  ProtocolResult,
  SizeResult,
  SuiteResult,
} from "./suites";

/** At most three significant figures, never exponential. Trailing zeros are
 * kept (0.5 -> "0.500"): they are significant digits, not padding. */
function significant3(value: number): string {
  const rounded = Number(value.toPrecision(3));
  const magnitude = Math.floor(Math.log10(rounded));
  return rounded.toFixed(Math.max(0, 2 - magnitude));
}

/** A duration, in the unit that suits its scale.
 *
 * Three significant figures, because that is the most any of these figures can
 * support: a batched sample is still quantised to CLOCK_CLAMP_MS / batch, so a
 * fourth digit would be reporting the timer's grid rather than the primitive.
 * Suites print their effective resolution alongside the table. */
export function formatMs(ms: number): string {
  if (ms === 0) {
    return "-";
  }
  if (ms < 1) {
    return `${significant3(ms * 1000)} us`;
  }
  return `${significant3(ms)} ms`;
}

export function formatBytes(bytes: number): string {
  return bytes.toLocaleString("en-US");
}

/** PQC-cost multiple relative to the classical baseline. */
export function formatFactor(pqc: number, classical: number): string {
  if (classical <= 0) {
    return "-";
  }
  const factor = pqc / classical;
  return factor >= 10 ? `x${Math.round(factor)}` : `x${factor.toFixed(1)}`;
}

/** Render a header + rows as an aligned monospace table (array of lines). */
function alignedTable(headers: readonly string[], rows: readonly (readonly string[])[]): string[] {
  const widths = headers.map((h, col) =>
    Math.max(h.length, ...rows.map((r) => (r[col] ?? "").length)),
  );
  const pad = (cells: readonly string[]): string =>
    cells.map((c, i) => (i === 0 ? c.padEnd(widths[i] ?? 0) : c.padStart(widths[i] ?? 0))).join("  ");
  const sep = widths.map((w) => "-".repeat(w)).join("  ");
  return [pad(headers), sep, ...rows.map(pad)];
}

/** Cells for a row whose classical side was never measured separately: the
 * baseline is reported once on another row (see the result's note). Blank
 * beats repeating that row's number, which would read as a second sample. */
const NO_CLASSICAL = ["-", "-", "-"] as const;

function latencyRows(result: LatencyResult): string[][] {
  return result.rows.map((row) => {
    const classical = row.classical;
    const classicalCells =
      classical === undefined
        ? [...NO_CLASSICAL]
        : [
            formatMs(classical.medianMs),
            formatMs(classical.p95Ms),
            formatFactor(row.pqc.medianMs, classical.medianMs),
          ];
    return [row.op, formatMs(row.pqc.medianMs), formatMs(row.pqc.p95Ms), ...classicalCells];
  });
}

function sizeRows(result: SizeResult): string[][] {
  return result.rows.map((row) => [
    row.object,
    formatBytes(row.classicalBytes),
    formatBytes(row.pqcBytes),
    formatFactor(row.pqcBytes, row.classicalBytes),
    // Whether the PQC figure came off a real object or out of a byte-layout
    // model. A composite priced on paper must not read like a measurement.
    row.basis,
  ]);
}

/** Column headers for a B4 table. The rate is named for the centre it comes
 * from: `opsPerSec` is 1000/mean, so a table showing median, p95 and an
 * unqualified "rate" was drawing from two centres without saying which. */
const PROTOCOL_HEADERS = ["metric", "median", "p95", "mean", "mean throughput"] as const;

function protocolRows(result: ProtocolResult): string[][] {
  return result.rows.map((row) => [
    row.metric,
    formatMs(row.stats.medianMs),
    formatMs(row.stats.p95Ms),
    // The mean is what the rate is built on, so it belongs in the table beside
    // the median rather than only surviving as a derived rate. Its distance
    // from the median is also the skew, which was previously invisible.
    formatMs(row.stats.meanMs),
    // A latency row reports latency. Inverting a per-op cost into a rate reads
    // as capacity, which this harness cannot measure.
    row.display === "throughput"
      ? `${Math.round(row.stats.opsPerSec).toLocaleString("en-US")} ${row.unit}/s`
      : "-",
  ]);
}

/** What the throughput column is, and what it is not. Rendered only when a
 * throughput row exists, so it can never describe an absent column. */
const RATE_FOOTNOTE =
  "Mean throughput is 1000 / mean for one single-threaded browser tab doing crypto only - " +
  "it is not system capacity: no network, no concurrency, no server, one core. Latency rows " +
  "carry no rate, since a per-op cost is not one. Where the mean exceeds the median the samples " +
  "are right-skewed, and the rate follows the mean rather than the median.";

function hasThroughputRow(result: ProtocolResult): boolean {
  return result.rows.some((row) => row.display === "throughput");
}

const BREAKDOWN_HEADERS = ["metric", "component", "count", "each", "subtotal"] as const;

const BREAKDOWN_TITLE = "where the time goes (primitive costs from B1/B2)";

const BREAKDOWN_NOTE =
  "Composition traced by hand from crypto/kx.ts, not instrumented - the fixture bundle carries " +
  "an OPK, so both ct2 paths run; an SPK-only handshake would drop one encaps and one decaps. " +
  "Predicted is the sum of per-op B1/B2 medians, and the median of a sum is not the sum of " +
  "medians, so read it as an estimate. B1/B2 also batch 32 calls per sample where B4 times one, " +
  "so their quantisation floors differ. The residual is everything the composition does not " +
  "name: SHA-512 transcript and prekey hashing, HKDF, XChaCha20-Poly1305, framing, allocation. " +
  "Line items are rounded for display while the totals come from the unrounded medians, so a " +
  "column may not add up in its last digit.";

const BREAKDOWN_ABSENT =
  "No breakdown: it prices these rows against the B1/B2 medians, which this run did not " +
  "produce. Run /bench with no argument. B4 will not run B1/B2 itself - that would add their " +
  "cost to the session it is timing.";

/** A signed duration, so a residual reads as the direction it went. */
function formatSignedMs(ms: number): string {
  if (ms === 0) {
    return "0";
  }
  return ms < 0 ? `-${formatMs(-ms)}` : `+${formatMs(ms)}`;
}

/** Line items then totals, one block per priced row. The metric is named once
 * per block; blank cells below it are continuation, which both table renderers
 * pad the same way. */
function breakdownRows(entries: readonly BreakdownEntry[]): string[][] {
  const rows: string[][] = [];
  for (const entry of entries) {
    entry.components.forEach((component, index) => {
      rows.push([
        index === 0 ? entry.metric : "",
        component.label,
        String(component.count),
        formatMs(component.eachMs),
        formatMs(component.count * component.eachMs),
      ]);
    });
    const residual = entry.measuredMs - entry.predictedMs;
    const share = entry.measuredMs > 0 ? (residual / entry.measuredMs) * 100 : 0;
    rows.push(["", "predicted total", "", "", formatMs(entry.predictedMs)]);
    rows.push(["", "measured median", "", "", formatMs(entry.measuredMs)]);
    rows.push(["", "residual", "", "", `${formatSignedMs(residual)} (${share.toFixed(1)}%)`]);
  }
  return rows;
}

/** Terminal-friendly rendering (one string per line). */
export function renderTerminal(results: readonly SuiteResult[]): string[] {
  const lines: string[] = [];
  for (const result of results) {
    lines.push("", result.title);
    if (result.kind === "latency") {
      lines.push(`  ${result.pqcName} (PQC) vs ${result.classicalName} (classical)`);
      lines.push(`  ${runCountLine(result)}`);
      lines.push(
        ...alignedTable(
          ["op", `${result.pqcName} med`, "p95", `${result.classicalName} med`, "p95", "factor"],
          latencyRows(result),
        ).map((l) => `  ${l}`),
      );
      if (result.note !== undefined) {
        lines.push(`  note: ${result.note}`);
      }
      lines.push(`  ${timerFootnote(result)}`);
    } else if (result.kind === "protocol") {
      // B4's counts are capped below B1/B2's, so the heading has to say so
      // here too - the terminal is where most readers meet these numbers.
      lines.push(`  ${runCountLine(result)}`);
      lines.push(
        ...alignedTable([...PROTOCOL_HEADERS], protocolRows(result)).map((l) => `  ${l}`),
      );
      if (result.note !== undefined) {
        lines.push(`  note: ${result.note}`);
      }
      if (hasThroughputRow(result)) {
        lines.push(`  ${RATE_FOOTNOTE}`);
      }
      lines.push(`  ${timerFootnote(result)}`);
      if (result.breakdown === undefined) {
        lines.push(`  ${BREAKDOWN_ABSENT}`);
      } else {
        lines.push("", `  ${BREAKDOWN_TITLE}`);
        lines.push(
          ...alignedTable([...BREAKDOWN_HEADERS], breakdownRows(result.breakdown)).map(
            (l) => `  ${l}`,
          ),
        );
        lines.push(`  ${BREAKDOWN_NOTE}`);
      }
    } else {
      lines.push(
        ...alignedTable(
          ["object", "classical", "pqc", "factor", "PQC basis"],
          sizeRows(result),
        ).map((l) => `  ${l}`),
      );
      if (result.note !== undefined) {
        lines.push(`  note: ${result.note}`);
      }
    }
  }
  return lines;
}

function mdTable(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  const line = (cells: readonly string[]): string => `| ${cells.join(" | ")} |`;
  return [line(headers), line(headers.map(() => "---")), ...rows.map(line)].join("\n");
}

/** What a suite actually ran, per row.
 *
 * "1000 iterations" was ambiguous once samples batch: it named the sample
 * count while a batch-64 row was executing 64,000 calls. So the sample and
 * warm-up counts are stated here, the per-row batch and resulting call count in
 * the timer footnote, and neither is left to be inferred from the other. */
function runCountLine(result: LatencyResult | ProtocolResult): string {
  const count = (n: number, noun: string): string =>
    `${n.toLocaleString("en-US")} ${noun}${n === 1 ? "" : "s"}`;
  // One batch across the whole suite (B4) states it inline; a suite whose rows
  // differ (B1 mixes 32 and 64, B2 mixes 1 and 32) has no single figure to
  // quote, so it points at the footnote that breaks it down per op.
  const batches = new Set(suiteStats(result).map((stats) => stats.batch));
  const only = batches.size === 1 ? [...batches][0] : undefined;
  const perRow =
    only === undefined
      ? "each a batch of calls - see the timer footnote for the batch per row"
      : `each timing a batch of ${count(only, "call")}, so ${count(result.samples * only, "call")} per row`;
  return (
    `median / p95 over ${count(result.samples, "sample")} per row (${perRow}), ` +
    `after ${count(result.warmup, "discarded warm-up sample")}`
  );
}

/** Every timed figure in a suite. */
function suiteStats(result: LatencyResult | ProtocolResult): Stats[] {
  if (result.kind === "protocol") {
    return result.rows.map((row) => row.stats);
  }
  return result.rows.flatMap((row) =>
    row.classical === undefined ? [row.pqc] : [row.pqc, row.classical],
  );
}

/** The suite's measurement floor, stated rather than implied. Batching divides
 * the clock's clamp but never abolishes it, so every figure in the table is a
 * multiple of its row's tick. Rows are grouped by batch because that is what
 * sets the tick, and each group names its ops so a reader can tell which rows
 * sit close to their floor - the ones whose digits mean least. */
function timerFootnote(result: LatencyResult | ProtocolResult): string {
  const byBatch = new Map<number, { tickMs: number; labels: string[] }>();
  for (const stats of suiteStats(result)) {
    const group = byBatch.get(stats.batch) ?? { tickMs: stats.tickMs, labels: [] };
    group.labels.push(stats.label);
    byBatch.set(stats.batch, group);
  }
  const groups = [...byBatch.entries()]
    .sort(([a], [b]) => a - b)
    .map(([batch, { tickMs, labels }]) => {
      // The number the old "over N iterations" heading hid: a batched row
      // executes samples x batch calls, not N.
      const calls = (result.samples * batch).toLocaleString("en-US");
      return (
        `batch ${batch} = ${calls} calls per row, effective per-op resolution ` +
        `${formatMs(tickMs)} (${labels.join(", ")})`
      );
    });
  return `Timer resolution: ${formatMs(CLOCK_CLAMP_MS)} clamped; ${groups.join("; ")}.`;
}

/** Markdown rendering for the report file. */
export function renderMarkdown(results: readonly SuiteResult[], generatedAt: string): string {
  const parts: string[] = [
    "# Meridian Edge benchmark report",
    "",
    `Generated: ${generatedAt}`,
    "",
    "PQC vs classical baselines. Latency figures are for these",
    "implementations in this environment, not the algorithms in the abstract.",
  ];
  for (const result of results) {
    parts.push("", `## ${result.title}`, "");
    if (result.kind === "latency") {
      parts.push(
        `${result.pqcName} (PQC) vs ${result.classicalName} (classical) - ${runCountLine(result)}.`,
        "",
        mdTable(
          ["op", `${result.pqcName} median`, `${result.pqcName} p95`, `${result.classicalName} median`, `${result.classicalName} p95`, "factor"],
          latencyRows(result),
        ),
      );
      if (result.note !== undefined) {
        parts.push("", `_${result.note}_`);
      }
      parts.push("", `_${timerFootnote(result)}_`);
    } else if (result.kind === "protocol") {
      parts.push(`${runCountLine(result)}.`, "");
      parts.push(mdTable([...PROTOCOL_HEADERS], protocolRows(result)));
      if (result.note !== undefined) {
        parts.push("", `_${result.note}_`);
      }
      if (hasThroughputRow(result)) {
        parts.push("", `_${RATE_FOOTNOTE}_`);
      }
      parts.push("", `_${timerFootnote(result)}_`);
      if (result.breakdown === undefined) {
        parts.push("", `_${BREAKDOWN_ABSENT}_`);
      } else {
        parts.push("", `### ${BREAKDOWN_TITLE}`, "");
        parts.push(mdTable([...BREAKDOWN_HEADERS], breakdownRows(result.breakdown)));
        parts.push("", `_${BREAKDOWN_NOTE}_`);
      }
    } else {
      parts.push(
        mdTable(["object", "classical", "pure PQC", "factor", "PQC basis"], sizeRows(result)),
      );
      if (result.note !== undefined) {
        parts.push("", `_${result.note}_`);
      }
    }
  }
  return parts.join("\n") + "\n";
}
