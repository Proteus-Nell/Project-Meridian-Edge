// Benchmark report formatting (MVP_DOC.md §8): turns suite results into aligned
// monospace tables for the terminal and Markdown tables for the report file,
// plus a JSON blob. Pure - no timing, no I/O.

import type { LatencyResult, ProtocolResult, SizeResult, SuiteResult } from "./suites";

export function formatMs(ms: number): string {
  if (ms === 0) {
    return "-";
  }
  if (ms < 0.001) {
    return `${(ms * 1000).toFixed(2)} us`;
  }
  if (ms < 1) {
    return `${(ms * 1000).toFixed(1)} us`;
  }
  return `${ms.toFixed(3)} ms`;
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

function latencyRows(result: LatencyResult): string[][] {
  return result.rows.map((row) => [
    row.op,
    formatMs(row.pqc.medianMs),
    formatMs(row.pqc.p95Ms),
    formatMs(row.classical.medianMs),
    formatMs(row.classical.p95Ms),
    formatFactor(row.pqc.medianMs, row.classical.medianMs),
  ]);
}

function sizeRows(result: SizeResult): string[][] {
  return result.rows.map((row) => [
    row.object,
    formatBytes(row.classicalBytes),
    formatBytes(row.pqcBytes),
    formatFactor(row.pqcBytes, row.classicalBytes),
  ]);
}

function protocolRows(result: ProtocolResult): string[][] {
  return result.rows.map((row) => [
    row.metric,
    formatMs(row.stats.medianMs),
    formatMs(row.stats.p95Ms),
    `${Math.round(row.stats.opsPerSec).toLocaleString("en-US")} ${row.unit}/s`,
  ]);
}

/** Terminal-friendly rendering (one string per line). */
export function renderTerminal(results: readonly SuiteResult[]): string[] {
  const lines: string[] = [];
  for (const result of results) {
    lines.push("", result.title);
    if (result.kind === "latency") {
      lines.push(`  ${result.pqcName} (PQC) vs ${result.classicalName} (classical), median of ${result.rows[0]?.pqc.iters ?? 0}`);
      lines.push(
        ...alignedTable(
          ["op", `${result.pqcName} med`, "p95", `${result.classicalName} med`, "p95", "factor"],
          latencyRows(result),
        ).map((l) => `  ${l}`),
      );
      if (result.note !== undefined) {
        lines.push(`  note: ${result.note}`);
      }
    } else if (result.kind === "protocol") {
      lines.push(
        ...alignedTable(["metric", "median", "p95", "rate"], protocolRows(result)).map(
          (l) => `  ${l}`,
        ),
      );
      if (result.note !== undefined) {
        lines.push(`  note: ${result.note}`);
      }
    } else {
      lines.push(
        ...alignedTable(["object", "classical", "pqc", "factor"], sizeRows(result)).map(
          (l) => `  ${l}`,
        ),
      );
    }
  }
  return lines;
}

function mdTable(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  const line = (cells: readonly string[]): string => `| ${cells.join(" | ")} |`;
  return [line(headers), line(headers.map(() => "---")), ...rows.map(line)].join("\n");
}

/** Markdown rendering for the report file. */
export function renderMarkdown(results: readonly SuiteResult[], generatedAt: string): string {
  const parts: string[] = [
    "# PQTerm benchmark report",
    "",
    `Generated: ${generatedAt}`,
    "",
    "PQC vs classical baselines (MVP_DOC.md §8). Latency figures are for these",
    "implementations in this environment, not the algorithms in the abstract.",
  ];
  for (const result of results) {
    parts.push("", `## ${result.title}`, "");
    if (result.kind === "latency") {
      parts.push(
        `${result.pqcName} (PQC) vs ${result.classicalName} (classical) - median / p95 over ${result.rows[0]?.pqc.iters ?? 0} iterations.`,
        "",
        mdTable(
          ["op", `${result.pqcName} median`, `${result.pqcName} p95`, `${result.classicalName} median`, `${result.classicalName} p95`, "factor"],
          latencyRows(result),
        ),
      );
      if (result.note !== undefined) {
        parts.push("", `_${result.note}_`);
      }
    } else if (result.kind === "protocol") {
      parts.push(mdTable(["metric", "median", "p95", "rate"], protocolRows(result)));
      if (result.note !== undefined) {
        parts.push("", `_${result.note}_`);
      }
    } else {
      parts.push(mdTable(["object", "classical", "pure PQC", "factor"], sizeRows(result)));
    }
  }
  return parts.join("\n") + "\n";
}
