// Benchmark entry point: runs the selected suites and returns
// the results plus terminal / Markdown / JSON renderings. Driven by the /bench
// command; also importable headlessly by tests.

import { benchB1, benchB2, benchB3, benchB4, DEFAULT_CONFIG, primitiveMedians } from "./suites";
import type { BenchConfig, SuiteResult } from "./suites";
import { renderMarkdown, renderTerminal } from "./report";

export type { BenchConfig, SuiteResult } from "./suites";
export { DEFAULT_CONFIG } from "./suites";

export type SuiteName = "b1" | "b2" | "b3" | "b4" | "all";

/** Normalize a raw /bench argument to a suite name, or null if unrecognized. */
export function parseSuite(raw: string | undefined): SuiteName | null {
  if (raw === undefined) {
    return "all";
  }
  const lower = raw.toLowerCase();
  if (lower === "b1" || lower === "b2" || lower === "b3" || lower === "b4" || lower === "all") {
    return lower;
  }
  return null;
}

export interface BenchOutput {
  readonly results: readonly SuiteResult[];
  readonly terminalLines: readonly string[];
  readonly markdown: string;
  readonly json: string;
}

export interface RunOptions {
  readonly config?: BenchConfig;
  /** Called before each suite starts, for interactive progress. */
  readonly onProgress?: (message: string) => void;
  /** Timestamp for the report header; injectable for deterministic tests. */
  readonly generatedAt?: string;
}

const TITLES: Record<Exclude<SuiteName, "all">, string> = {
  b1: "B1 (KEM latency)",
  b2: "B2 (signature latency)",
  b3: "B3 (size overhead)",
  b4: "B4 (protocol level)",
};

export async function runBench(suite: SuiteName, options: RunOptions = {}): Promise<BenchOutput> {
  const config = options.config ?? DEFAULT_CONFIG;
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const progress = options.onProgress ?? ((): void => {});
  const order: Exclude<SuiteName, "all">[] =
    suite === "all" ? ["b1", "b2", "b3", "b4"] : [suite];

  const results: SuiteResult[] = [];
  for (const name of order) {
    progress(`running ${TITLES[name]}...`);
    if (name === "b1") {
      results.push(await benchB1(config));
    } else if (name === "b2") {
      results.push(await benchB2(config));
    } else if (name === "b3") {
      results.push(benchB3());
    } else {
      // B4 prices its handshake rows against the B1/B2 medians when those
      // suites have already run in this session. It never runs them itself:
      // that would add their cost to the timings it is about to take, so
      // `/bench b4` alone simply reports no breakdown.
      results.push(await benchB4(config, primitiveMedians(results) ?? undefined));
    }
  }

  return {
    results,
    terminalLines: renderTerminal(results),
    markdown: renderMarkdown(results, generatedAt),
    json: JSON.stringify({ generatedAt, config, results }, null, 2),
  };
}
