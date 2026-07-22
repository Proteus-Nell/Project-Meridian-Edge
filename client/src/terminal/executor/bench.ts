// /bench (§8): run the PQC-vs-classical benchmark suites in the browser.
// The whole bench module, including its classical baseline primitives, is
// dynamically imported so it only loads on demand and never enters the main
// bundle (keeps the B5 size delta honest).

import type { ExecutorInternals } from "./context";

export async function doBench(x: ExecutorInternals, suite: string | undefined): Promise<void> {
  const bench = await import("../../bench/index");
  const parsed = bench.parseSuite(suite);
  if (parsed === null) {
    x.renderer.event("failure", "unknown suite - use b1, b2, b3, or omit for all");
    return;
  }
  x.renderer.event(
    "info",
    "running benchmarks (PQC vs classical primitives) - primitive latency takes a few seconds...",
  );
  const output = await bench.runBench(parsed, {
    onProgress: (message) => x.renderer.event("info", message),
  });
  for (const line of output.terminalLines) {
    x.renderer.plain(line);
  }
  // The machine-readable report goes to the browser console for the
  // researcher to capture; the terminal shows the human-readable tables.
  if (typeof console !== "undefined") {
    console.log(output.markdown);
    console.log(output.json);
  }
  x.renderer.event("success", "benchmark complete - JSON + Markdown logged to the browser console");
}
