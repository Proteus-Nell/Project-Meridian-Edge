// /bench: run the PQC-vs-classical benchmark suites in the browser.
// The whole bench module, including its classical baseline primitives, is
// dynamically imported so it only loads on demand and never enters the main
// bundle (keeps the B5 size delta honest).

import type { ExecutorInternals } from "./context";

/** Offer the machine-readable report as a file, so the researcher gets
 * something they can pass straight to `bench/consolidate.py` instead of
 * selecting JSON out of devtools. Returns false when there is no DOM to hang
 * the download off, or the browser refuses it - the console dump is the
 * fallback either way, so a failure here costs nothing. */
function offerDownload(json: string, filename: string): boolean {
  if (typeof document === "undefined" || typeof URL.createObjectURL !== "function") {
    return false;
  }
  let url: string | null = null;
  try {
    url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    link.remove();
    return true;
  } catch {
    return false;
  } finally {
    if (url !== null) {
      // Revoking in the same task can cancel the download that was just
      // started, so let the click settle first.
      const settled = url;
      setTimeout(() => {
        URL.revokeObjectURL(settled);
      }, 0);
    }
  }
}

export async function doBench(x: ExecutorInternals, suite: string | undefined): Promise<void> {
  const bench = await import("../../bench/index");
  const parsed = bench.parseSuite(suite);
  if (parsed === null) {
    x.renderer.error("E105");
    return;
  }
  x.renderer.event(
    "info",
    "Running benchmarks, comparing PQC against classical primitives. Primitive latency takes a few seconds...",
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
  // The JSON is also offered as a file, because it is an input to
  // `make bench-report` - the step that merges these browser suites with the
  // native and bundle numbers into one document.
  const filename = `meridian-bench-${parsed}.json`;
  const downloaded = offerDownload(output.json, filename);
  x.renderer.event(
    "success",
    downloaded
      ? `Benchmark complete. JSON saved as ${filename} (and printed to the browser console). ` +
          "For the consolidated report: move it to bench/out/browser.json and run make bench-report."
      : "Benchmark complete. The full JSON and Markdown went to the browser console. " +
          "For the consolidated report: save the JSON to bench/out/browser.json and run make bench-report.",
  );
}
