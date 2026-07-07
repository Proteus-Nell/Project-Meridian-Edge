// Benchmark timing core (MVP_DOC.md §8). Kept dependency-free and pure where it
// matters: summarize() is a total function over a sample array, unit-tested
// against known inputs; timeit() is the only impure part (performance.now + the
// work under test).
//
// Methodology (MVP §8): a warm-up run is discarded, then `iters` samples are
// collected and reported as median / p95 / mean. Fast primitives (X25519,
// Ed25519 at tens of microseconds) sit near the browser's clamped
// performance.now() resolution, so each sample times a `batch` of calls and
// divides - the per-op figure stays meaningful without a high-resolution timer.

export interface Stats {
  readonly label: string;
  readonly iters: number;
  readonly batch: number;
  readonly medianMs: number;
  readonly p95Ms: number;
  readonly meanMs: number;
  readonly minMs: number;
  readonly opsPerSec: number;
}

/** Nearest-rank percentile over an already-collected sample set. */
function percentile(sortedAsc: readonly number[], p: number): number {
  if (sortedAsc.length === 0) {
    return 0;
  }
  const rank = Math.ceil((p / 100) * sortedAsc.length);
  const index = Math.min(sortedAsc.length - 1, Math.max(0, rank - 1));
  return sortedAsc[index] ?? 0;
}

/** Reduce per-op millisecond samples to summary statistics. Pure. */
export function summarize(label: string, samplesMs: readonly number[], batch = 1): Stats {
  const sorted = [...samplesMs].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const meanMs = n === 0 ? 0 : sum / n;
  return {
    label,
    iters: n,
    batch,
    medianMs: percentile(sorted, 50),
    p95Ms: percentile(sorted, 95),
    meanMs,
    minMs: sorted[0] ?? 0,
    opsPerSec: meanMs > 0 ? 1000 / meanMs : 0,
  };
}

export interface TimeitOptions {
  readonly warmup: number;
  readonly iters: number;
  /** Calls per timed sample; the sample value is (batch time / batch). */
  readonly batch: number;
  /** Yield to the event loop every N samples so an interactive run keeps the
   * terminal responsive. Yielding happens between samples, never inside a
   * timed region, so it does not perturb the measurement. */
  readonly yieldEvery?: number;
}

const yieldToEventLoop = (): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, 0);
  });

/** Time `fn` per the §8 methodology and return summary statistics. */
export async function timeit(
  label: string,
  fn: () => void,
  opts: TimeitOptions,
): Promise<Stats> {
  const { warmup, iters, batch } = opts;
  const yieldEvery = opts.yieldEvery ?? 0;
  for (let i = 0; i < warmup; i += 1) {
    fn();
  }
  const samples: number[] = new Array<number>(iters);
  for (let i = 0; i < iters; i += 1) {
    const start = performance.now();
    for (let b = 0; b < batch; b += 1) {
      fn();
    }
    samples[i] = (performance.now() - start) / batch;
    if (yieldEvery > 0 && (i + 1) % yieldEvery === 0) {
      await yieldToEventLoop();
    }
  }
  return summarize(label, samples, batch);
}
