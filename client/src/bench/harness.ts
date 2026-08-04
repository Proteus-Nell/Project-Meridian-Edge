// Benchmark timing core. Kept dependency-free and pure where it
// matters: summarize() is a total function over a sample array, unit-tested
// against known inputs; timeit() is the only impure part (performance.now + the
// work under test).
//
// Methodology: a warm-up run is discarded, then `iters` samples are
// collected and reported as median / p95 / mean. Fast primitives (X25519,
// Ed25519) sit near the browser's clamped performance.now() resolution,
// so each sample times a `batch` of calls and divides - the per-op
// figure stays meaningful without a high-resolution timer.
//
// Batching shrinks the quantisation but never removes it: every per-op figure
// is still a multiple of CLOCK_CLAMP_MS / batch. That floor travels with the
// numbers as `Stats.tickMs` so the report can state it instead of implying a
// precision the clock cannot deliver.

/** Granularity of `performance.now()` in the browser. The timer is coarsened
 * as a Spectre mitigation: a document that is not cross-origin isolated (COOP +
 * COEP) reads the clock at 100 us in Chrome and Edge, and every figure this
 * harness has produced lands exactly on that grid.
 *
 * It is an assumption, not a measurement: a context that coarsens further
 * (Firefox's default privacy.reduceTimerPrecision is 1 ms) would make the
 * resolution reported here optimistic by 10x, and cross-origin isolation would
 * make it pessimistic. The report prints the assumption for that reason. */
export const CLOCK_CLAMP_MS = 0.1;

export interface Stats {
  readonly label: string;
  readonly iters: number;
  readonly batch: number;
  readonly medianMs: number;
  readonly p95Ms: number;
  readonly meanMs: number;
  readonly minMs: number;
  readonly opsPerSec: number;
  /** Effective per-op timer resolution for this measurement: the clock clamp
   * divided by the batch size. Every figure in this row is a multiple of it,
   * and no difference smaller than it is real. */
  readonly tickMs: number;
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
    tickMs: CLOCK_CLAMP_MS / Math.max(1, batch),
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

/** Time `fn` per the methodology and return summary statistics. */
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
