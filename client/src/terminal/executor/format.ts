// Duration parsing/printing shared by the timer, purge, and view modules.

import type { Duration, DurationUnit } from "../parser";

export const DURATION_UNIT_SECONDS: Record<DurationUnit, number> = {
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60,
  w: 7 * 24 * 60 * 60,
};

/** Parsed duration to seconds; null for "off" (spec 5.2/5.3). */
export function durationToSeconds(duration: Duration): number | null {
  return duration.kind === "off" ? null : duration.amount * DURATION_UNIT_SECONDS[duration.unit];
}

/** Compact human label for a whole-unit second count (e.g. 3600 to "1h"). */
export function formatDuration(seconds: number): string {
  for (const unit of ["w", "d", "h", "m"] as const) {
    const size = DURATION_UNIT_SECONDS[unit];
    if (seconds % size === 0) {
      return `${seconds / size}${unit}`;
    }
  }
  return `${seconds}s`;
}
