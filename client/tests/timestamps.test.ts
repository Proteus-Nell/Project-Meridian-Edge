// The dating policy: what instant a received message is shown and sorted
// under. Exercised directly here, at its boundaries, because the two-executor
// fixture can only reach it through a real session - and a real session always
// opens with a KX message, which seeds the monotonicity floor and so puts the
// global floor out of reach end-to-end. The properties that matter are
// arithmetic, so they are asserted as arithmetic.

import { describe, expect, it } from "vitest";

import { stampIncoming } from "../src/terminal/executor/records";

const NOW = 1_788_618_340_000; // 5 September 2026, the bug report's own day
const DAY = 86_400_000;
const MINUTE = 60_000;

describe("stampIncoming", () => {
  it("falls back to arrival when the peer carried no time", () => {
    expect(stampIncoming(null, NOW)).toEqual({ ts: NOW, receivedAt: NOW });
  });

  it("falls back to arrival on a non-finite claim", () => {
    // The two decoders drop these before they get here; this is the second
    // guard, and the one a future third caller would rely on.
    expect(stampIncoming(Number.NaN, NOW).ts).toBe(NOW);
    expect(stampIncoming(Number.POSITIVE_INFINITY, NOW).ts).toBe(NOW);
    expect(stampIncoming(Number.NEGATIVE_INFINITY, NOW).ts).toBe(NOW);
  });

  it("passes an ordinary claim through untouched", () => {
    expect(stampIncoming(NOW - 2 * DAY, NOW).ts).toBe(NOW - 2 * DAY);
  });

  it("reaches back exactly as far as the queue TTL and no further", () => {
    expect(stampIncoming(NOW - 14 * DAY, NOW).ts).toBe(NOW - 14 * DAY);
    expect(stampIncoming(NOW - 14 * DAY - 1, NOW).ts).toBe(NOW - 14 * DAY);
    expect(stampIncoming(NOW - 4000 * DAY, NOW).ts).toBe(NOW - 14 * DAY);
  });

  it("allows exactly five minutes of forward skew and no more", () => {
    expect(stampIncoming(NOW + 5 * MINUTE, NOW).ts).toBe(NOW + 5 * MINUTE);
    expect(stampIncoming(NOW + 5 * MINUTE + 1, NOW).ts).toBe(NOW + 5 * MINUTE);
    expect(stampIncoming(NOW + 4000 * DAY, NOW).ts).toBe(NOW + 5 * MINUTE);
  });

  it("raises the floor to the previous message on the session", () => {
    // A peer cannot file a message below one they already sent.
    expect(stampIncoming(NOW - DAY, NOW, NOW - MINUTE).ts).toBe(NOW - MINUTE);
    // An honest claim above that floor is still its own.
    expect(stampIncoming(NOW - 30_000, NOW, NOW - MINUTE).ts).toBe(NOW - 30_000);
  });

  it("ignores a session floor older than the global one", () => {
    expect(stampIncoming(NOW - 20 * DAY, NOW, NOW - 30 * DAY).ts).toBe(NOW - 14 * DAY);
  });

  it("lets the ceiling win when the floor has overtaken it", () => {
    // Only reachable if the local clock jumped backwards since the previous
    // message. Documented as the one case where the floor does not hold.
    expect(stampIncoming(NOW, NOW, NOW + DAY).ts).toBe(NOW + 5 * MINUTE);
  });

  it("returns arrival unchanged whatever happens to the displayed time", () => {
    // Deadlines count from this, so nothing above may perturb it.
    for (const claim of [null, NOW, NOW - 4000 * DAY, NOW + 4000 * DAY, Number.NaN]) {
      expect(stampIncoming(claim, NOW, NOW - MINUTE).receivedAt).toBe(NOW);
    }
  });
});
