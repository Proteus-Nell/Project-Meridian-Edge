import { describe, expect, it } from "vitest";

import { computeSafetyNumber, formatSafetyNumber } from "../src/crypto/safetynumber";

const ikA = new Uint8Array(1952).fill(1);
const ikB = new Uint8Array(1952).fill(2);

describe("computeSafetyNumber", () => {
  it("is symmetric: both parties derive the identical number", () => {
    const fromAlice = computeSafetyNumber(ikA, "ALICEUID000000000000000000", ikB, "BOBUID0000000000000000000000");
    const fromBob = computeSafetyNumber(ikB, "BOBUID0000000000000000000000", ikA, "ALICEUID000000000000000000");
    expect(fromBob.groups).toEqual(fromAlice.groups);
  });

  it("produces 12 groups of exactly 5 digits (60 digits total)", () => {
    const sn = computeSafetyNumber(ikA, "AAAA", ikB, "BBBB");
    expect(sn.groups).toHaveLength(12);
    for (const g of sn.groups) {
      expect(g).toMatch(/^\d{5}$/);
    }
  });

  it("changes when either identity key changes", () => {
    const base = computeSafetyNumber(ikA, "AAAA", ikB, "BBBB");
    const ikBTampered = ikB.slice();
    ikBTampered[0] = (ikBTampered[0] ?? 0) ^ 0xff;
    const changed = computeSafetyNumber(ikA, "AAAA", ikBTampered, "BBBB");
    expect(changed.groups).not.toEqual(base.groups);
  });

  it("changes when either UID changes", () => {
    const base = computeSafetyNumber(ikA, "AAAA", ikB, "BBBB");
    const changed = computeSafetyNumber(ikA, "AAAA", ikB, "CCCC");
    expect(changed.groups).not.toEqual(base.groups);
  });

  it("is deterministic", () => {
    const first = computeSafetyNumber(ikA, "AAAA", ikB, "BBBB");
    const second = computeSafetyNumber(ikA, "AAAA", ikB, "BBBB");
    expect(second.groups).toEqual(first.groups);
  });
});

describe("formatSafetyNumber", () => {
  it("renders 3 rows of 4 groups", () => {
    const sn = computeSafetyNumber(ikA, "AAAA", ikB, "BBBB");
    const rows = formatSafetyNumber(sn);
    expect(rows).toHaveLength(3);
    for (const row of rows) {
      expect(row.split(" ")).toHaveLength(4);
    }
  });
});
