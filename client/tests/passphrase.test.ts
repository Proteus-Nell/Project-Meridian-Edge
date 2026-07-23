// Strength rules for a new passphrase (executor/identity.ts), shared by
// /register, /recover and /rotate passphrase.
//
// The passphrase never leaves the device: it derives the KEK that wraps the
// store's DEK through Argon2id. Offline guessing against a copied IndexedDB is
// therefore the threat these rules price, which is why length is checked first
// and reported separately from composition.

import { describe, expect, it } from "vitest";

import { passphraseProblem } from "../src/terminal/executor/identity";

describe("passphraseProblem", () => {
  it("accepts a passphrase meeting all three rules", () => {
    expect(passphraseProblem("correct horse 7!")).toBeNull();
  });

  it("enforces the 12-character floor at the boundary", () => {
    expect(passphraseProblem("elevench3!x")).toBe("short"); // 11
    expect(passphraseProblem("twelvechar3!")).toBeNull(); // 12
  });

  it("rejects an empty or trivially short passphrase", () => {
    expect(passphraseProblem("")).toBe("short");
    expect(passphraseProblem("ab3!")).toBe("short");
  });

  it("requires at least one digit", () => {
    expect(passphraseProblem("no digits here!")).toBe("composition");
  });

  it("requires at least one symbol", () => {
    expect(passphraseProblem("alphanumeric123")).toBe("composition");
  });

  it("counts any non-alphanumeric as a symbol, spaces and non-Latin included", () => {
    expect(passphraseProblem("spaces count 1")).toBeNull();
    expect(passphraseProblem("unicode ok 1 é£")).toBeNull();
  });

  // Length is the dominant factor, so a passphrase failing both rules should
  // be told to get longer rather than to sprinkle in punctuation.
  it("reports length before composition when both fail", () => {
    expect(passphraseProblem("short")).toBe("short");
  });
});
