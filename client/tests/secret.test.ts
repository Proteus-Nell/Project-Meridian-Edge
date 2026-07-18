import { describe, expect, it } from "vitest";

import { constantTimeEqual, secretStringsEqual } from "../src/util/secret";

describe("constantTimeEqual", () => {
  it("matches equal arrays and rejects different ones", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([]), new Uint8Array([]))).toBe(true);
  });

  it("rejects different lengths", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
  });
});

describe("secretStringsEqual", () => {
  it("compares by content including unicode", () => {
    expect(secretStringsEqual("pass phrase ✓", "pass phrase ✓")).toBe(true);
    expect(secretStringsEqual("passphrase", "passphrasE")).toBe(false);
    expect(secretStringsEqual("", "")).toBe(true);
    expect(secretStringsEqual("a", "ab")).toBe(false);
  });
});
