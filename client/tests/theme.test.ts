import { describe, expect, it } from "vitest";

import { normalizeHex, resolveScheme, SCHEMES } from "../src/terminal/theme";

describe("normalizeHex", () => {
  it("accepts 6-digit hex with or without #, normalizing to lowercase #rrggbb", () => {
    expect(normalizeHex("#1A2B3C")).toBe("#1a2b3c");
    expect(normalizeHex("1a2b3c")).toBe("#1a2b3c");
  });

  it("rejects everything else", () => {
    for (const bad of ["#fff", "red", "#12345", "#1234567", "112233x", "", "#gg0011"]) {
      expect(normalizeHex(bad), bad).toBeNull();
    }
  });
});

describe("resolveScheme", () => {
  it("returns the pure scheme when there are no overrides", () => {
    const resolved = resolveScheme("olive", {});
    expect(resolved.accent).toBe(SCHEMES.olive.colors.accent);
    expect(resolved.background).toBe("#141a0e");
    expect(resolved.ansi).toBeNull();
  });

  it("layers HEX overrides on top of the scheme", () => {
    const resolved = resolveScheme("dark", { accent: "#ff0000", muted: "#00ff00" });
    expect(resolved.accent).toBe("#ff0000");
    expect(resolved.muted).toBe("#00ff00");
    expect(resolved.background).toBe(SCHEMES.dark.colors.background);
  });

  it("ignores invalid override values", () => {
    const resolved = resolveScheme("dark", { accent: "chartreuse" });
    expect(resolved.accent).toBe(SCHEMES.dark.colors.accent);
  });

  it("parchment carries ANSI overrides for light-background legibility", () => {
    const resolved = resolveScheme("parchment", {});
    expect(resolved.ansi).not.toBeNull();
    expect(resolved.ansi?.brightCyan).toBeDefined();
  });
});
