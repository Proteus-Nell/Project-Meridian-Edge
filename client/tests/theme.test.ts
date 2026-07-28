import { describe, expect, it } from "vitest";

import {
  EVENT_COLOR_SLOTS,
  MAX_CUSTOM_SCHEMES,
  SCHEMES,
  isValidCustomSchemeName,
  normalizeHex,
  resolveEventColors,
  resolveScheme,
  sanitizeCustomSchemes,
  schemeColorsOf,
  schemeExists,
} from "../src/terminal/theme";
import type { CustomScheme } from "../src/terminal/theme";

function custom(name: string, over: Partial<CustomScheme["colors"]> = {}): CustomScheme {
  return {
    name,
    base: "dark",
    colors: { ...SCHEMES.dark.colors, ...over },
  };
}

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

  it("rejects values that would break out of a CSS declaration", () => {
    // The only thing standing between the prefs record and style.setProperty.
    for (const attack of [
      "red;}body{display:none",
      "#112233;}",
      "url(https://example.invalid)",
      "var(--x)",
      "expression(alert(1))",
      "#112233 !important",
    ]) {
      expect(normalizeHex(attack), attack).toBeNull();
    }
  });
});

describe("resolveScheme", () => {
  it("returns the pure scheme for a preset", () => {
    const resolved = resolveScheme("olive", []);
    expect(resolved.accent).toBe(SCHEMES.olive.colors.accent);
    expect(resolved.background).toBe("#141a0e");
    expect(resolved.ansi).toBeNull();
  });

  it("resolves a custom scheme by name", () => {
    const resolved = resolveScheme("mine", [custom("mine", { accent: "#ff0000" })]);
    expect(resolved.accent).toBe("#ff0000");
    expect(resolved.background).toBe(SCHEMES.dark.colors.background);
  });

  it("inherits the base preset's ANSI overrides so a light fork stays legible", () => {
    const light: CustomScheme = { name: "paper", base: "parchment", colors: SCHEMES.parchment.colors };
    expect(resolveScheme("paper", [light]).ansi).toEqual(SCHEMES.parchment.ansi);
    expect(resolveScheme("parchment", []).ansi).not.toBeNull();
  });

  it("falls back to the default preset for a name that does not exist", () => {
    const resolved = resolveScheme("deleted-yesterday", []);
    expect(resolved.accent).toBe(SCHEMES.dark.colors.accent);
  });

  it("never lets a custom scheme shadow a preset", () => {
    // sanitize drops such an entry, but resolve checks presets first regardless.
    const impostor = { name: "dark", base: "dark", colors: { ...SCHEMES.dark.colors, accent: "#ff0000" } } as CustomScheme;
    expect(resolveScheme("dark", [impostor]).accent).toBe(SCHEMES.dark.colors.accent);
  });
});

describe("preset immutability", () => {
  it("hands out a copy, so a caller cannot mutate the shipped palette", () => {
    const first = schemeColorsOf("dark", []);
    first.accent = "#ff0000";
    expect(SCHEMES.dark.colors.accent).toBe("#58a6ff");
    expect(resolveScheme("dark", []).accent).toBe("#58a6ff");
    expect(schemeColorsOf("dark", []).accent).toBe("#58a6ff");
  });
});

describe("isValidCustomSchemeName", () => {
  it("accepts ordinary names", () => {
    for (const name of ["mine", "midnight", "dark-custom", "a", "z9-x", "a".repeat(24)]) {
      expect(isValidCustomSchemeName(name), name).toBe(true);
    }
  });

  it("rejects preset and reserved words, which would shadow the grammar", () => {
    for (const name of ["dark", "parchment", "olive", "new", "delete", "list", "reset"]) {
      expect(isValidCustomSchemeName(name), name).toBe(false);
    }
  });

  it("rejects prototype-shaped names", () => {
    for (const name of ["__proto__", "constructor", "prototype"]) {
      expect(isValidCustomSchemeName(name), name).toBe(false);
    }
  });

  it("rejects anything that could carry markup, escapes, or separators", () => {
    for (const name of [
      "",
      "Mine", // uppercase: names are canonically lowercase
      "-leading",
      "9leading",
      "with space",
      "with_underscore",
      "semi;colon",
      "../etc/passwd",
      "<script>",
      "a".repeat(25),
      "[31mred",
      "tab\there",
      "new\nline",
    ]) {
      expect(isValidCustomSchemeName(name), JSON.stringify(name)).toBe(false);
    }
  });
});

describe("sanitizeCustomSchemes", () => {
  it("passes a well-formed list through, normalizing hex case", () => {
    const cleaned = sanitizeCustomSchemes([
      { name: "mine", base: "olive", colors: { ...SCHEMES.dark.colors, accent: "#AABBCC" } },
    ]);
    expect(cleaned).toHaveLength(1);
    expect(cleaned[0]?.base).toBe("olive");
    expect(cleaned[0]?.colors.accent).toBe("#aabbcc");
  });

  it("returns an empty list for anything that is not an array", () => {
    for (const raw of [undefined, null, 0, "nope", {}, { mine: custom("mine") }]) {
      expect(sanitizeCustomSchemes(raw)).toEqual([]);
    }
  });

  it("drops entries with an unusable name, keeping the rest", () => {
    const cleaned = sanitizeCustomSchemes([
      custom("__proto__"),
      custom("dark"),
      custom("list"),
      custom("keeper"),
      custom("with space"),
    ]);
    expect(cleaned.map((s) => s.name)).toEqual(["keeper"]);
  });

  it("drops an entry whose colors are incomplete or invalid", () => {
    const cleaned = sanitizeCustomSchemes([
      { name: "missing-slot", base: "dark", colors: { accent: "#112233" } },
      { name: "bad-value", base: "dark", colors: { ...SCHEMES.dark.colors, muted: "chartreuse" } },
      { name: "no-colors", base: "dark" },
      custom("keeper"),
    ]);
    expect(cleaned.map((s) => s.name)).toEqual(["keeper"]);
  });

  it("defaults an unknown base rather than dropping an otherwise good scheme", () => {
    const cleaned = sanitizeCustomSchemes([{ ...custom("mine"), base: "neon" }]);
    expect(cleaned[0]?.base).toBe("dark");
  });

  it("keeps the first of a duplicated name", () => {
    const cleaned = sanitizeCustomSchemes([
      custom("mine", { accent: "#111111" }),
      custom("mine", { accent: "#222222" }),
    ]);
    expect(cleaned).toHaveLength(1);
    expect(cleaned[0]?.colors.accent).toBe("#111111");
  });

  it("caps the list, so a tampered record cannot bloat the prefs blob", () => {
    const many = Array.from({ length: MAX_CUSTOM_SCHEMES + 20 }, (_, i) => custom(`s${i}`));
    expect(sanitizeCustomSchemes(many)).toHaveLength(MAX_CUSTOM_SCHEMES);
  });

  it("leaves Object.prototype alone even when handed a __proto__ entry", () => {
    sanitizeCustomSchemes([{ name: "__proto__", base: "dark", colors: SCHEMES.dark.colors }]);
    sanitizeCustomSchemes(JSON.parse('[{"name":"__proto__","polluted":true}]'));
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).colors).toBeUndefined();
  });
});

describe("schemeExists", () => {
  it("covers presets and custom schemes, and nothing else", () => {
    const customs = [custom("mine")];
    expect(schemeExists("dark", customs)).toBe(true);
    expect(schemeExists("mine", customs)).toBe(true);
    expect(schemeExists("nope", customs)).toBe(false);
    expect(schemeExists("new", customs)).toBe(false);
  });
});

describe("resolveEventColors", () => {
  it("fills every slot, so the DOM status strip always has a real value", () => {
    const resolved = resolveEventColors(null, undefined);
    for (const slot of EVENT_COLOR_SLOTS) {
      expect(resolved[slot], slot).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  it("prefers the user's choice, then the base preset, then the built-in", () => {
    // dark carries no ANSI map, so an unset slot falls all the way through.
    expect(resolveEventColors(null, undefined).success).toBe("#3fb950");
    // parchment darkens its ANSI for a light background; the strip follows.
    expect(resolveEventColors(SCHEMES.parchment.ansi, undefined).success).toBe(
      SCHEMES.parchment.ansi?.green,
    );
    // and an explicit choice wins over both.
    expect(resolveEventColors(SCHEMES.parchment.ansi, { success: "#ff00ff" }).success).toBe(
      "#ff00ff",
    );
  });

  it("is exposed on every resolved scheme, preset or custom", () => {
    for (const name of ["dark", "parchment", "olive", "nonexistent"]) {
      const resolved = resolveScheme(name, []);
      for (const slot of EVENT_COLOR_SLOTS) {
        expect(resolved.events[slot], `${name}/${slot}`).toMatch(/^#[0-9a-f]{6}$/);
      }
    }
    const mine: CustomScheme = { ...custom("mine"), events: { warning: "#123456" } };
    expect(resolveScheme("mine", [mine]).events.warning).toBe("#123456");
  });

  it("leaves the terminal ANSI map untouched when no marker was set", () => {
    // The strip needs concrete values; the transcript is happy with xterm's own
    // palette, so resolving strip colors must not start overriding ANSI.
    expect(resolveScheme("dark", []).ansi).toBeNull();
    expect(resolveScheme("olive", []).ansi).toBeNull();
  });
});
