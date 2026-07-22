// Color schemes and emblem catalog (CLAUDE.md §1). Pure data + helpers, no
// DOM: chrome.ts turns a resolved scheme into CSS custom properties and xterm
// theme objects; the executor persists the user's choice in the unencrypted
// display prefs. Each scheme is exactly five slots (accent / background /
// panel / text / muted) - matching the design references - plus an optional
// ANSI override map so terminal output stays legible on light backgrounds.

export const COLOR_SLOTS = ["accent", "background", "panel", "text", "muted"] as const;
export type ColorSlot = (typeof COLOR_SLOTS)[number];

export type SchemeColors = Record<ColorSlot, string>;

/** Subset of xterm's ITheme we override per scheme (ANSI slots our renderer
 * actually emits: 31/32/33/36 + bright cyan for peer aliases). */
export interface AnsiOverrides {
  readonly red?: string;
  readonly green?: string;
  readonly yellow?: string;
  readonly cyan?: string;
  readonly brightRed?: string;
  readonly brightGreen?: string;
  readonly brightYellow?: string;
  readonly brightCyan?: string;
}

export interface Scheme {
  readonly colors: SchemeColors;
  readonly ansi: AnsiOverrides | null;
}

export const SCHEME_NAMES = ["dark", "parchment", "olive"] as const;
export type SchemeName = (typeof SCHEME_NAMES)[number];

export function isSchemeName(word: string): word is SchemeName {
  return (SCHEME_NAMES as readonly string[]).includes(word);
}

/** dark = the original GitHub-dark palette; parchment + olive come from the
 * design reference swatches (light paper and dark olive-green). */
export const SCHEMES: Record<SchemeName, Scheme> = {
  dark: {
    colors: {
      accent: "#58a6ff",
      background: "#0d1117",
      panel: "#161b22",
      text: "#c9d1d9",
      muted: "#8b949e",
    },
    ansi: null,
  },
  parchment: {
    colors: {
      accent: "#8a6d2f",
      background: "#e3e7d3",
      panel: "#f0efe0",
      text: "#2b3320",
      muted: "#5f6d4e",
    },
    // Default ANSI colors are tuned for dark backgrounds; darken the ones our
    // output uses so events stay readable on paper.
    ansi: {
      red: "#a13424",
      green: "#43682f",
      yellow: "#8a6a1f",
      cyan: "#20606b",
      brightRed: "#b42318",
      brightGreen: "#3f6212",
      brightYellow: "#92400e",
      brightCyan: "#0f4c5c",
    },
  },
  olive: {
    colors: {
      accent: "#c9a35c",
      background: "#141a0e",
      panel: "#232e1a",
      text: "#ece4cd",
      muted: "#9aa982",
    },
    ansi: null,
  },
};

export const EMBLEM_NAMES = ["globe", "tree"] as const;
export type EmblemName = (typeof EMBLEM_NAMES)[number];

export function isEmblemName(word: string): word is EmblemName {
  return (EMBLEM_NAMES as readonly string[]).includes(word);
}

export function isColorSlot(word: string): word is ColorSlot {
  return (COLOR_SLOTS as readonly string[]).includes(word);
}

const HEX_RE = /^#?([0-9a-fA-F]{6})$/;

/** Normalize user hex input to lowercase #rrggbb, or null if invalid. */
export function normalizeHex(raw: string): string | null {
  const match = HEX_RE.exec(raw);
  return match === null ? null : `#${(match[1] ?? "").toLowerCase()}`;
}

export interface ResolvedScheme extends SchemeColors {
  readonly ansi: AnsiOverrides | null;
}

/** A scheme with the user's per-slot HEX overrides layered on top. */
export function resolveScheme(
  name: SchemeName,
  overrides: Partial<Record<ColorSlot, string>>,
): ResolvedScheme {
  const scheme = SCHEMES[name];
  const colors: SchemeColors = { ...scheme.colors };
  for (const slot of COLOR_SLOTS) {
    const hex = overrides[slot];
    if (typeof hex === "string" && normalizeHex(hex) !== null) {
      colors[slot] = normalizeHex(hex) ?? colors[slot];
    }
  }
  return { ...colors, ansi: scheme.ansi };
}
