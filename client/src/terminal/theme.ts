// Color schemes and emblem catalog. Pure data + helpers, no
// DOM: chrome.ts turns a resolved scheme into CSS custom properties and xterm
// theme objects; the executor persists the user's choice in the unencrypted
// display prefs. Each scheme is exactly five slots (accent / background /
// panel / text / muted) - matching the design references - plus an optional
// ANSI override map so terminal output stays legible on light backgrounds.
//
// The three presets are IMMUTABLE. Editing a color never writes to one: it
// forks a custom scheme (see executor/settings.ts::doSettingsColor), so
// /settings scheme dark always returns the palette shipped here, whatever the
// user has done to their own schemes.
//
// Custom schemes come out of the unencrypted display prefs, which means they
// are untrusted input: anything with database access (including an XSS) can
// write that record, and every value in it ends up in a CSS custom property or
// an xterm theme. sanitizeCustomSchemes is the single gate - names are matched
// against a strict pattern and colors against normalizeHex, so the only string
// that can ever reach the DOM is a literal #rrggbb. They are also stored as an
// ARRAY rather than a name-keyed object: a keyed record read back from storage
// would let a hand-written "__proto__" entry poison Object.prototype.

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

export const DEFAULT_SCHEME: SchemeName = "dark";

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

/** A user-defined scheme. `base` is the preset it was derived from: it supplies
 * the ANSI overrides (so a custom light scheme keeps legible terminal output)
 * and is what /settings color reset restores the slots to. */
export interface CustomScheme {
  readonly name: string;
  readonly base: SchemeName;
  readonly colors: SchemeColors;
}

/** Enough to organise by, few enough that a tampered or runaway record cannot
 * bloat the prefs blob the page reads before it paints. */
export const MAX_CUSTOM_SCHEMES = 16;

/** Suffix appended to a preset's name when /settings color forks it. */
export const FORK_SUFFIX = "-custom";

/** Words the `/settings scheme` grammar owns; a custom scheme taking one would
 * become unreachable by name. */
export const RESERVED_SCHEME_WORDS = ["new", "delete", "list", "reset"] as const;

/** Lowercase, starts with a letter, letters/digits/hyphens, 1-24 characters.
 * Tight on purpose: it excludes whitespace, control and ANSI escape sequences,
 * path and shell metacharacters, and the `_`-bearing names (`__proto__`) that
 * make object keys dangerous. */
const CUSTOM_NAME_RE = /^[a-z][a-z0-9-]{0,23}$/;

/** Names that are syntactically fine but would shadow something. Kept explicit
 * rather than relying on the pattern: `constructor` and `prototype` are plain
 * lowercase words that CUSTOM_NAME_RE happily accepts. */
const FORBIDDEN_NAMES: readonly string[] = ["constructor", "prototype", "__proto__"];

/** Whether `name` may be used for a user-defined scheme: well-formed, not a
 * preset, not a grammar keyword, not a prototype-shaped name. */
export function isValidCustomSchemeName(name: string): boolean {
  return (
    CUSTOM_NAME_RE.test(name) &&
    !isSchemeName(name) &&
    !(RESERVED_SCHEME_WORDS as readonly string[]).includes(name) &&
    !FORBIDDEN_NAMES.includes(name)
  );
}

export function findCustomScheme(
  customs: readonly CustomScheme[],
  name: string,
): CustomScheme | null {
  return customs.find((scheme) => scheme.name === name) ?? null;
}

/** Whether `name` names any scheme the user can switch to. */
export function schemeExists(name: string, customs: readonly CustomScheme[]): boolean {
  return isSchemeName(name) || findCustomScheme(customs, name) !== null;
}

export const EMBLEM_NAMES = ["globe", "tree"] as const;
export type EmblemName = (typeof EMBLEM_NAMES)[number];

export function isEmblemName(word: string): word is EmblemName {
  return (EMBLEM_NAMES as readonly string[]).includes(word);
}

export function isColorSlot(word: string): word is ColorSlot {
  return (COLOR_SLOTS as readonly string[]).includes(word);
}

const HEX_RE = /^#?([0-9a-fA-F]{6})$/;

/** Normalize user hex input to lowercase #rrggbb, or null if invalid. The only
 * way a color value enters the app; everything downstream assumes it ran. */
export function normalizeHex(raw: string): string | null {
  const match = HEX_RE.exec(raw);
  return match === null ? null : `#${(match[1] ?? "").toLowerCase()}`;
}

export interface ResolvedScheme extends SchemeColors {
  readonly ansi: AnsiOverrides | null;
}

/** The five slots of whichever scheme `name` refers to, ready to paint. Total:
 * an unknown name falls back to the default preset rather than throwing, so a
 * prefs record naming a scheme that has since been deleted still renders. */
export function resolveScheme(name: string, customs: readonly CustomScheme[]): ResolvedScheme {
  if (isSchemeName(name)) {
    const preset = SCHEMES[name];
    return { ...preset.colors, ansi: preset.ansi };
  }
  const custom = findCustomScheme(customs, name);
  if (custom === null) {
    const fallback = SCHEMES[DEFAULT_SCHEME];
    return { ...fallback.colors, ansi: fallback.ansi };
  }
  // ANSI comes from the base preset: a custom scheme sets the five slots, and
  // inheriting the base's terminal colors is what keeps a light fork readable.
  return { ...custom.colors, ansi: SCHEMES[custom.base].ansi };
}

/** The slot values a new custom scheme starts from: the resolved colors of
 * whatever is currently applied. */
export function schemeColorsOf(name: string, customs: readonly CustomScheme[]): SchemeColors {
  const resolved = resolveScheme(name, customs);
  return {
    accent: resolved.accent,
    background: resolved.background,
    panel: resolved.panel,
    text: resolved.text,
    muted: resolved.muted,
  };
}

/** Which preset a scheme derives from: itself if it is one, its recorded base
 * if it is custom, the default otherwise. */
export function baseSchemeOf(name: string, customs: readonly CustomScheme[]): SchemeName {
  if (isSchemeName(name)) {
    return name;
  }
  return findCustomScheme(customs, name)?.base ?? DEFAULT_SCHEME;
}

function sanitizeColors(raw: unknown): SchemeColors | null {
  if (typeof raw !== "object" || raw === null) {
    return null;
  }
  const source = raw as Partial<Record<ColorSlot, unknown>>;
  const colors: Partial<SchemeColors> = {};
  for (const slot of COLOR_SLOTS) {
    const value = source[slot];
    const hex = typeof value === "string" ? normalizeHex(value) : null;
    if (hex === null) {
      return null; // a scheme missing a slot has no sane rendering; drop it
    }
    colors[slot] = hex;
  }
  return colors as SchemeColors;
}

/** Validate a stored custom-scheme list. Every entry must pass on its own
 * merits; a bad one is dropped rather than degrading the whole list, and the
 * result is capped. This is the trust boundary for the display prefs: nothing
 * else validates what comes out of that record. */
export function sanitizeCustomSchemes(raw: unknown): CustomScheme[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: CustomScheme[] = [];
  const seen = new Set<string>();
  for (const entry of raw as readonly unknown[]) {
    if (out.length >= MAX_CUSTOM_SCHEMES) {
      break;
    }
    if (typeof entry !== "object" || entry === null) {
      continue;
    }
    const { name, base, colors } = entry as {
      name?: unknown;
      base?: unknown;
      colors?: unknown;
    };
    if (typeof name !== "string" || !isValidCustomSchemeName(name) || seen.has(name)) {
      continue;
    }
    const validColors = sanitizeColors(colors);
    if (validColors === null) {
      continue;
    }
    seen.add(name);
    out.push({
      name,
      base: typeof base === "string" && isSchemeName(base) ? base : DEFAULT_SCHEME,
      colors: validColors,
    });
  }
  return out;
}
