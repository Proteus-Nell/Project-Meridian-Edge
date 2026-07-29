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

export const SCHEME_NAMES = ["dark", "parchment", "olive", "contrast"] as const;
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
  // Accessibility preset. Pure black ground with every slot chosen to clear
  // WCAG AA (4.5:1) against it, including `muted`, which the other schemes
  // deliberately let recede: dimmed furniture is exactly what fails for a
  // low-vision reader. The ANSI map is set explicitly rather than left to the
  // terminal default, since those defaults are not contrast-checked.
  contrast: {
    colors: {
      accent: "#00d7ff",
      background: "#000000",
      panel: "#1a1a1a",
      text: "#ffffff",
      muted: "#c6c6c6",
    },
    ansi: {
      red: "#ff6b6b",
      green: "#5fff87",
      yellow: "#ffd75f",
      cyan: "#5fffff",
      brightRed: "#ff8787",
      brightGreen: "#87ffaf",
      brightYellow: "#ffff87",
      brightCyan: "#afffff",
    },
  },
};

/** The terminal's notification markers, as colors a user can set.
 *
 * These are the `[✓]` `[!]` `[*]` `[E###]` prefixes the renderer puts in front
 * of every event line, plus the `[alias]` label on an incoming message. They
 * default to the ANSI palette, which is tuned for the base preset - and that is
 * exactly the problem worth fixing: a custom scheme can put a green marker on a
 * green background, and the user has no way to say otherwise.
 *
 * Recoloring these is safe, and deliberately so. The renderer tints ONLY the
 * marker: every event's message text is printed in the scheme's `text` color
 * after a reset, so no setting here can make the words of a warning
 * unreadable. The markers also carry their meaning as literal text (`[!]`,
 * `[SECURITY]`, the E-code), and the DOM status strip mirrors every event with
 * its own CSS colors, independent of anything here. Three channels, and this
 * touches one of them. */
export const EVENT_COLOR_SLOTS = ["success", "warning", "info", "failure", "peer"] as const;
export type EventColorSlot = (typeof EVENT_COLOR_SLOTS)[number];

export function isEventColorSlot(word: string): word is EventColorSlot {
  return (EVENT_COLOR_SLOTS as readonly string[]).includes(word);
}

export type EventColors = Partial<Record<EventColorSlot, string>>;

/** Which ANSI theme entries each event slot drives. The renderer emits SGR 31
 * (red), 32 (green), 33 (yellow), 36 (cyan) and 96 (bright cyan), so setting a
 * slot means overriding the matching xterm theme colors; the bright variants
 * move with their base so bold output does not drift back to the default. */
const EVENT_ANSI_KEYS: Record<EventColorSlot, readonly (keyof AnsiOverrides)[]> = {
  success: ["green", "brightGreen"],
  warning: ["yellow", "brightYellow"],
  info: ["cyan"],
  failure: ["red", "brightRed"],
  peer: ["brightCyan"],
};

/** Concrete fallbacks for the footer status strip, which is DOM rather than
 * terminal cells and so cannot inherit "whatever xterm's default palette says".
 * These are the colors the strip has always used, kept as the defaults so a
 * scheme that never touches its markers looks exactly as it did. */
const EVENT_FALLBACKS: Record<EventColorSlot, string> = {
  success: "#3fb950",
  warning: "#d29922",
  info: "#58a6ff",
  failure: "#f85149",
  peer: "#56d4dd",
};

/** The five marker colors, fully resolved: the user's choice if they set one,
 * else whatever the base preset's ANSI map says (parchment darkens these for a
 * light background), else the strip's built-in default.
 *
 * Always complete, unlike `ansi`, which stays null when nothing overrides the
 * terminal's own palette. The strip needs a real value for every slot; the
 * terminal does not. */
export function resolveEventColors(
  base: AnsiOverrides | null,
  events: EventColors | undefined,
): Record<EventColorSlot, string> {
  const out = {} as Record<EventColorSlot, string>;
  for (const slot of EVENT_COLOR_SLOTS) {
    const primary = EVENT_ANSI_KEYS[slot][0];
    out[slot] =
      events?.[slot] ??
      (primary !== undefined ? base?.[primary] : undefined) ??
      EVENT_FALLBACKS[slot];
  }
  return out;
}

/** A user-defined scheme. `base` is the preset it was derived from: it supplies
 * the ANSI overrides (so a custom light scheme keeps legible terminal output)
 * and is what /settings color reset restores the slots to. */
export interface CustomScheme {
  readonly name: string;
  readonly base: SchemeName;
  readonly colors: SchemeColors;
  /** Per-slot notification marker colors layered over the base's ANSI map.
   * Absent on schemes created before the setting existed, and on any scheme
   * whose markers the user has left alone. */
  readonly events?: EventColors;
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

// ----- fonts ----------------------------------------------------------------
//
// Monospace only, and that is a constraint rather than a taste: xterm lays the
// transcript out in fixed cells, and every aligned listing in the app (/help,
// /contacts, the home dashboard) is built from padded columns. A proportional
// face breaks both.
//
// The stacks are a fixed allowlist for the same reason the colors go through
// normalizeHex: a font-family string is a CSS declaration, and the value comes
// from the unencrypted display prefs, which anything with database access can
// write. Nothing here is ever built from user input. No stack names a webfont
// either: a remote font is a request to somebody else's server on every page
// load, which the CSP forbids and which would be a privacy beacon regardless.

export const FONT_NAMES = ["default", "system", "classic", "wide", "compact"] as const;
export type FontName = (typeof FONT_NAMES)[number];

export function isFontName(word: string): word is FontName {
  return (FONT_NAMES as readonly string[]).includes(word);
}

export const DEFAULT_FONT: FontName = "default";

/** Each entry is a local-font stack ending in the generic `monospace`, so a
 * machine with none of the named faces still gets a fixed-width one. */
export const FONT_STACKS: Record<FontName, string> = {
  default: "'Cascadia Mono', 'Fira Mono', Menlo, Consolas, monospace",
  system: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
  classic: "'Courier New', Courier, monospace",
  wide: "'DejaVu Sans Mono', 'Liberation Mono', 'Lucida Console', Consolas, monospace",
  compact: "Iosevka, 'Roboto Mono', 'Fira Mono', 'Droid Sans Mono', monospace",
};

/** Short human descriptions for `/settings font list`. */
export const FONT_BLURBS: Record<FontName, string> = {
  default: "the shipped stack: Cascadia Mono, then Fira Mono, Menlo, Consolas",
  system: "your platform's own UI monospace face",
  classic: "Courier New, the widest-available typewriter face",
  wide: "DejaVu Sans Mono and friends: roomier, easier to read at small sizes",
  compact: "Iosevka and friends: narrow, fits more columns on a phone",
};

export const MIN_FONT_SIZE = 10;
export const MAX_FONT_SIZE = 28;
export const DEFAULT_FONT_SIZE = 15;

/** Clamp a stored or typed size into the supported range. */
export function clampFontSize(size: number): number {
  if (!Number.isFinite(size)) {
    return DEFAULT_FONT_SIZE;
  }
  return Math.min(MAX_FONT_SIZE, Math.max(MIN_FONT_SIZE, Math.round(size)));
}

// ----- accessibility ---------------------------------------------------------

/** Opt-in accessibility switches, stored unencrypted beside the other display
 * preferences so they apply to the lock screen too, which is exactly where
 * someone who needs them meets the app first. */
export interface AccessibilityPrefs {
  /** xterm's screenReaderMode: maintains an ARIA live region mirroring the
   * terminal so a screen reader can follow output. Off by default because it
   * costs render performance, not because it exposes anything: the same text is
   * already in the DOM as terminal cells. */
  readonly screenReader: boolean;
  /** Force the reduced-motion treatment on, for someone whose OS setting does
   * not reflect what they need right now. The `prefers-reduced-motion` media
   * query still applies independently. */
  readonly reduceMotion: boolean;
}

export const DEFAULT_ACCESSIBILITY: AccessibilityPrefs = {
  screenReader: false,
  reduceMotion: false,
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

/** Normalize user hex input to lowercase #rrggbb, or null if invalid. The only
 * way a color value enters the app; everything downstream assumes it ran. */
export function normalizeHex(raw: string): string | null {
  const match = HEX_RE.exec(raw);
  return match === null ? null : `#${(match[1] ?? "").toLowerCase()}`;
}

export interface ResolvedScheme extends SchemeColors {
  readonly ansi: AnsiOverrides | null;
  /** The five notification-marker colors, every slot filled. Drives both the
   * terminal markers (through `ansi`) and the footer status strip (through the
   * --event-* CSS variables), so one setting moves both. */
  readonly events: Record<EventColorSlot, string>;
}

/** The five slots of whichever scheme `name` refers to, ready to paint. Total:
 * an unknown name falls back to the default preset rather than throwing, so a
 * prefs record naming a scheme that has since been deleted still renders. */
export function resolveScheme(name: string, customs: readonly CustomScheme[]): ResolvedScheme {
  const custom = isSchemeName(name) ? null : findCustomScheme(customs, name);
  if (custom === null) {
    // Either a preset, or a name that no longer resolves (deleted, or dropped
    // by validation), which falls back to the default so the page still paints.
    const preset = SCHEMES[isSchemeName(name) ? name : DEFAULT_SCHEME];
    return {
      ...preset.colors,
      ansi: preset.ansi,
      events: resolveEventColors(preset.ansi, undefined),
    };
  }
  // ANSI comes from the base preset: a custom scheme sets the five slots, and
  // inheriting the base's terminal colors is what keeps a light fork readable.
  // Any marker colors the user set are layered on top of that.
  const baseAnsi = SCHEMES[custom.base].ansi;
  return {
    ...custom.colors,
    ansi: mergeEventColors(baseAnsi, custom.events),
    events: resolveEventColors(baseAnsi, custom.events),
  };
}

/** Fold a scheme's event-marker choices into an ANSI override map. Returns the
 * base map untouched when nothing was set, so a scheme that never used the
 * feature resolves exactly as it did before it existed. */
export function mergeEventColors(
  base: AnsiOverrides | null,
  events: EventColors | undefined,
): AnsiOverrides | null {
  if (events === undefined || Object.keys(events).length === 0) {
    return base;
  }
  const merged: Record<string, string> = { ...(base ?? {}) };
  for (const slot of EVENT_COLOR_SLOTS) {
    const hex = events[slot];
    if (hex === undefined) {
      continue;
    }
    for (const key of EVENT_ANSI_KEYS[slot]) {
      merged[key] = hex;
    }
  }
  return merged;
}

/** Validate a stored event-color map, dropping any slot that is not a literal
 * #rrggbb. Same trust boundary as the five main slots. */
export function sanitizeEventColors(raw: unknown): EventColors {
  if (typeof raw !== "object" || raw === null) {
    return {};
  }
  const source = raw as Partial<Record<EventColorSlot, unknown>>;
  const out: EventColors = {};
  for (const slot of EVENT_COLOR_SLOTS) {
    const value = source[slot];
    const hex = typeof value === "string" ? normalizeHex(value) : null;
    if (hex !== null) {
      out[slot] = hex;
    }
  }
  return out;
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
    const events = sanitizeEventColors((entry as { events?: unknown }).events);
    out.push({
      name,
      base: typeof base === "string" && isSchemeName(base) ? base : DEFAULT_SCHEME,
      colors: validColors,
      // Omitted rather than stored empty, so a scheme that never touched the
      // markers round-trips identically (exactOptionalPropertyTypes is on).
      ...(Object.keys(events).length > 0 ? { events } : {}),
    });
  }
  return out;
}
