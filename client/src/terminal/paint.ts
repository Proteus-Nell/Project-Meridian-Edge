// Page-level style application, split out of chrome.ts so it can run before
// the terminals exist.
//
// The scheme lives in IndexedDB, which is asynchronous, so the page always
// paints the CSS defaults first and only learns the user's real scheme a few
// milliseconds later. The synchronous web-storage API would close the gap
// entirely, but scripts/audit.py bans it repo-wide as a token-persistence
// guard, and evading a security gate for a cosmetic win is not a trade
// worth making. Instead:
//
//   1. main.ts starts the prefs read as its very first statement, so it runs
//      in parallel with xterm construction/mount (previously the read happened
//      after both terminals were mounted, which is where the long, obvious
//      flash came from), and
//   2. #app stays visibility:hidden until markThemeReady() runs, so no content
//      is ever painted in the wrong scheme - only the page backdrop, briefly,
//      and only for someone whose chosen scheme differs from the default.

import { clampFontSize, clampLetterSpacing, clampLineHeight, resolveScheme } from "./theme";
import type { AccessibilityPrefs, EmblemName, ResolvedScheme, TextStyle } from "./theme";
import { EMBLEM_NAMES, EVENT_COLOR_SLOTS, FONT_STACKS } from "./theme";
import { KeyStore } from "../crypto/store";
import type { ThemePrefs } from "../crypto/store";

/** Push a resolved scheme's five slots into the CSS custom properties every
 * other rule derives from. Chrome applies the terminal (xterm) themes
 * separately, since it owns the terminal instances. */
export function applySchemeVars(scheme: ResolvedScheme): void {
  const root = document.documentElement.style;
  root.setProperty("--accent", scheme.accent);
  root.setProperty("--bg", scheme.background);
  root.setProperty("--panel", scheme.panel);
  root.setProperty("--text", scheme.text);
  root.setProperty("--muted", scheme.muted);
  // The notification-marker colors, so the footer status strip is tinted from
  // the same values as the transcript's [✓] [!] [*] [E###] markers. One
  // /settings color event setting, both surfaces. Every value has already been
  // through normalizeHex, so nothing but #rrggbb reaches a CSS declaration.
  for (const slot of EVENT_COLOR_SLOTS) {
    root.setProperty(`--event-${slot}`, scheme.events[slot]);
  }
}

/** Push the text metrics into the CSS custom properties the DOM chrome derives
 * from. The terminals are themed separately by Chrome, which owns the xterm
 * instances; both read the same prefs, so the transcript and the furniture
 * around it never disagree about how text is set.
 *
 * The spacing values reach the DOM as well as the terminals on purpose: the
 * status strip and the undelivered panel are read by the same eyes, and a
 * readability setting that stopped at the terminal edge would be half a
 * setting. */
export function applyTextVars(style: TextStyle): void {
  const root = document.documentElement.style;
  // From a fixed allowlist keyed by name, so no stored string is ever
  // interpolated into a CSS declaration (theme.ts::FONT_STACKS). The numbers
  // are clamped rather than trusted, for the same reason.
  root.setProperty("--font-mono", FONT_STACKS[style.font]);
  root.setProperty("--font-size", `${clampFontSize(style.fontSize)}px`);
  root.setProperty("--letter-spacing", `${clampLetterSpacing(style.letterSpacing)}px`);
  root.setProperty("--line-height", `${clampLineHeight(style.lineHeight)}`);
}

/** Reflect the accessibility switches as body classes. `a11y-reduce-motion`
 * mirrors what the prefers-reduced-motion media query already does, so a user
 * whose OS setting does not match what they need can force it here. */
export function applyAccessibilityClasses(prefs: AccessibilityPrefs): void {
  document.body.classList.toggle("a11y-reduce-motion", prefs.reduceMotion);
}

/** Toggle the atmosphere-layer body classes (/settings theme). */
export function applyThemeClasses(theme: ThemePrefs): void {
  const body = document.body;
  body.classList.toggle("th-emblem", theme.emblem);
  body.classList.toggle("th-scanlines", theme.scanlines);
  body.classList.toggle("th-vignette", theme.vignette);
  body.classList.toggle("th-dock", theme.dock);
}

/** Select the medallion glyph body class (/settings emblem). */
export function applyEmblemClass(name: EmblemName): void {
  for (const emblem of EMBLEM_NAMES) {
    document.body.classList.toggle(`em-${emblem}`, emblem === name);
  }
}

/** Reveal the app. Until this runs, style.css keeps #app hidden so nothing
 * renders in the default scheme before the saved one is known. Always called,
 * even when the prefs read fails, so a storage error can never leave a blank
 * page. */
export function markThemeReady(): void {
  document.body.classList.add("theme-ready");
}

/** Read the persisted display preferences and apply everything that affects
 * the page paint, then reveal the app. Deliberately does NOT need the
 * terminals, so main.ts can start it before constructing them; the executor's
 * own init() re-applies the same prefs afterwards (idempotent) and additionally
 * themes the terminals and the passphrase mask. */
export async function preloadDisplayStyle(store: KeyStore = new KeyStore()): Promise<void> {
  try {
    const prefs = await store.getDisplayPrefs();
    applySchemeVars(resolveScheme(prefs.scheme, prefs.customSchemes));
    applyThemeClasses(prefs.theme);
    applyEmblemClass(prefs.emblemGlyph);
    applyTextVars(prefs);
    applyAccessibilityClasses(prefs.accessibility);
  } catch {
    // No store yet, or it could not be read: the CSS defaults stand.
  } finally {
    markThemeReady();
  }
}
