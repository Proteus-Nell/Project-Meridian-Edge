// /settings subcommands. Two storage classes, deliberately distinct: the
// rotation prompt and trust mode live ENCRYPTED, because they describe security
// posture. Display preferences (mask, theme, scheme, emblem, colors) live
// unencrypted so they can apply before anyone unlocks the store, for example to
// the very first passphrase prompt.

import type { DisplayPrefs, ThemePrefs } from "../../crypto/store";
import {
  FONT_BLURBS,
  FONT_NAMES,
  FORK_SUFFIX,
  MAX_CUSTOM_SCHEMES,
  MAX_FONT_SIZE,
  MIN_FONT_SIZE,
  SCHEME_NAMES,
  baseSchemeOf,
  clampFontSize,
  findCustomScheme,
  isSchemeName,
  isValidCustomSchemeName,
  resolveScheme,
  schemeColorsOf,
  schemeExists,
} from "../theme";
import type {
  AccessibilityPrefs,
  ColorSlot,
  CustomScheme,
  EmblemName,
  EventColorSlot,
  FontName,
} from "../theme";
import type { A11yFeature } from "../parser";
import type { ThemeElement, Weekday } from "../parser";
import type { ExecutorInternals } from "./context";
import { DEFAULT_ROTATION } from "./records";
import type { RotationSettings } from "./records";

export async function doSettingsRotation(
  x: ExecutorInternals,
  setting: { kind: "on" } | { kind: "off" } | { kind: "day"; day: Weekday },
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E404");
    return;
  }
  const current =
    (await x.store.getJson<RotationSettings>("settings/rotation")) ?? DEFAULT_ROTATION;
  let next: RotationSettings;
  switch (setting.kind) {
    case "on":
      next = { ...current, enabled: true };
      break;
    case "off":
      next = { ...current, enabled: false };
      break;
    case "day":
      next = { ...current, enabled: true, day: setting.day };
      break;
  }
  await x.store.putJson("settings/rotation", next);
  x.renderer.event(
    "success",
    next.enabled ? `Weekly rotation prompt is on, for ${next.day}.` : "Weekly rotation prompt is off.",
  );
}

export async function doSettingsMask(
  x: ExecutorInternals,
  mask: "asterisk" | "hidden",
): Promise<void> {
  // Read-modify-write so the other display preferences are preserved.
  x.shell.setSecretMask(mask);
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, secretMask: mask });
  x.renderer.event(
    "success",
    mask === "hidden"
      ? "Passphrase entry hidden. No characters are echoed, sudo-style."
      : "Passphrase entry is masked with asterisks.",
  );
}

/** `/settings trust <auto|manual>`: switch trust-on-first-use (a). */
export async function doSettingsTrust(
  x: ExecutorInternals,
  mode: "auto" | "manual",
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E405");
    return;
  }
  x.autoTrust = mode === "auto";
  await x.store.putJson("settings/trust", { auto: x.autoTrust });
  if (x.autoTrust) {
    x.renderer.event(
      "success",
      "Trust-on-first-use is ON. New contacts are auto-verified, and a key change is auto-accepted with a warning, so no /verify, /verified or /ack is needed. It is convenient, but it trusts the server not to swap keys. Use /settings trust manual for out-of-band verification.",
    );
  } else {
    x.renderer.event(
      "success",
      "Manual verification is ON. Compare safety numbers with /verify and /verified, and a key change blocks until /ack. This is the strongest protection against a machine-in-the-middle.",
    );
  }
}

/** `/settings theme <element|all> <on|off>`: toggle an atmosphere layer.
 * Purely cosmetic; works while locked for the same reason it lives
 * unencrypted. */
export async function doSettingsTheme(
  x: ExecutorInternals,
  element: ThemeElement | "all",
  enabled: boolean,
): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const theme: ThemePrefs =
    element === "all"
      ? { emblem: enabled, scanlines: enabled, vignette: enabled, dock: enabled }
      : { ...prefs.theme, [element]: enabled };
  await x.store.setDisplayPrefs({ ...prefs, theme });
  x.chrome.applyTheme(theme);
  x.renderer.event(
    "success",
    element === "all"
      ? `All theme layers turned ${enabled ? "on" : "off"}.`
      : `Theme layer '${element}' turned ${enabled ? "on" : "off"}.`,
  );
}

/** Persist a prefs change and repaint from it in one step, so what is stored
 * and what is on screen can never disagree. */
async function applyPrefs(x: ExecutorInternals, prefs: DisplayPrefs): Promise<void> {
  await x.store.setDisplayPrefs(prefs);
  x.chrome.applyScheme(resolveScheme(prefs.scheme, prefs.customSchemes));
}

/** `/settings scheme <name>`: switch to a preset or one of the user's own. */
export async function doSettingsScheme(x: ExecutorInternals, scheme: string): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  if (!schemeExists(scheme, prefs.customSchemes)) {
    x.renderer.error("E106", scheme);
    return;
  }
  await applyPrefs(x, { ...prefs, scheme });
  x.renderer.event(
    "success",
    isSchemeName(scheme)
      ? `Color scheme set to the '${scheme}' preset.`
      : `Color scheme set to your '${scheme}' scheme.`,
  );
}

/** `/settings scheme new <name>`: copy whatever is on screen into a scheme of
 * your own and switch to it. The copy is what makes presets safe to edit - the
 * preset itself is never written to. */
export async function doSettingsSchemeNew(x: ExecutorInternals, name: string): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  if (!isValidCustomSchemeName(name)) {
    x.renderer.error("E107", name);
    return;
  }
  if (schemeExists(name, prefs.customSchemes)) {
    x.renderer.error("E109", name);
    return;
  }
  if (prefs.customSchemes.length >= MAX_CUSTOM_SCHEMES) {
    x.renderer.error("E108", MAX_CUSTOM_SCHEMES);
    return;
  }
  const base = baseSchemeOf(prefs.scheme, prefs.customSchemes);
  const created: CustomScheme = {
    name,
    base,
    colors: schemeColorsOf(prefs.scheme, prefs.customSchemes),
  };
  await applyPrefs(x, {
    ...prefs,
    scheme: name,
    customSchemes: [...prefs.customSchemes, created],
  });
  x.renderer.event(
    "success",
    `Created '${name}' from ${prefs.scheme} and switched to it. Use /settings color <slot> <#rrggbb> to edit it.`,
  );
}

/** `/settings scheme delete <name>`: drop one of your own schemes. Presets are
 * not deletable; the whole point is that they are always there to go back to. */
export async function doSettingsSchemeDelete(x: ExecutorInternals, name: string): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  if (isSchemeName(name) || !isValidCustomSchemeName(name)) {
    x.renderer.error("E107", name);
    return;
  }
  const target = findCustomScheme(prefs.customSchemes, name);
  if (target === null) {
    x.renderer.error("E106", name);
    return;
  }
  const customSchemes = prefs.customSchemes.filter((scheme) => scheme.name !== name);
  // Deleting what is on screen falls back to the preset it came from, rather
  // than leaving the page pointing at something that no longer exists.
  const scheme = prefs.scheme === name ? target.base : prefs.scheme;
  await applyPrefs(x, { ...prefs, scheme, customSchemes });
  x.renderer.event(
    "success",
    prefs.scheme === name
      ? `Deleted '${name}'. Back to the '${target.base}' preset.`
      : `Deleted '${name}'.`,
  );
}

/** `/settings scheme list`: every scheme that can be switched to, marking the
 * active one and where each custom scheme came from. */
export async function doSettingsSchemeList(x: ExecutorInternals): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  x.renderer.event("info", "color schemes:");
  const names = [...SCHEME_NAMES, ...prefs.customSchemes.map((scheme) => scheme.name)];
  const width = Math.max(...names.map((name) => name.length));
  for (const name of SCHEME_NAMES) {
    const mark = name === prefs.scheme ? "*" : " ";
    x.renderer.plain(`  ${mark} ${name.padEnd(width)}  preset (never modified)`);
  }
  for (const scheme of prefs.customSchemes) {
    const mark = scheme.name === prefs.scheme ? "*" : " ";
    x.renderer.plain(`  ${mark} ${scheme.name.padEnd(width)}  custom, based on ${scheme.base}`);
  }
  x.renderer.plain(
    `  (${prefs.customSchemes.length}/${MAX_CUSTOM_SCHEMES} custom · /settings scheme new <name> to add one)`,
  );
}

/** `/settings font <name>`: switch the monospace stack. Every option is
 * monospace by necessity, not preference: the transcript is laid out in fixed
 * cells and every aligned listing in the app is built from padded columns. */
export async function doSettingsFont(x: ExecutorInternals, font: FontName): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, font });
  x.chrome.applyFont(font, prefs.fontSize);
  x.renderer.event("success", `Font set to '${font}': ${FONT_BLURBS[font]}.`);
}

/** `/settings font list`: the available stacks, marking the active one. */
export async function doSettingsFontList(x: ExecutorInternals): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  x.renderer.event("info", "fonts (all monospace, all local, none fetched from anywhere):");
  const width = Math.max(...FONT_NAMES.map((name) => name.length));
  for (const name of FONT_NAMES) {
    const mark = name === prefs.font ? "*" : " ";
    x.renderer.plain(`  ${mark} ${name.padEnd(width)}  ${FONT_BLURBS[name]}`);
  }
  x.renderer.plain(`  (size ${prefs.fontSize}px · /settings fontsize <${MIN_FONT_SIZE}-${MAX_FONT_SIZE}>)`);
}

/** `/settings fontsize <n>`: scale both terminals. */
export async function doSettingsFontSize(x: ExecutorInternals, size: number): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const fontSize = clampFontSize(size);
  await x.store.setDisplayPrefs({ ...prefs, fontSize });
  x.chrome.applyFont(prefs.font, fontSize);
  x.renderer.event(
    "success",
    `Font size set to ${fontSize}px. The terminal was re-fitted to the new cell size.`,
  );
}

/** `/settings a11y <screenreader|motion> <on|off>`. Both live unencrypted with
 * the other display preferences, so they are already in effect at the lock
 * screen, which is where someone who needs them meets the app first. */
export async function doSettingsA11y(
  x: ExecutorInternals,
  feature: A11yFeature,
  enabled: boolean,
): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const accessibility: AccessibilityPrefs =
    feature === "screenreader"
      ? { ...prefs.accessibility, screenReader: enabled }
      : { ...prefs.accessibility, reduceMotion: enabled };
  await x.store.setDisplayPrefs({ ...prefs, accessibility });
  x.chrome.applyAccessibility(accessibility);
  if (feature === "screenreader") {
    x.renderer.event(
      "success",
      enabled
        ? "Screen reader mode on. The terminal now mirrors its output into an ARIA live region, which costs some rendering speed."
        : "Screen reader mode off.",
    );
    return;
  }
  x.renderer.event(
    "success",
    enabled
      ? "Reduced motion on. The medallion no longer spins or pulses."
      : "Reduced motion off. Your system setting still applies on its own.",
  );
}

/** `/settings emblem <pq|globe|tree>`: choose the medallion glyph. */
export async function doSettingsEmblem(x: ExecutorInternals, emblem: EmblemName): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, emblemGlyph: emblem });
  x.chrome.applyEmblem(emblem);
  x.renderer.event("success", `Emblem set to '${emblem}'.`);
}

/** `/settings color <slot> <#rrggbb>`: the terminal-native color picker.
 *
 * Editing a preset does not modify it - presets are immutable, which is what
 * lets `/settings scheme dark` always mean the palette that shipped. The first
 * edit on a preset forks it into `<preset>-custom` and switches there, so the
 * change lands somewhere the user owns and the original stays intact. A second
 * edit finds that fork already active and just writes to it. */
export async function doSettingsColor(
  x: ExecutorInternals,
  slot: ColorSlot,
  hex: string,
): Promise<void> {
  await editActiveScheme(x, `${slot} set to ${hex}`, (scheme) => ({
    ...scheme,
    colors: { ...scheme.colors, [slot]: hex },
  }));
}

/** `/settings color event <slot> <#rrggbb>`: recolor one notification marker -
 * the `[✓]` `[!]` `[*]` `[E###]` prefixes and the `[alias]` on an incoming
 * message. They default to the ANSI palette, which a custom scheme can easily
 * collide with (green markers on a green background); this is the way out.
 *
 * Only the marker is tinted. Every event's message text is printed in the
 * scheme's `text` color, so nothing set here can make the words of a warning
 * unreadable - see theme.ts::EVENT_COLOR_SLOTS for why that makes it safe to
 * expose. Forks a preset exactly as the slot colors do. */
export async function doSettingsColorEvent(
  x: ExecutorInternals,
  slot: EventColorSlot,
  hex: string,
): Promise<void> {
  await editActiveScheme(x, `${slot} marker set to ${hex}`, (scheme) => ({
    ...scheme,
    events: { ...scheme.events, [slot]: hex },
  }));
}

/** Apply `edit` to the scheme currently on screen, and report `summary`.
 *
 * When a preset is active there is nothing to edit: presets are immutable, so
 * this forks `<preset>-custom`, switches there, and applies the change to the
 * fork instead. A second edit finds that fork already active and just writes to
 * it. Shared by both colour commands so they fork identically. */
async function editActiveScheme(
  x: ExecutorInternals,
  summary: string,
  edit: (scheme: CustomScheme) => CustomScheme,
): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const active = findCustomScheme(prefs.customSchemes, prefs.scheme);
  if (active !== null) {
    const edited = edit(active);
    await applyPrefs(x, {
      ...prefs,
      customSchemes: prefs.customSchemes.map((s) => (s.name === active.name ? edited : s)),
    });
    x.renderer.event("success", `${summary} on '${active.name}'.`);
    return;
  }

  const base = baseSchemeOf(prefs.scheme, prefs.customSchemes);
  const name = `${base}${FORK_SUFFIX}`;
  const existing = findCustomScheme(prefs.customSchemes, name);
  if (existing === null && prefs.customSchemes.length >= MAX_CUSTOM_SCHEMES) {
    x.renderer.error("E108", MAX_CUSTOM_SCHEMES);
    return;
  }
  const forked = edit(existing ?? { name, base, colors: schemeColorsOf(base, []) });
  await applyPrefs(x, {
    ...prefs,
    scheme: name,
    customSchemes:
      existing === null
        ? [...prefs.customSchemes, forked]
        : prefs.customSchemes.map((s) => (s.name === name ? forked : s)),
  });
  x.renderer.event(
    "success",
    `${summary} on '${name}'. The '${base}' preset is unchanged, and /settings scheme ${base} goes back to it.`,
  );
}

/** `/settings color reset`: put the active custom scheme's five slots AND its
 * notification markers back to its base preset's. A preset is already pristine,
 * so there is nothing to do. */
export async function doSettingsColorReset(x: ExecutorInternals): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const active = findCustomScheme(prefs.customSchemes, prefs.scheme);
  if (active === null) {
    x.renderer.event(
      "info",
      `'${prefs.scheme}' is a preset and carries no custom colors, so there is nothing to reset.`,
    );
    return;
  }
  // `events` is dropped entirely rather than emptied: absent is how a scheme
  // that never touched the markers is stored.
  const restored: CustomScheme = { name: active.name, base: active.base, colors: schemeColorsOf(active.base, []) };
  await applyPrefs(x, {
    ...prefs,
    customSchemes: prefs.customSchemes.map((s) => (s.name === active.name ? restored : s)),
  });
  x.renderer.event(
    "success",
    `'${active.name}' reset to the '${active.base}' preset colors. Use /settings scheme ${active.base} to switch to the preset itself.`,
  );
}
