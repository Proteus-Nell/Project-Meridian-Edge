// /settings subcommands. Two storage classes, deliberately distinct: the
// rotation prompt and trust mode live ENCRYPTED, because they describe security
// posture. Display preferences (mask, theme, scheme, emblem, colors) live
// unencrypted so they can apply before anyone unlocks the store, for example to
// the very first passphrase prompt.

import type { DisplayPrefs, ThemePrefs } from "../../crypto/store";
import {
  FORK_SUFFIX,
  MAX_CUSTOM_SCHEMES,
  SCHEME_NAMES,
  baseSchemeOf,
  findCustomScheme,
  isSchemeName,
  isValidCustomSchemeName,
  resolveScheme,
  schemeColorsOf,
  schemeExists,
} from "../theme";
import type { ColorSlot, CustomScheme, EmblemName } from "../theme";
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
    next.enabled ? `weekly rotation prompt on (${next.day})` : "weekly rotation prompt off",
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
      ? "passphrase entry hidden - no characters echoed (sudo-style)"
      : "passphrase entry masked with asterisks",
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
      "trust-on-first-use ON - new contacts are auto-verified, and a key change is auto-accepted with a warning (no /verify, /verified, or /ack needed). Convenient, but it trusts the server not to swap keys; use /settings trust manual for out-of-band verification.",
    );
  } else {
    x.renderer.event(
      "success",
      "manual verification ON - compare safety numbers with /verify + /verified, and a key change blocks until /ack (strongest MITM protection).",
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
      ? `all theme layers turned ${enabled ? "on" : "off"}`
      : `theme layer '${element}' turned ${enabled ? "on" : "off"}`,
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
      ? `color scheme set to the '${scheme}' preset`
      : `color scheme set to '${scheme}' (custom)`,
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
    `created '${name}' from ${prefs.scheme} and switched to it - /settings color <slot> <#rrggbb> to edit it`,
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
      ? `deleted '${name}' - back to the '${target.base}' preset`
      : `deleted '${name}'`,
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

/** `/settings emblem <pq|globe|tree>`: choose the medallion glyph. */
export async function doSettingsEmblem(x: ExecutorInternals, emblem: EmblemName): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, emblemGlyph: emblem });
  x.chrome.applyEmblem(emblem);
  x.renderer.event("success", `emblem set to '${emblem}'`);
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
  const prefs = await x.store.getDisplayPrefs();
  const active = findCustomScheme(prefs.customSchemes, prefs.scheme);
  if (active !== null) {
    const edited: CustomScheme = { ...active, colors: { ...active.colors, [slot]: hex } };
    await applyPrefs(x, {
      ...prefs,
      customSchemes: prefs.customSchemes.map((s) => (s.name === active.name ? edited : s)),
    });
    x.renderer.event("success", `${slot} set to ${hex} on '${active.name}'`);
    return;
  }

  const base = baseSchemeOf(prefs.scheme, prefs.customSchemes);
  const name = `${base}${FORK_SUFFIX}`;
  const existing = findCustomScheme(prefs.customSchemes, name);
  if (existing === null && prefs.customSchemes.length >= MAX_CUSTOM_SCHEMES) {
    x.renderer.error("E108", MAX_CUSTOM_SCHEMES);
    return;
  }
  const colors = { ...(existing?.colors ?? schemeColorsOf(base, [])), [slot]: hex };
  const forked: CustomScheme = { name, base, colors };
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
    `${slot} set to ${hex} on '${name}' - the '${base}' preset is unchanged, /settings scheme ${base} goes back to it`,
  );
}

/** `/settings color reset`: put the active custom scheme's five slots back to
 * its base preset's. A preset is already pristine, so there is nothing to do. */
export async function doSettingsColorReset(x: ExecutorInternals): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const active = findCustomScheme(prefs.customSchemes, prefs.scheme);
  if (active === null) {
    x.renderer.event(
      "info",
      `'${prefs.scheme}' is a preset and carries no custom colors - nothing to reset`,
    );
    return;
  }
  const restored: CustomScheme = { ...active, colors: schemeColorsOf(active.base, []) };
  await applyPrefs(x, {
    ...prefs,
    customSchemes: prefs.customSchemes.map((s) => (s.name === active.name ? restored : s)),
  });
  x.renderer.event(
    "success",
    `'${active.name}' reset to the '${active.base}' preset colors (/settings scheme ${active.base} switches to the preset itself)`,
  );
}
