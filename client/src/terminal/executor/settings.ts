// /settings subcommands. Two storage classes, deliberately distinct: the
// rotation prompt and trust mode live ENCRYPTED (they describe security
// posture), while display preferences (mask, theme, scheme, emblem, colors)
// are stored unencrypted so they can apply before the store is unlocked,
// e.g. to the very first passphrase prompt.

import type { ThemePrefs } from "../../crypto/store";
import { resolveScheme } from "../theme";
import type { ColorSlot, EmblemName, SchemeName } from "../theme";
import type { ThemeElement, Weekday } from "../parser";
import type { ExecutorInternals } from "./context";
import { DEFAULT_ROTATION } from "./records";
import type { RotationSettings } from "./records";

export async function doSettingsRotation(
  x: ExecutorInternals,
  setting: { kind: "on" } | { kind: "off" } | { kind: "day"; day: Weekday },
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.event("failure", "store is locked - /login first (settings live encrypted)");
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

/** `/settings trust <auto|manual>`: switch trust-on-first-use (spec 4.6a). */
export async function doSettingsTrust(
  x: ExecutorInternals,
  mode: "auto" | "manual",
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.event("failure", "store is locked - /login first (trust setting lives encrypted)");
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
 * Purely cosmetic; works while locked for the same reason it is stored
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

/** `/settings scheme <dark|parchment|olive>`: switch the base palette. */
export async function doSettingsScheme(x: ExecutorInternals, scheme: SchemeName): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, scheme });
  x.chrome.applyScheme(resolveScheme(scheme, prefs.colorOverrides));
  x.renderer.event("success", `color scheme set to '${scheme}'`);
}

/** `/settings emblem <pq|globe|tree>`: choose the medallion glyph. */
export async function doSettingsEmblem(x: ExecutorInternals, emblem: EmblemName): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, emblemGlyph: emblem });
  x.chrome.applyEmblem(emblem);
  x.renderer.event("success", `emblem set to '${emblem}'`);
}

/** `/settings color <slot> <#rrggbb>`: override one slot of the active
 * scheme with a custom HEX value (the terminal-native color picker). */
export async function doSettingsColor(
  x: ExecutorInternals,
  slot: ColorSlot,
  hex: string,
): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  const colorOverrides = { ...prefs.colorOverrides, [slot]: hex };
  await x.store.setDisplayPrefs({ ...prefs, colorOverrides });
  x.chrome.applyScheme(resolveScheme(prefs.scheme, colorOverrides));
  x.renderer.event("success", `${slot} set to ${hex} (on the '${prefs.scheme}' scheme)`);
}

/** `/settings color reset`: drop all HEX overrides, back to the pure scheme. */
export async function doSettingsColorReset(x: ExecutorInternals): Promise<void> {
  const prefs = await x.store.getDisplayPrefs();
  await x.store.setDisplayPrefs({ ...prefs, colorOverrides: {} });
  x.chrome.applyScheme(resolveScheme(prefs.scheme, {}));
  x.renderer.event("success", `custom colors cleared - pure '${prefs.scheme}' scheme restored`);
}
