// Fonts, spacing and accessibility: /settings font, /settings fontsize,
// /settings spacing, /settings a11y, and the contrast preset. All display
// preferences, so all unencrypted and all available before unlock, which is the
// point: someone who needs a larger face, looser spacing or a screen reader
// meets the lock screen first.

import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { KeyStore } from "../src/crypto/store";
import {
  DEFAULT_FONT_SIZE,
  DEFAULT_LETTER_SPACING,
  DEFAULT_LINE_HEIGHT,
  FONT_NAMES,
  FONT_STACKS,
  MAX_FONT_SIZE,
  MAX_LETTER_SPACING,
  MAX_LINE_HEIGHT,
  MIN_FONT_SIZE,
  MIN_LETTER_SPACING,
  MIN_LINE_HEIGHT,
  SCHEMES,
  clampFontSize,
  clampLetterSpacing,
  clampLineHeight,
  resolveScheme,
} from "../src/terminal/theme";
import { CaptureSink, FakeChrome, FakeShell } from "./helpers/executor-harness";

function makeExecutor(store?: KeyStore): {
  executor: Executor;
  output: CaptureSink;
  chrome: FakeChrome;
  store: KeyStore;
} {
  const output = new CaptureSink();
  const chrome = new FakeChrome();
  const real = store ?? new KeyStore(`meridian-edge-a11y-${Math.random()}`, new IDBFactory());
  const executor = new Executor(new Renderer(output), new FakeShell(), real, undefined, chrome);
  return { executor, output, chrome, store: real };
}

async function run(executor: Executor, line: string): Promise<void> {
  executor.handle(parseLine(line));
  await executor.idle();
}

describe("font stacks", () => {
  it("are monospace-only, local-only, and never fetched", () => {
    for (const name of FONT_NAMES) {
      const stack = FONT_STACKS[name];
      // A remote font would be a request to someone else's server on every
      // load. The CSP forbids it; this keeps it out of the source too.
      expect(stack, name).not.toMatch(/url\(|https?:|@import/i);
      // Every stack ends in the generic family, so a machine with none of the
      // named faces still gets fixed-width cells.
      expect(stack.trim().endsWith("monospace"), `${name}: ${stack}`).toBe(true);
      // Nothing proportional sneaks in: xterm's cell model and every padded
      // column in the app depend on it.
      expect(stack, name).not.toMatch(/\b(sans-serif|serif|cursive|fantasy)\b/);
    }
  });

  it("carries no character that could break out of a CSS declaration", () => {
    for (const name of FONT_NAMES) {
      expect(FONT_STACKS[name], name).toMatch(/^[A-Za-z0-9 ,'-]+$/);
    }
  });
});

describe("/settings font", () => {
  it("switches the stack, persists it, and applies it while locked", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings font classic");
    expect(chrome.textStyles.at(-1)).toMatchObject({
      font: "classic",
      fontSize: DEFAULT_FONT_SIZE,
    });
    expect(store.isUnlocked()).toBe(false);
    expect((await store.getDisplayPrefs()).font).toBe("classic");
  });

  it("rejects a name outside the allowlist", async () => {
    const { executor, output, store } = makeExecutor();
    await run(executor, "/settings font comic-sans");
    expect(output.text()).toContain("[E102]");
    expect((await store.getDisplayPrefs()).font).toBe("default");
  });

  it("lists every stack, marking the active one", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings font wide");
    await run(executor, "/settings font list");
    const text = output.text();
    for (const name of FONT_NAMES) {
      expect(text).toContain(name);
    }
    expect(text).toContain("* wide");
    expect(text).toContain("all monospace");
  });
});

describe("/settings fontsize", () => {
  it("resizes and re-applies the current stack", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings font compact");
    await run(executor, "/settings fontsize 22");
    expect(chrome.textStyles.at(-1)).toMatchObject({ font: "compact", fontSize: 22 });
    expect((await store.getDisplayPrefs()).fontSize).toBe(22);
  });

  it("rejects a size outside the supported range", async () => {
    const { executor, output, store } = makeExecutor();
    for (const line of [
      "/settings fontsize 4",
      "/settings fontsize 99",
      "/settings fontsize big",
      "/settings fontsize",
    ]) {
      await run(executor, line);
    }
    expect(output.text()).toContain("[E102]");
    expect((await store.getDisplayPrefs()).fontSize).toBe(DEFAULT_FONT_SIZE);
  });

  it("clamps a tampered stored size rather than trusting it", async () => {
    const { store } = makeExecutor();
    await store.setDisplayPrefs({
      ...(await store.getDisplayPrefs()),
      fontSize: 9999,
    });
    expect((await store.getDisplayPrefs()).fontSize).toBe(MAX_FONT_SIZE);
    expect(clampFontSize(-5)).toBe(MIN_FONT_SIZE);
    expect(clampFontSize(Number.NaN)).toBe(DEFAULT_FONT_SIZE);
  });
});

describe("/settings a11y", () => {
  it("toggles screen reader mode and persists it", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings a11y screenreader on");
    expect(chrome.accessibility.at(-1)?.screenReader).toBe(true);
    expect((await store.getDisplayPrefs()).accessibility.screenReader).toBe(true);

    await run(executor, "/settings a11y screenreader off");
    expect(chrome.accessibility.at(-1)?.screenReader).toBe(false);
  });

  it("toggles reduced motion without disturbing the other switch", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings a11y screenreader on");
    await run(executor, "/settings a11y motion on");
    expect(chrome.accessibility.at(-1)).toEqual({ screenReader: true, reduceMotion: true });
    expect((await store.getDisplayPrefs()).accessibility).toEqual({
      screenReader: true,
      reduceMotion: true,
    });
  });

  it("rejects an unknown switch", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings a11y telepathy on");
    expect(output.text()).toContain("[E102]");
  });

  it("says that reduced motion does not replace the system setting", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings a11y motion off");
    expect(output.text()).toContain("system setting still applies");
  });
});

describe("the contrast preset", () => {
  it("clears WCAG AA against its own background, every slot", () => {
    const scheme = resolveScheme("contrast", []);
    for (const slot of ["accent", "text", "muted"] as const) {
      expect(contrastRatio(scheme[slot], scheme.background), slot).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("clears AA for the notification markers too", () => {
    const scheme = resolveScheme("contrast", []);
    for (const [name, hex] of Object.entries(scheme.ansi ?? {})) {
      expect(contrastRatio(hex, scheme.background), name).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("is a preset, so it cannot be edited or deleted away", async () => {
    const { executor, output, store } = makeExecutor();
    await run(executor, "/settings scheme contrast");
    expect((await store.getDisplayPrefs()).scheme).toBe("contrast");
    await run(executor, "/settings scheme delete contrast");
    expect(output.text()).toContain("[E107]");
    expect(resolveScheme("contrast", []).background).toBe(SCHEMES.contrast.colors.background);
  });
});

/** WCAG 2.1 relative luminance and contrast ratio, for the preset assertions. */
function luminance(hex: string): number {
  const channel = (offset: number): number => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrastRatio(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

describe("/settings spacing", () => {
  it("sets letter spacing and re-applies the whole text style", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings spacing letter 1.5");
    // The whole style goes to the chrome, not just the changed field: all four
    // metrics move the cell box together, so they share one application path.
    expect(chrome.textStyles.at(-1)).toMatchObject({
      letterSpacing: 1.5,
      lineHeight: DEFAULT_LINE_HEIGHT,
      fontSize: DEFAULT_FONT_SIZE,
    });
    expect((await store.getDisplayPrefs()).letterSpacing).toBe(1.5);
  });

  it("sets line height independently of letter spacing", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings spacing letter 2");
    await run(executor, "/settings spacing line 1.8");
    expect(chrome.textStyles.at(-1)).toMatchObject({ letterSpacing: 2, lineHeight: 1.8 });
    const prefs = await store.getDisplayPrefs();
    expect(prefs.letterSpacing).toBe(2);
    expect(prefs.lineHeight).toBe(1.8);
  });

  it("survives a reload, since it lives with the unencrypted display prefs", async () => {
    const factory = new IDBFactory();
    const name = "meridian-edge-spacing-persist";
    const first = makeExecutor(new KeyStore(name, factory));
    await run(first.executor, "/settings spacing line 2");

    const second = makeExecutor(new KeyStore(name, factory));
    await second.executor.init();
    expect(second.store.isUnlocked()).toBe(false);
    expect(second.chrome.textStyles.at(-1)).toMatchObject({ lineHeight: 2 });
  });

  it("rejects a value outside its range, and an unknown kind", async () => {
    const { executor, output, store } = makeExecutor();
    for (const line of [
      "/settings spacing letter 9", // above the 4px cap
      "/settings spacing line 0.5", // below 1x, which would overlap rows
      "/settings spacing line 9",
      "/settings spacing letter wide",
      "/settings spacing word 2", // not a kind
      "/settings spacing letter",
      "/settings spacing letter 1.25", // finer than one decimal
    ]) {
      await run(executor, line);
    }
    expect(output.text()).toContain("[E102]");
    const prefs = await store.getDisplayPrefs();
    expect(prefs.letterSpacing).toBe(DEFAULT_LETTER_SPACING);
    expect(prefs.lineHeight).toBe(DEFAULT_LINE_HEIGHT);
  });

  it("accepts the boundaries", async () => {
    const { executor, store } = makeExecutor();
    await run(executor, "/settings spacing letter 0");
    await run(executor, "/settings spacing line 2.5");
    const prefs = await store.getDisplayPrefs();
    expect(prefs.letterSpacing).toBe(MIN_LETTER_SPACING);
    expect(prefs.lineHeight).toBe(MAX_LINE_HEIGHT);
  });

  it("clamps a tampered stored value rather than trusting it", async () => {
    const { store } = makeExecutor();
    await store.setDisplayPrefs({
      ...(await store.getDisplayPrefs()),
      letterSpacing: 9999,
      lineHeight: -3,
    });
    const prefs = await store.getDisplayPrefs();
    expect(prefs.letterSpacing).toBe(MAX_LETTER_SPACING);
    expect(prefs.lineHeight).toBe(MIN_LINE_HEIGHT);
    expect(clampLetterSpacing(Number.NaN)).toBe(DEFAULT_LETTER_SPACING);
    expect(clampLineHeight(Number.NaN)).toBe(DEFAULT_LINE_HEIGHT);
  });

  it("shows the current spacing in /settings font list", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings spacing letter 1");
    await run(executor, "/settings font list");
    expect(output.text()).toContain("letter spacing 1px");
    expect(output.text()).toContain("line height 1x");
  });
});
