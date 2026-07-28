// UI-surface wiring in the executor: the /clr screen wipe and the
// "did you mean …?" hint. Neither touches the network or an unlocked store, so
// these run without api mocks.

import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { KeyStore } from "../src/crypto/store";
import { CaptureSink, FakeChrome, FakeShell } from "./helpers/executor-harness";

function makeExecutor(): {
  executor: Executor;
  output: CaptureSink;
  chrome: FakeChrome;
  store: KeyStore;
} {
  const output = new CaptureSink();
  const chrome = new FakeChrome();
  const store = new KeyStore(`meridian-edge-ui-${Math.random()}`, new IDBFactory());
  const executor = new Executor(new Renderer(output), new FakeShell(), store, undefined, chrome);
  return { executor, output, chrome, store };
}

describe("executor UI wiring", () => {
  it("routes /clr to the chrome screen clear", () => {
    const { executor, chrome } = makeExecutor();
    executor.handle(parseLine("/clr"));
    expect(chrome.clears).toBe(1);
  });

  it("prints a did-you-mean hint for a mistyped command", () => {
    const { executor, output } = makeExecutor();
    executor.handle(parseLine("/loing")); // a typo, not an alias
    expect(output.text()).toContain("did you mean /login?");
  });

  it("prints a did-you-mean hint for a near-miss typo", () => {
    const { executor, output } = makeExecutor();
    executor.handle(parseLine("/registr")); // a typo, not an alias
    expect(output.text()).toContain("did you mean /register?");
  });

  it("adds no hint for far-off input", () => {
    const { executor, output } = makeExecutor();
    executor.handle(parseLine("/zzzzzzzz"));
    expect(output.text()).not.toContain("did you mean");
  });
});

describe("/settings theme", () => {
  it("toggles one layer, applies it, and persists it while locked", async () => {
    const { executor, chrome, store } = makeExecutor();
    // Layers default off, so toggle one ON and confirm the others stay off.
    executor.handle(parseLine("/settings theme emblem on"));
    await executor.idle();
    expect(chrome.themes[chrome.themes.length - 1]).toEqual({
      emblem: true,
      scanlines: false,
      vignette: false,
      dock: false,
    });
    // Persisted unencrypted: readable without ever unlocking the store.
    expect(store.isUnlocked()).toBe(false);
    expect((await store.getDisplayPrefs()).theme.emblem).toBe(true);
  });

  it("'all off' flips every layer at once", async () => {
    const { executor, chrome, store } = makeExecutor();
    executor.handle(parseLine("/settings theme all off"));
    await executor.idle();
    expect(chrome.themes[chrome.themes.length - 1]).toEqual({
      emblem: false,
      scanlines: false,
      vignette: false,
      dock: false,
    });
    executor.handle(parseLine("/settings theme dock on"));
    await executor.idle();
    expect((await store.getDisplayPrefs()).theme).toEqual({
      emblem: false,
      scanlines: false,
      vignette: false,
      dock: true,
    });
  });

  it("switches between presets", async () => {
    const { executor, chrome, store } = makeExecutor();
    executor.handle(parseLine("/settings scheme parchment"));
    await executor.idle();
    const applied = chrome.schemes[chrome.schemes.length - 1];
    expect(applied?.background).toBe("#e3e7d3");
    expect(applied?.accent).toBe("#8a6d2f");
    expect((await store.getDisplayPrefs()).scheme).toBe("parchment");
  });

  it("rejects a scheme name that does not exist", async () => {
    const { executor, output, store } = makeExecutor();
    executor.handle(parseLine("/settings scheme neon"));
    await executor.idle();
    expect(output.text()).toContain("[E106]");
    expect((await store.getDisplayPrefs()).scheme).toBe("dark");
  });

  it("selects an emblem glyph and persists it", async () => {
    const { executor, chrome, store } = makeExecutor();
    executor.handle(parseLine("/settings emblem globe"));
    await executor.idle();
    expect(chrome.glyphs[chrome.glyphs.length - 1]).toBe("globe");
    expect((await store.getDisplayPrefs()).emblemGlyph).toBe("globe");
    executor.handle(parseLine("/settings emblem tree"));
    await executor.idle();
    expect(chrome.glyphs[chrome.glyphs.length - 1]).toBe("tree");
  });

  it("preserves the theme when the mask setting is changed", async () => {
    const { executor, store } = makeExecutor();
    executor.handle(parseLine("/settings theme scanlines off"));
    await executor.idle();
    executor.handle(parseLine("/settings mask hidden"));
    await executor.idle();
    const prefs = await store.getDisplayPrefs();
    expect(prefs.secretMask).toBe("hidden");
    expect(prefs.theme.scanlines).toBe(false);
  });
});
