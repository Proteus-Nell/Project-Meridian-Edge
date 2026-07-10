// UI-surface wiring in the executor (CLAUDE.md §1): the /clr screen wipe and the
// "did you mean …?" hint. Neither touches the network or an unlocked store, so
// these run without api mocks.

import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import type { LineSink } from "../src/terminal/renderer";
import type { ShellIO } from "../src/terminal/shell";
import { KeyStore } from "../src/crypto/store";
import type { ThemePrefs } from "../src/crypto/store";
import type { EmblemName, ResolvedScheme } from "../src/terminal/theme";

class FakeShell implements ShellIO {
  readSecret(): Promise<string | null> {
    return Promise.resolve(null);
  }
  readLine(): Promise<string | null> {
    return Promise.resolve(null);
  }
  setPrompt(): void {}
  setSecretMask(): void {}
}

class CaptureSink implements LineSink {
  lines: string[] = [];
  printLine(line: string): void {
    this.lines.push(line);
  }
  text(): string {
    return this.lines.join("\n");
  }
}

class FakeChrome {
  clears = 0;
  themes: ThemePrefs[] = [];
  context: string | null = null;
  emblem = "unset";
  confirmSent(): void {}
  rejectSent(): void {}
  clearScreen(): void {
    this.clears += 1;
  }
  setChatContext(text: string | null): void {
    this.context = text;
  }
  applyTheme(theme: ThemePrefs): void {
    this.themes.push(theme);
  }
  setEmblemState(state: string): void {
    this.emblem = state;
  }
  schemes: ResolvedScheme[] = [];
  glyphs: EmblemName[] = [];
  applyScheme(scheme: ResolvedScheme): void {
    this.schemes.push(scheme);
  }
  applyEmblem(name: EmblemName): void {
    this.glyphs.push(name);
  }
}

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
    executor.handle(parseLine("/settings theme emblem off"));
    await executor.idle();
    expect(chrome.themes[chrome.themes.length - 1]).toEqual({
      emblem: false,
      scanlines: true,
      vignette: true,
      dock: true,
    });
    // Persisted unencrypted: readable without ever unlocking the store.
    expect(store.isUnlocked()).toBe(false);
    expect((await store.getDisplayPrefs()).theme.emblem).toBe(false);
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

  it("switches schemes, applies HEX overrides, and resets them", async () => {
    const { executor, chrome, store } = makeExecutor();
    executor.handle(parseLine("/settings scheme parchment"));
    await executor.idle();
    let applied = chrome.schemes[chrome.schemes.length - 1];
    expect(applied?.background).toBe("#e3e7d3");
    expect(applied?.accent).toBe("#8a6d2f");
    expect((await store.getDisplayPrefs()).scheme).toBe("parchment");

    // A HEX override layers on the active scheme and persists.
    executor.handle(parseLine("/settings color background #101820"));
    await executor.idle();
    applied = chrome.schemes[chrome.schemes.length - 1];
    expect(applied?.background).toBe("#101820");
    expect(applied?.accent).toBe("#8a6d2f"); // untouched slot keeps scheme value
    expect((await store.getDisplayPrefs()).colorOverrides).toEqual({ background: "#101820" });

    // Reset restores the pure scheme.
    executor.handle(parseLine("/settings color reset"));
    await executor.idle();
    applied = chrome.schemes[chrome.schemes.length - 1];
    expect(applied?.background).toBe("#e3e7d3");
    expect((await store.getDisplayPrefs()).colorOverrides).toEqual({});
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
