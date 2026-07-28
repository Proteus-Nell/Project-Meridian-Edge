// Custom color schemes and the immutability of the three presets.
//
// The behaviour this file exists to pin down: editing a color must never write
// to a preset, so `/settings scheme dark` is always a way back to the palette
// that shipped. Everything else here (create, delete, list, limits) follows
// from that. None of it touches the network or an unlocked store - display
// prefs are deliberately unencrypted - so these run without api mocks.

import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { KeyStore } from "../src/crypto/store";
import { MAX_CUSTOM_SCHEMES, SCHEMES } from "../src/terminal/theme";
import { CaptureSink, FakeChrome, FakeShell } from "./helpers/executor-harness";

function makeExecutor(): {
  executor: Executor;
  output: CaptureSink;
  chrome: FakeChrome;
  store: KeyStore;
} {
  const output = new CaptureSink();
  const chrome = new FakeChrome();
  const store = new KeyStore(`meridian-edge-schemes-${Math.random()}`, new IDBFactory());
  const executor = new Executor(new Renderer(output), new FakeShell(), store, undefined, chrome);
  return { executor, output, chrome, store };
}

/** Run a command and wait for both lanes to settle. */
async function run(executor: Executor, line: string): Promise<void> {
  executor.handle(parseLine(line));
  await executor.idle();
}

function lastScheme(chrome: FakeChrome): Record<string, unknown> {
  return (chrome.schemes[chrome.schemes.length - 1] ?? {}) as unknown as Record<string, unknown>;
}

describe("presets are immutable", () => {
  it("forks a preset instead of editing it, and says so", async () => {
    const { executor, output, chrome, store } = makeExecutor();
    await run(executor, "/settings color background #101820");

    expect(lastScheme(chrome).background).toBe("#101820");
    const prefs = await store.getDisplayPrefs();
    expect(prefs.scheme).toBe("dark-custom");
    expect(prefs.customSchemes).toHaveLength(1);
    expect(prefs.customSchemes[0]?.base).toBe("dark");
    // The untouched slots come from the preset it forked.
    expect(prefs.customSchemes[0]?.colors.accent).toBe(SCHEMES.dark.colors.accent);
    expect(output.text()).toContain("the 'dark' preset is unchanged");
  });

  it("gives the pristine preset back when you switch to it", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings color background #101820");
    await run(executor, "/settings color accent #ff0000");
    await run(executor, "/settings scheme dark");

    expect(lastScheme(chrome).background).toBe(SCHEMES.dark.colors.background);
    expect(lastScheme(chrome).accent).toBe(SCHEMES.dark.colors.accent);
    expect((await store.getDisplayPrefs()).scheme).toBe("dark");
  });

  it("keeps the fork intact after a round trip through the preset", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings color background #101820");
    await run(executor, "/settings scheme dark");
    await run(executor, "/settings scheme dark-custom");

    expect(lastScheme(chrome).background).toBe("#101820");
    expect((await store.getDisplayPrefs()).customSchemes).toHaveLength(1);
  });

  it("edits the existing fork rather than stacking up new ones", async () => {
    const { executor, store } = makeExecutor();
    await run(executor, "/settings color background #101820");
    await run(executor, "/settings color accent #ff0000");
    await run(executor, "/settings color muted #00ff00");

    const prefs = await store.getDisplayPrefs();
    expect(prefs.customSchemes).toHaveLength(1);
    expect(prefs.customSchemes[0]?.colors).toMatchObject({
      background: "#101820",
      accent: "#ff0000",
      muted: "#00ff00",
    });
  });

  it("forks each preset separately", async () => {
    const { executor, store } = makeExecutor();
    await run(executor, "/settings color accent #ff0000");
    await run(executor, "/settings scheme olive");
    await run(executor, "/settings color accent #00ff00");

    const prefs = await store.getDisplayPrefs();
    expect(prefs.scheme).toBe("olive-custom");
    expect(prefs.customSchemes.map((s) => s.name).sort()).toEqual(["dark-custom", "olive-custom"]);
    // The olive fork starts from olive, not from the dark fork.
    const oliveFork = prefs.customSchemes.find((s) => s.name === "olive-custom");
    expect(oliveFork?.colors.background).toBe(SCHEMES.olive.colors.background);
  });

  it("refuses to delete a preset", async () => {
    const { executor, output, store } = makeExecutor();
    await run(executor, "/settings scheme delete dark");
    expect(output.text()).toContain("[E107]");
    expect((await store.getDisplayPrefs()).scheme).toBe("dark");
  });

  it("reports that a preset has nothing to reset", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings color reset");
    expect(output.text()).toContain("nothing to reset");
  });
});

describe("/settings scheme new", () => {
  it("copies what is on screen and switches to it", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings scheme parchment");
    await run(executor, "/settings scheme new paper");

    const prefs = await store.getDisplayPrefs();
    expect(prefs.scheme).toBe("paper");
    expect(prefs.customSchemes[0]?.base).toBe("parchment");
    expect(prefs.customSchemes[0]?.colors.background).toBe(SCHEMES.parchment.colors.background);
    // ANSI overrides come with the base, so a light fork stays readable.
    expect(lastScheme(chrome).ansi).toEqual(SCHEMES.parchment.ansi);
  });

  it("carries the current custom colors into a second scheme", async () => {
    const { executor, store } = makeExecutor();
    await run(executor, "/settings color accent #ff0000");
    await run(executor, "/settings scheme new copy");

    const copy = (await store.getDisplayPrefs()).customSchemes.find((s) => s.name === "copy");
    expect(copy?.colors.accent).toBe("#ff0000");
    expect(copy?.base).toBe("dark");
  });

  it("rejects a name that is reserved, a preset, or malformed", async () => {
    const { executor, output, store } = makeExecutor();
    for (const name of ["dark", "list", "new", "__proto__", "constructor"]) {
      await run(executor, `/settings scheme new ${name}`);
    }
    expect(output.text()).toContain("[E107]");
    expect((await store.getDisplayPrefs()).customSchemes).toEqual([]);
    // Object.prototype is untouched by any of it.
    expect(({} as Record<string, unknown>).base).toBeUndefined();
  });

  it("rejects a name the parser will not even carry", async () => {
    const { executor, output, store } = makeExecutor();
    await run(executor, "/settings scheme new with;semicolon");
    expect(output.text()).toContain("[E102]");
    expect((await store.getDisplayPrefs()).customSchemes).toEqual([]);
  });

  it("rejects a duplicate name", async () => {
    const { executor, output, store } = makeExecutor();
    await run(executor, "/settings scheme new mine");
    await run(executor, "/settings scheme new mine");
    expect(output.text()).toContain("[E109]");
    expect((await store.getDisplayPrefs()).customSchemes).toHaveLength(1);
  });

  it("enforces the custom scheme limit", async () => {
    const { executor, output, store } = makeExecutor();
    for (let i = 0; i < MAX_CUSTOM_SCHEMES; i += 1) {
      await run(executor, `/settings scheme new s${i}`);
    }
    expect((await store.getDisplayPrefs()).customSchemes).toHaveLength(MAX_CUSTOM_SCHEMES);
    await run(executor, "/settings scheme new one-too-many");
    expect(output.text()).toContain("[E108]");
    expect((await store.getDisplayPrefs()).customSchemes).toHaveLength(MAX_CUSTOM_SCHEMES);
  });
});

describe("/settings scheme delete", () => {
  it("removes a custom scheme", async () => {
    const { executor, store } = makeExecutor();
    await run(executor, "/settings scheme new mine");
    await run(executor, "/settings scheme dark");
    await run(executor, "/settings scheme delete mine");
    expect((await store.getDisplayPrefs()).customSchemes).toEqual([]);
  });

  it("falls back to the base preset when deleting what is on screen", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings scheme olive");
    await run(executor, "/settings scheme new mine");
    await run(executor, "/settings color accent #ff0000");
    await run(executor, "/settings scheme delete mine");

    expect((await store.getDisplayPrefs()).scheme).toBe("olive");
    expect(lastScheme(chrome).accent).toBe(SCHEMES.olive.colors.accent);
  });

  it("reports an unknown custom scheme", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings scheme delete nothing-here");
    expect(output.text()).toContain("[E106]");
  });
});

describe("/settings color reset", () => {
  it("restores a custom scheme to its base preset colors, keeping the scheme", async () => {
    const { executor, chrome, store } = makeExecutor();
    await run(executor, "/settings scheme olive");
    await run(executor, "/settings color accent #ff0000");
    await run(executor, "/settings color reset");

    const prefs = await store.getDisplayPrefs();
    expect(prefs.scheme).toBe("olive-custom");
    expect(prefs.customSchemes[0]?.colors).toEqual(SCHEMES.olive.colors);
    expect(lastScheme(chrome).accent).toBe(SCHEMES.olive.colors.accent);
  });
});

describe("/settings scheme list", () => {
  it("lists presets and custom schemes, marking the active one", async () => {
    const { executor, output } = makeExecutor();
    await run(executor, "/settings scheme new mine");
    await run(executor, "/settings scheme list");

    const text = output.text();
    for (const name of ["dark", "parchment", "olive", "mine"]) {
      expect(text).toContain(name);
    }
    expect(text).toContain("preset (never modified)");
    expect(text).toContain("* mine");
    expect(text).toContain(`1/${MAX_CUSTOM_SCHEMES} custom`);
  });
});

describe("persistence", () => {
  it("re-applies a custom scheme on the next start, before any unlock", async () => {
    const factory = new IDBFactory();
    const name = "meridian-edge-schemes-persist";
    const first = makeExecutorOn(new KeyStore(name, factory));
    await run(first.executor, "/settings color background #101820");

    // A reload: fresh executor, same database, store still locked.
    const second = makeExecutorOn(new KeyStore(name, factory));
    await second.executor.init();
    expect(second.store.isUnlocked()).toBe(false);
    expect(lastScheme(second.chrome).background).toBe("#101820");
  });
});

function makeExecutorOn(store: KeyStore): {
  executor: Executor;
  chrome: FakeChrome;
  store: KeyStore;
} {
  const chrome = new FakeChrome();
  const executor = new Executor(
    new Renderer(new CaptureSink()),
    new FakeShell(),
    store,
    undefined,
    chrome,
  );
  return { executor, chrome, store };
}
