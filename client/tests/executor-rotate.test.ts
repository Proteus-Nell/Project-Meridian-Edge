import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { KeyStore } from "../src/crypto/store";
import type { Argon2Params } from "../src/crypto/store";
import { CaptureSink, FakeShell } from "./helpers/executor-harness";

const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };

async function setup(): Promise<{
  executor: Executor;
  shell: FakeShell;
  output: CaptureSink;
  store: KeyStore;
}> {
  const store = new KeyStore("meridian-edge-exec-test", new IDBFactory());
  await store.create("original passphrase 1", FAST);
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store);
  return { executor, shell, output, store };
}

async function rotate(executor: Executor): Promise<void> {
  executor.handle(parseLine("/rotate passphrase"));
  await executor.idle();
}

describe("/rotate passphrase same-passphrase guard", () => {
  it("warns and prompts when the new passphrase equals the current one", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase 1", "original passphrase 1", "original passphrase 1"];
    shell.lines = ["n"];
    await rotate(executor);

    const text = output.lines.join("\n");
    expect(text).toContain("identical to the current one");
    expect(shell.lineQueries).toEqual(["rotate anyway? (y/N): "]);
    expect(text).toContain("Rotation cancelled");
    expect(text).not.toContain("Passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase 1")).toBe(true);
  });

  it("defaults to cancel on Enter or Ctrl+C", async () => {
    const { executor, shell, output } = await setup();
    shell.secrets = ["original passphrase 1", "original passphrase 1", "original passphrase 1"];
    shell.lines = [""];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("Rotation cancelled");

    shell.secrets = ["original passphrase 1", "original passphrase 1", "original passphrase 1"];
    shell.lines = [null]; // Ctrl+C
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("Rotation cancelled");
  });

  it("proceeds when the user explicitly confirms", async () => {
    const { executor, shell, output } = await setup();
    shell.secrets = ["original passphrase 1", "original passphrase 1", "original passphrase 1"];
    shell.lines = ["y"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("Passphrase rotated");
  });

  it("does not prompt when the new passphrase differs", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase 1", "different passphrase 2", "different passphrase 2"];
    await rotate(executor);

    expect(shell.lineQueries).toEqual([]);
    expect(output.lines.join("\n")).toContain("Passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase 1")).toBe(false);
    expect(await store.unlock("different passphrase 2")).toBe(true);
  });

  it("still rejects a wrong current passphrase", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["wrong guess!", "different passphrase 2", "different passphrase 2"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("Rotation failed");
    store.lock();
    expect(await store.unlock("original passphrase 1")).toBe(true);
  });

  it("rejects a too-short new passphrase without touching the store", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase 1", "short"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("at least 12 characters");
    expect(output.lines.join("\n")).not.toContain("Passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase 1")).toBe(true);
  });

  it("rejects a mismatched confirmation without touching the store", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase 1", "brand new passphrase 3", "different confirmation"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("did not match");
    expect(output.lines.join("\n")).not.toContain("Passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase 1")).toBe(true);
  });
});

describe("/settings mask", () => {
  it("applies the mask to the shell and persists it", async () => {
    const { executor, shell, store } = await setup();
    executor.handle(parseLine("/settings mask hidden"));
    await executor.idle();
    expect(shell.masks.at(-1)).toBe("hidden");
    expect((await store.getDisplayPrefs()).secretMask).toBe("hidden");
  });

  it("init() applies the persisted mask before any prompt", async () => {
    const { executor, store } = await setup();
    executor.handle(parseLine("/settings mask hidden"));
    await executor.idle();

    // A fresh executor over the same store reads and applies it on init.
    const shell2 = new FakeShell();
    const output2 = new CaptureSink();
    const executor2 = new Executor(new Renderer(output2), shell2, store);
    await executor2.init();
    expect(shell2.masks).toContain("hidden");
  });

  it("switching back to asterisk persists too", async () => {
    const { executor, shell, store } = await setup();
    executor.handle(parseLine("/settings mask hidden"));
    await executor.idle();
    executor.handle(parseLine("/settings mask asterisk"));
    await executor.idle();
    expect(shell.masks.at(-1)).toBe("asterisk");
    expect((await store.getDisplayPrefs()).secretMask).toBe("asterisk");
  });
});
