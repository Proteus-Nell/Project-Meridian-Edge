import { describe, expect, it } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import type { LineSink } from "../src/terminal/renderer";
import type { ShellIO } from "../src/terminal/shell";
import { KeyStore } from "../src/crypto/store";
import type { Argon2Params } from "../src/crypto/store";

const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };

class FakeShell implements ShellIO {
  secrets: (string | null)[] = [];
  lines: (string | null)[] = [];
  lineQueries: string[] = [];
  masks: string[] = [];

  readSecret(): Promise<string | null> {
    return Promise.resolve(this.secrets.shift() ?? null);
  }

  readLine(promptText: string): Promise<string | null> {
    this.lineQueries.push(promptText);
    return Promise.resolve(this.lines.shift() ?? null);
  }

  setPrompt(): void {}

  setSecretMask(mask: string): void {
    this.masks.push(mask);
  }
}

class CaptureSink implements LineSink {
  lines: string[] = [];
  printLine(line: string): void {
    this.lines.push(line);
  }
}

async function setup(): Promise<{
  executor: Executor;
  shell: FakeShell;
  output: CaptureSink;
  store: KeyStore;
}> {
  const store = new KeyStore("pqterm-exec-test", new IDBFactory());
  await store.create("original passphrase", FAST);
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
    shell.secrets = ["original passphrase", "original passphrase", "original passphrase"];
    shell.lines = ["n"];
    await rotate(executor);

    const text = output.lines.join("\n");
    expect(text).toContain("identical to the current one");
    expect(shell.lineQueries).toEqual(["rotate anyway? (y/N): "]);
    expect(text).toContain("rotation cancelled");
    expect(text).not.toContain("passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(true);
  });

  it("defaults to cancel on Enter or Ctrl+C", async () => {
    const { executor, shell, output } = await setup();
    shell.secrets = ["original passphrase", "original passphrase", "original passphrase"];
    shell.lines = [""];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("rotation cancelled");

    shell.secrets = ["original passphrase", "original passphrase", "original passphrase"];
    shell.lines = [null]; // Ctrl+C
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("rotation cancelled");
  });

  it("proceeds when the user explicitly confirms", async () => {
    const { executor, shell, output } = await setup();
    shell.secrets = ["original passphrase", "original passphrase", "original passphrase"];
    shell.lines = ["y"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("passphrase rotated");
  });

  it("does not prompt when the new passphrase differs", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase", "different passphrase", "different passphrase"];
    await rotate(executor);

    expect(shell.lineQueries).toEqual([]);
    expect(output.lines.join("\n")).toContain("passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(false);
    expect(await store.unlock("different passphrase")).toBe(true);
  });

  it("still rejects a wrong current passphrase", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["wrong guess!", "different passphrase", "different passphrase"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("rotation failed");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(true);
  });

  it("rejects a too-short new passphrase without touching the store", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase", "short"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("at least 8 characters");
    expect(output.lines.join("\n")).not.toContain("passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(true);
  });

  it("rejects a mismatched confirmation without touching the store", async () => {
    const { executor, shell, output, store } = await setup();
    shell.secrets = ["original passphrase", "brand new passphrase", "different confirmation"];
    await rotate(executor);
    expect(output.lines.join("\n")).toContain("do not match");
    expect(output.lines.join("\n")).not.toContain("passphrase rotated");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(true);
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
