// /recover (CLAUDE.md §2.2): redeem a recovery code, enroll a fresh identity
// key, rebuild the local store. Network is mocked; the store, prompts, and
// crypto are real. The peer-side consequence of a recovery (identity-key
// change) is covered by the §4.6 tests in executor-verify.test.ts.

import { describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import * as api from "../src/net/api";
import { KeyStore } from "../src/crypto/store";
import type { Argon2Params } from "../src/crypto/store";
import { Executor } from "../src/terminal/executor";
import { formatUid, normalizeRecoveryCode, parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import type { LineSink } from "../src/terminal/renderer";
import type { ShellIO } from "../src/terminal/shell";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return {
    ApiError: actual.ApiError,
    register: vi.fn(),
    recover: vi.fn(),
    loginChallenge: vi.fn(),
    loginVerify: vi.fn(),
    logout: vi.fn(),
    uploadSpk: vi.fn(),
    uploadOpks: vi.fn(),
    keysStatus: vi.fn(),
    fetchBundle: vi.fn(),
    sendMessage: vi.fn(),
    fetchMessages: vi.fn(),
    ackMessages: vi.fn(),
  };
});

const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };
const UID = "A".repeat(26);
const CODE_TYPED = "7777-7777-7777-7777";
const FRESH_CODES = Array.from({ length: 10 }, (_, i) => `NEW${i}-NEW${i}-NEW${i}-NEW${i}`);

class FakeShell implements ShellIO {
  secrets: (string | null)[] = [];
  lines: (string | null)[] = [];
  lineQueries: string[] = [];

  readSecret(): Promise<string | null> {
    return Promise.resolve(this.secrets.shift() ?? null);
  }

  readLine(promptText: string): Promise<string | null> {
    this.lineQueries.push(promptText);
    return Promise.resolve(this.lines.shift() ?? null);
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

function mockServerFlows(): void {
  vi.mocked(api.recover).mockResolvedValue({
    uid: formatUid(UID),
    recovery_codes: FRESH_CODES,
  });
  vi.mocked(api.loginChallenge).mockResolvedValue({
    nonce: "ab".repeat(32),
    timestamp: 0,
    origin: "",
  });
  vi.mocked(api.loginVerify).mockResolvedValue({ token: "session-token" });
  vi.mocked(api.uploadSpk).mockResolvedValue(undefined);
  vi.mocked(api.uploadOpks).mockResolvedValue(undefined);
}

/** A store whose internally created databases (the /recover rebuild) use the
 * fast Argon2id parameters instead of the production §0 cost. */
function fastStore(name: string): KeyStore {
  return new KeyStore(name, new IDBFactory(), FAST);
}

function setup(store: KeyStore): { executor: Executor; shell: FakeShell; output: CaptureSink } {
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store);
  return { executor, shell, output };
}

async function runRecover(executor: Executor): Promise<void> {
  executor.handle(parseLine("/recover"));
  await executor.idle();
}

describe("/recover parsing", () => {
  it("parses /recover and resolves the /restore alias to it", () => {
    expect(parseLine("/recover")).toEqual({ kind: "command", command: { name: "recover" } });
    expect(parseLine("/restore")).toEqual({ kind: "command", command: { name: "recover" } });
  });

  it("rejects arguments", () => {
    expect(parseLine("/recover please").kind).toBe("invalid");
  });
});

describe("recovery-code normalization", () => {
  it("canonicalizes dashes, case, and Crockford ambiguity", () => {
    expect(normalizeRecoveryCode("7777-7777-7777-7777")).toBe("7777777777777777");
    expect(normalizeRecoveryCode("77o7 77I7 77l7 7777")).toBe("7707771777177777");
  });

  it("rejects wrong lengths and non-alphabet characters", () => {
    expect(normalizeRecoveryCode("7777")).toBeNull();
    expect(normalizeRecoveryCode("U".repeat(16))).toBeNull(); // U not in Crockford
  });
});

describe("/recover on a fresh device", () => {
  it("redeems the code, rebuilds the store, and prints the new code set once", async () => {
    vi.clearAllMocks();
    mockServerFlows();
    const store = fastStore("meridian-edge-recover-fresh");
    const { executor, shell, output } = setup(store);
    shell.lines = [` ${formatUid(UID).toLowerCase()} `]; // untrimmed, dashed, lowercase
    shell.secrets = [CODE_TYPED, "new passphrase!", "new passphrase!"];
    await runRecover(executor);

    // No destroy prompt on a device with no store.
    expect(shell.lineQueries).toEqual(["account UID: "]);
    expect(api.recover).toHaveBeenCalledTimes(1);
    const [sentUid, sentCode, sentKey] = vi.mocked(api.recover).mock.calls[0] ?? [];
    expect(sentUid).toBe(UID);
    expect(sentCode).toBe("7777777777777777");
    expect(sentKey).toBeInstanceOf(Uint8Array);
    expect((sentKey as Uint8Array).length).toBe(1952);

    const text = output.text();
    expect(text).toContain(`account recovered - your UID is ${formatUid(UID)}`);
    expect(text).toContain("NEW recovery codes");
    for (const code of FRESH_CODES) {
      expect(text).toContain(code);
    }
    expect(text).toContain("identity-key-change warning");
    expect(text).toContain("logged in");
    expect(api.uploadSpk).toHaveBeenCalledTimes(1);
    expect(api.uploadOpks).toHaveBeenCalledTimes(1);

    // The rebuilt store holds the recovered identity under the new passphrase.
    store.lock();
    expect(await store.unlock("new passphrase!")).toBe(true);
    const identity = await store.getJson<{ uid: string }>("identity");
    expect(identity?.uid).toBe(UID);
  });

  it("rejects a malformed code locally without calling the server", async () => {
    vi.clearAllMocks();
    mockServerFlows();
    const store = fastStore("meridian-edge-recover-badcode");
    const { executor, shell, output } = setup(store);
    shell.lines = [formatUid(UID)];
    shell.secrets = ["not-a-real-code"];
    await runRecover(executor);

    expect(output.text()).toContain("invalid recovery code");
    expect(api.recover).not.toHaveBeenCalled();
    expect(await store.exists()).toBe(false);
  });

  it("rejects a malformed UID locally without calling the server", async () => {
    vi.clearAllMocks();
    mockServerFlows();
    const store = fastStore("meridian-edge-recover-baduid");
    const { executor, shell, output } = setup(store);
    shell.lines = ["definitely-not-a-uid"];
    await runRecover(executor);

    expect(output.text()).toContain("invalid UID");
    expect(api.recover).not.toHaveBeenCalled();
  });
});

describe("/recover over an existing store", () => {
  async function storeWithIdentity(name: string): Promise<KeyStore> {
    const store = fastStore(name);
    await store.create("original passphrase", FAST);
    await store.putJson("identity", { uid: "B".repeat(26), pub: "cHVi", sec: "c2Vj" });
    return store;
  }

  it("requires an explicit yes and aborts untouched otherwise", async () => {
    vi.clearAllMocks();
    mockServerFlows();
    const store = await storeWithIdentity("meridian-edge-recover-decline");
    const { executor, shell, output } = setup(store);
    shell.lines = ["no"];
    await runRecover(executor);

    expect(shell.lineQueries).toEqual(["destroy the local store and recover? (yes/NO): "]);
    expect(output.text()).toContain("recovery cancelled - nothing was changed");
    expect(api.recover).not.toHaveBeenCalled();
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(true);
    expect((await store.getJson<{ uid: string }>("identity"))?.uid).toBe("B".repeat(26));
  });

  it("leaves the old store intact when the server rejects the code", async () => {
    vi.clearAllMocks();
    mockServerFlows();
    vi.mocked(api.recover).mockRejectedValue(new api.ApiError(401));
    const store = await storeWithIdentity("meridian-edge-recover-401");
    const { executor, shell, output } = setup(store);
    shell.lines = ["yes", formatUid(UID)];
    shell.secrets = [CODE_TYPED, "new passphrase!", "new passphrase!"];
    await runRecover(executor);

    expect(output.text()).toContain("recovery failed - unknown UID or invalid recovery code");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(true);
    expect((await store.getJson<{ uid: string }>("identity"))?.uid).toBe("B".repeat(26));
  });

  it("replaces the store only after the server accepts", async () => {
    vi.clearAllMocks();
    mockServerFlows();
    const store = await storeWithIdentity("meridian-edge-recover-replace");
    const { executor, shell, output } = setup(store);
    shell.lines = ["YES", formatUid(UID)]; // case-insensitive confirmation
    shell.secrets = [CODE_TYPED, "new passphrase!", "new passphrase!"];
    await runRecover(executor);

    expect(output.text()).toContain("account recovered");
    store.lock();
    expect(await store.unlock("original passphrase")).toBe(false);
    expect(await store.unlock("new passphrase!")).toBe(true);
    expect((await store.getJson<{ uid: string }>("identity"))?.uid).toBe(UID);
  });
});
