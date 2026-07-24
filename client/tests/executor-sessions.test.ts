// /sessions and /logout all through the executor. The network layer is mocked;
// the focus is that the commands gate on being logged in, format the listing,
// and report the revoke count.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import * as api from "../src/net/api";
import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { KeyStore } from "../src/crypto/store";
import { CaptureSink, FakeShell } from "./helpers/executor-harness";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return {
    ApiError: actual.ApiError,
    register: vi.fn(),
    loginChallenge: vi.fn(),
    loginVerify: vi.fn(),
    logout: vi.fn(),
    logoutAll: vi.fn(),
    sessions: vi.fn(),
    uploadSpk: vi.fn(),
    uploadOpks: vi.fn(),
    fetchMessages: vi.fn(),
  };
});

interface Rig {
  executor: Executor;
  output: CaptureSink;
}

/** A logged-out executor (no token, but a usable store is not even needed). */
function loggedOut(): Rig {
  const store = new KeyStore(`meridian-edge-sess-${Math.random()}`, new IDBFactory());
  const output = new CaptureSink();
  const executor = new Executor(new Renderer(output), new FakeShell(), store);
  return { executor, output };
}

/** A logged-in executor: register through the mocked api, which lands a token. */
async function loggedIn(): Promise<Rig> {
  const store = new KeyStore(`meridian-edge-sess-${Math.random()}`, new IDBFactory());
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store);

  vi.mocked(api.register).mockResolvedValueOnce({
    uid: "A".repeat(26),
    recovery_codes: Array(10).fill("AAAA-AAAA"),
  });
  vi.mocked(api.loginChallenge).mockResolvedValue({ nonce: "00".repeat(32), timestamp: 0, origin: "" });
  vi.mocked(api.loginVerify).mockResolvedValue({ token: "tok" });
  vi.mocked(api.uploadSpk).mockResolvedValue(undefined);
  vi.mocked(api.uploadOpks).mockResolvedValue(undefined);
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });

  shell.secrets = ["passphrase-1234!", "passphrase-1234!"];
  executor.handle(parseLine("/register"));
  await executor.idle();
  return { executor, output };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("/sessions", () => {
  it("requires being logged in", async () => {
    const { executor, output } = loggedOut();
    executor.handle(parseLine("/sessions"));
    await executor.idle();
    expect(output.text()).toContain("[E201]");
    expect(api.sessions).not.toHaveBeenCalled();
  });

  it("lists sessions, marking the current device and offering /logout all", async () => {
    const { executor, output } = await loggedIn();
    vi.mocked(api.sessions).mockResolvedValue({
      sessions: [
        { age_seconds: 30, idle_seconds: 0, current: true },
        { age_seconds: 172800, idle_seconds: 3600, current: false },
      ],
    });
    executor.handle(parseLine("/sessions"));
    await executor.idle();
    const text = output.text();
    expect(text).toContain("2 active sessions");
    expect(text).toContain("this device: started moments ago, active now");
    expect(text).toContain("another device: started 2d ago, idle 1h");
    expect(text).toContain("/logout all");
  });

  it("does not suggest /logout all when there is only one session", async () => {
    const { executor, output } = await loggedIn();
    vi.mocked(api.sessions).mockResolvedValue({
      sessions: [{ age_seconds: 10, idle_seconds: 0, current: true }],
    });
    executor.handle(parseLine("/sessions"));
    await executor.idle();
    const text = output.text();
    expect(text).toContain("1 active session");
    expect(text).not.toContain("sign out the others");
  });
});

describe("/logout all", () => {
  it("requires being logged in", async () => {
    const { executor, output } = loggedOut();
    executor.handle(parseLine("/logout all"));
    await executor.idle();
    expect(output.text()).toContain("[E201]");
    expect(api.logoutAll).not.toHaveBeenCalled();
  });

  it("reports how many other sessions were signed out and stays logged in", async () => {
    const { executor, output } = await loggedIn();
    vi.mocked(api.logoutAll).mockResolvedValue({ revoked: 3 });
    executor.handle(parseLine("/logout all"));
    await executor.idle();
    expect(output.text()).toContain("signed out 3 other sessions - this device stays logged in");
    // Plain logout was not used: the current session survives.
    expect(api.logout).not.toHaveBeenCalled();
  });

  it("uses the singular form for exactly one other session", async () => {
    const { executor, output } = await loggedIn();
    vi.mocked(api.logoutAll).mockResolvedValue({ revoked: 1 });
    executor.handle(parseLine("/logout all"));
    await executor.idle();
    expect(output.text()).toContain("signed out 1 other session -");
  });

  it("says so when there is nothing else to sign out", async () => {
    const { executor, output } = await loggedIn();
    vi.mocked(api.logoutAll).mockResolvedValue({ revoked: 0 });
    executor.handle(parseLine("/logout all"));
    await executor.idle();
    expect(output.text()).toContain("only active device");
  });

  it("plain /logout still logs this device out (does not call logoutAll)", async () => {
    const { executor } = await loggedIn();
    vi.mocked(api.logout).mockResolvedValue(undefined);
    executor.handle(parseLine("/logout"));
    await executor.idle();
    expect(api.logout).toHaveBeenCalledTimes(1);
    expect(api.logoutAll).not.toHaveBeenCalled();
  });
});
