// The duress passphrase: arming it, disarming it, and what happens when it is
// typed at the /login prompt. Network is mocked; the store, prompts, and
// crypto are real.
//
// The properties worth failing a build over are the silent ones. A duress login
// must produce exactly the output a mistyped passphrase produces, must destroy
// the local store before it touches the network, and must still destroy it when
// the network is unreachable. Those are asserted directly rather than inferred.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import * as api from "../src/net/api";
import { KeyStore } from "../src/crypto/store";
import type { Argon2Params } from "../src/crypto/store";
import { Executor } from "../src/terminal/executor";
import { doLogin } from "../src/terminal/executor/identity";
import { formatUid, parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { CaptureSink, FakeChrome, FakeShell } from "./helpers/executor-harness";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return {
    ApiError: actual.ApiError,
    register: vi.fn(),
    recover: vi.fn(),
    loginChallenge: vi.fn(),
    loginVerify: vi.fn(),
    logout: vi.fn(),
    deleteAccount: vi.fn(),
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
const REAL = "correct horse battery1!";
const DURESS = "under the floorboards9!";

interface Harness {
  executor: Executor;
  shell: FakeShell;
  output: CaptureSink;
  chrome: FakeChrome;
  store: KeyStore;
  /** Kept so a test can read the raw records the way someone imaging the
   * database would, rather than through the store's own decrypting API. */
  factory: IDBFactory;
  dbName: string;
}

function setup(): Harness {
  const output = new CaptureSink();
  const shell = new FakeShell();
  const chrome = new FakeChrome();
  const factory = new IDBFactory();
  const dbName = `meridian-edge-duress-${Math.random()}`;
  const store = new KeyStore(dbName, factory, FAST);
  const executor = new Executor(new Renderer(output), shell, store, undefined, chrome);
  return { executor, shell, output, chrome, store, factory, dbName };
}

/** The stored (still encrypted) record at `key`, straight out of IndexedDB. */
async function rawRecord(h: Harness, key: string): Promise<{ ct: Uint8Array } | undefined> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = h.factory.open(h.dbName, 1);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexeddb error"));
  });
  try {
    const tx = db.transaction("vault", "readonly");
    return await new Promise<{ ct: Uint8Array } | undefined>((resolve, reject) => {
      const req = tx.objectStore("vault").get(key);
      req.onsuccess = () => resolve(req.result as { ct: Uint8Array } | undefined);
      req.onerror = () => reject(req.error ?? new Error("indexeddb error"));
    });
  } finally {
    db.close();
  }
}

async function run(h: Harness, line: string): Promise<void> {
  h.executor.handle(parseLine(line));
  await h.executor.idle();
}

/** A registered, logged-in device: real store, real identity keypair. */
async function register(h: Harness): Promise<void> {
  vi.mocked(api.register).mockResolvedValue({ uid: formatUid(UID), recovery_codes: ["CODE"] });
  vi.mocked(api.loginChallenge).mockResolvedValue({
    nonce: "ab".repeat(32),
    timestamp: 0,
    origin: "",
  });
  vi.mocked(api.loginVerify).mockResolvedValue({ token: "session-token" });
  vi.mocked(api.uploadSpk).mockResolvedValue(undefined);
  vi.mocked(api.uploadOpks).mockResolvedValue(undefined);
  vi.mocked(api.keysStatus).mockResolvedValue({ spk_uploaded_at: 1, opk_count: 50 });
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });
  h.shell.secrets.push(REAL, REAL);
  await run(h, "/register");
}

/** Arm the duress passphrase through the real command, confirmation and all. */
async function arm(h: Harness, passphrase = DURESS): Promise<void> {
  h.shell.lines.push("yes");
  h.shell.secrets.push(passphrase, passphrase);
  await run(h, "/duress set");
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("/duress parsing", () => {
  it("parses the three forms", () => {
    expect(parseLine("/duress set")).toEqual({
      kind: "command",
      command: { name: "duress-set" },
    });
    expect(parseLine("/duress off")).toEqual({
      kind: "command",
      command: { name: "duress-off" },
    });
    expect(parseLine("/duress status")).toEqual({
      kind: "command",
      command: { name: "duress-status" },
    });
  });

  it("rejects anything else", () => {
    for (const line of ["/duress", "/duress on", "/duress set now", "/duress off please"]) {
      expect(parseLine(line).kind, line).toBe("invalid");
    }
  });
});

describe("/duress set", () => {
  it("warns before anything is armed and requires a typed yes", async () => {
    const h = setup();
    await register(h);
    h.shell.lines.push("no");
    await run(h, "/duress set");

    const text = h.output.text();
    expect(text).toContain("[SECURITY]");
    expect(text).toContain("NO warning and NO confirmation");
    expect(text).toContain("not armed. Nothing was changed");
    // Declining leaves the passphrase prompts untouched and nothing sealed.
    expect(h.shell.secrets).toHaveLength(0);
    expect(await h.store.tryDuress(DURESS)).toBeNull();
  });

  it("arms it and reports it as armed", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    expect(h.output.text()).toContain("Duress passphrase armed");

    await run(h, "/duress status");
    expect(h.output.text()).toContain("ARMED");
  });

  it("refuses a duress passphrase that is the unlock passphrase", async () => {
    const h = setup();
    await register(h);
    h.shell.lines.push("yes");
    h.shell.secrets.push(REAL, REAL);
    await run(h, "/duress set");

    expect(h.output.text()).toContain("[E211]");
    expect(await h.store.tryDuress(REAL)).toBeNull();
    // And the real passphrase still just logs in.
    h.executor.lockLocal();
    expect(await h.store.unlock(REAL)).toBe(true);
  });

  it("applies the same strength rules as any other passphrase", async () => {
    const h = setup();
    await register(h);
    h.shell.lines.push("yes");
    h.shell.secrets.push("short1!");
    await run(h, "/duress set");
    expect(h.output.text()).toContain("[E206]");

    h.shell.lines.push("yes");
    h.shell.secrets.push("all lower case letters");
    await run(h, "/duress set");
    expect(h.output.text()).toContain("[E209]");
  });

  it("rejects a mismatched confirmation", async () => {
    const h = setup();
    await register(h);
    h.shell.lines.push("yes");
    h.shell.secrets.push(DURESS, "something else 9!");
    await run(h, "/duress set");
    expect(h.output.text()).toContain("[E207]");
    expect(await h.store.tryDuress(DURESS)).toBeNull();
  });

  it("needs an unlocked store", async () => {
    const h = setup();
    await register(h);
    h.executor.lockLocal();
    await run(h, "/duress set");
    expect(h.output.text()).toContain("[E406]");
  });

  it("reports 'not armed' by default", async () => {
    const h = setup();
    await register(h);
    await run(h, "/duress status");
    expect(h.output.text()).toContain("not armed");
  });
});

describe("the armed flag, as an imaged database sees it", () => {
  // IndexedDB key names are stored in the clear; only values are sealed. A
  // record written the first time /duress set ran would therefore tell anyone
  // with the raw database, and no passphrase at all, that this device
  // configured the feature - which is the single fact it exists to hide. These
  // two tests are the reason it is written at registration and at a fixed size.

  it("exists from registration on a device that has never touched the feature", async () => {
    const h = setup();
    await register(h);
    expect(await h.store.listKeys("settings/")).toContain("settings/duress");
  });

  it("is the same size at rest whether armed, disarmed, or never configured", async () => {
    const untouched = setup();
    await register(untouched);

    const armedH = setup();
    await register(armedH);
    await arm(armedH);

    const disarmed = setup();
    await register(disarmed);
    await arm(disarmed);
    await run(disarmed, "/duress off");

    const sizes = await Promise.all(
      [untouched, armedH, disarmed].map(async (h) => {
        const record = await rawRecord(h, "settings/duress");
        expect(record?.ct, "the record must be present in every state").toBeDefined();
        return record?.ct.length;
      }),
    );
    // XChaCha20-Poly1305 is length-preserving, so two JSON encodings differing
    // by one byte would leak the state the presence check no longer does.
    expect(new Set(sizes).size, `ciphertext lengths diverged: ${sizes.join(", ")}`).toBe(1);
    // And the flag still round-trips through the padded form.
    await run(armedH, "/duress status");
    expect(armedH.output.text()).toContain("ARMED");
    await run(disarmed, "/duress status");
    expect(disarmed.output.text()).toContain("not armed");
  });
});

describe("/duress off", () => {
  it("disarms so the passphrase becomes an ordinary wrong one", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    await run(h, "/duress off");
    expect(h.output.text()).toContain("disarmed");

    h.executor.lockLocal();
    h.shell.secrets.push(DURESS);
    await run(h, "/login");
    // Nothing was destroyed: the store is still there and still opens.
    expect(await h.store.exists()).toBe(true);
    expect(vi.mocked(api.deleteAccount)).not.toHaveBeenCalled();
  });
});

describe("a duress passphrase at the /login prompt", () => {
  it("destroys the local store and deletes the account", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    vi.mocked(api.deleteAccount).mockResolvedValue(undefined);

    h.executor.lockLocal();
    h.shell.secrets.push(DURESS);
    await run(h, "/login");

    expect(await h.store.exists()).toBe(false);
    expect(h.store.isUnlocked()).toBe(false);
    expect(vi.mocked(api.deleteAccount)).toHaveBeenCalledTimes(1);
    expect(h.executor.identity).toBeNull();
    expect(h.executor.token).toBeNull();
    expect(h.executor.contacts.size).toBe(0);
    expect(h.executor.active).toBeNull();
  });

  it("looks exactly like a mistyped passphrase", async () => {
    const armed = setup();
    await register(armed);
    await arm(armed);
    vi.mocked(api.deleteAccount).mockResolvedValue(undefined);
    armed.executor.lockLocal();
    armed.output.lines.length = 0;
    armed.shell.secrets.push(DURESS);
    await run(armed, "/login");

    const typo = setup();
    await register(typo);
    typo.executor.lockLocal();
    typo.output.lines.length = 0;
    typo.shell.secrets.push("just a typo 8!");
    await run(typo, "/login");

    // Same transcript, and no screen clear to give it away. Timestamps are
    // masked: the two runs are seconds apart on the wall clock, and the clock
    // is not what the property is about.
    const withoutClock = (text: string): string => text.replace(/\d\d:\d\d:\d\d/g, "HH:MM:SS");
    expect(withoutClock(armed.output.text())).toBe(withoutClock(typo.output.text()));
    expect(armed.output.text()).toContain("[E203] Unlock failed");
    expect(armed.chrome.clears).toBe(0);
  });

  it("still destroys the local store when the server is unreachable", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    vi.mocked(api.deleteAccount).mockRejectedValue(new api.ApiError(503));
    vi.mocked(api.loginChallenge).mockRejectedValue(new api.ApiError(503));

    h.executor.lockLocal();
    h.shell.secrets.push(DURESS);
    await run(h, "/login");

    // The irreversible part does not depend on the network, and the failure is
    // never reported.
    expect(await h.store.exists()).toBe(false);
    expect(h.output.text()).toContain("[E203] Unlock failed");
    expect(h.output.text()).not.toContain("[E302]");
    expect(h.output.text()).not.toContain("[E599]");
  });

  it("leaves the store alone for any other wrong passphrase", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    h.executor.lockLocal();
    h.shell.secrets.push("neither of them 5!");
    await run(h, "/login");

    expect(await h.store.exists()).toBe(true);
    expect(vi.mocked(api.deleteAccount)).not.toHaveBeenCalled();
    // And the real passphrase still works afterwards.
    expect(await h.store.unlock(REAL)).toBe(true);
  });

  it("is not triggered on an unarmed device", async () => {
    const h = setup();
    await register(h);
    h.executor.lockLocal();
    h.shell.secrets.push(DURESS);
    await run(h, "/login");
    expect(await h.store.exists()).toBe(true);
    expect(vi.mocked(api.deleteAccount)).not.toHaveBeenCalled();
  });
});

describe("/rotate passphrase", () => {
  it("refuses to rotate the unlock passphrase onto the armed duress one", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    h.shell.secrets.push(REAL, DURESS, DURESS);
    await run(h, "/rotate passphrase");

    expect(h.output.text()).toContain("[E211]");
    // Unchanged: the old passphrase still unlocks, the duress one still does not.
    h.executor.lockLocal();
    expect(await h.store.unlock(REAL)).toBe(true);
  });

  it("leaves the duress passphrase working after an ordinary rotation", async () => {
    const h = setup();
    await register(h);
    await arm(h);
    const next = "a different phrase 7?";
    h.shell.secrets.push(REAL, next, next);
    await run(h, "/rotate passphrase");
    expect(h.output.text()).toContain("Passphrase rotated");

    expect(await h.store.tryDuress(DURESS)).not.toBeNull();
    h.executor.lockLocal();
    expect(await h.store.unlock(next)).toBe(true);
  });
});

describe("S3 - doLogin's failure path prints E203 before the rejection hook finishes", () => {
  // Calls doLogin directly with a hand-built hook instead of going through
  // /login (which always wires the real maybeTriggerDuress), so the test can
  // hold the hook open and observe exactly what has already been rendered
  // when it starts - which is the property the fix is about, independent of
  // duress specifically. A duress trigger wipes the store and calls the
  // network before returning; if E203 were printed only after that finished,
  // a duress login would visibly take longer than an ordinary typo, which is
  // exactly the tell this feature exists not to have.
  it("has already rendered E203 by the time the hook is invoked, however long the hook takes", async () => {
    const h = setup();
    await register(h);
    h.executor.lockLocal();
    h.shell.secrets.push("not the real passphrase 4!");

    let textWhenHookStarted: string | null = null;
    let resolveInvoked!: () => void;
    const invoked = new Promise<void>((resolve) => {
      resolveInvoked = resolve;
    });
    let finishHook!: () => void;
    const hookWork = new Promise<void>((resolve) => {
      finishHook = resolve;
    });
    const hook = async (): Promise<void> => {
      // Runs synchronously up to this line the instant doLogin calls it, so
      // this snapshot reflects exactly what doLogin had already rendered
      // beforehand - no timing assumptions on the test's side required.
      textWhenHookStarted = h.output.text();
      resolveInvoked();
      await hookWork; // held open to prove E203 does not wait on this
    };

    const loginPromise = doLogin(h.executor, hook);
    await invoked;
    expect(textWhenHookStarted).not.toBeNull();
    expect(textWhenHookStarted).toContain("[E203] Unlock failed");

    finishHook();
    await loginPromise;
  });
});
