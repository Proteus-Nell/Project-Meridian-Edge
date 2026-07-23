// /remove and /rename (contacts.ts). Local-only operations: no network, so
// the api is mocked to inert and the real encrypted store carries the
// contacts, sessions, and message history the commands act on.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import { KeyStore } from "../src/crypto/store";
import type { Argon2Params } from "../src/crypto/store";
import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import type { LineSink } from "../src/terminal/renderer";
import type { ShellIO } from "../src/terminal/shell";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return { ApiError: actual.ApiError };
});

const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };
const UID_A = "A".repeat(26);
const UID_B = "B".repeat(26);

class FakeShell implements ShellIO {
  lines: (string | null)[] = [];
  prompts: string[] = [];
  readSecret(): Promise<string | null> {
    return Promise.resolve(null);
  }
  readLine(): Promise<string | null> {
    return Promise.resolve(this.lines.shift() ?? null);
  }
  setPrompt(p: string): void {
    this.prompts.push(p);
  }
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

interface Harness {
  executor: Executor;
  store: KeyStore;
  shell: FakeShell;
  output: CaptureSink;
}

async function harness(): Promise<Harness> {
  const store = new KeyStore("meridian-edge-contacts-test", new IDBFactory(), FAST);
  await store.create("passphrase!!", FAST); // unlocked
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store);
  return { executor, store, shell, output };
}

/** Seed a contact in the in-memory map plus its at-rest session and two
 * stored messages, the way a logged-in session would hold them. */
async function seed(
  h: Harness,
  uid: string,
  alias: string,
  extra: { pending?: boolean } = {},
): Promise<void> {
  h.executor.contacts.set(alias, {
    uid,
    alias,
    ik: "aWs=",
    verified: true,
    keyChangeBlocked: false,
    timerSeconds: null,
  });
  await h.store.putJson(`session/${uid}`, { ratchet: {}, peerIk: "x", reducedFs: false });
  await h.store.putJson(`msg/${uid}/1000`, { dir: "out", text: "hi", ts: 1000 });
  await h.store.putJson(`msg/${uid}/1001`, { dir: "in", text: "yo", ts: 1001 });
  if (extra.pending === true) {
    await h.store.putJson(`pending/${uid}`, { held: true });
  }
  await h.store.putJson("contacts", [...h.executor.contacts.values()]);
}

async function run(executor: Executor, line: string): Promise<void> {
  executor.handle(parseLine(line));
  await executor.idle();
}

describe("/remove single", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
    await seed(h, UID_A, "alice", { pending: true });
    await seed(h, UID_B, "bob");
  });

  it("removes the contact and session but keeps history by default", async () => {
    await run(h.executor, "/remove alice");

    expect(h.executor.contacts.has("alice")).toBe(false);
    expect(h.executor.contacts.has("bob")).toBe(true);
    expect(await h.store.getJson("session/" + UID_A)).toBeNull();
    expect(await h.store.getJson("pending/" + UID_A)).toBeNull();
    // History is retained unless purge is asked for.
    expect(await h.store.listKeys(`msg/${UID_A}/`)).toHaveLength(2);
    expect(h.output.text()).toContain("removed alice");
    expect(h.output.text()).toContain("message history kept");
    // Persisted: the stored contacts array no longer holds alice.
    const stored = await h.store.getJson<{ alias: string }[]>("contacts");
    expect(stored?.map((c) => c.alias)).toEqual(["bob"]);
  });

  it("also deletes history when 'purge' is given", async () => {
    await run(h.executor, "/remove alice purge");
    expect(await h.store.listKeys(`msg/${UID_A}/`)).toHaveLength(0);
    expect(h.output.text()).toContain("and its message history");
    // bob is untouched.
    expect(await h.store.listKeys(`msg/${UID_B}/`)).toHaveLength(2);
  });

  it("resolves by UID as well as alias", async () => {
    await run(h.executor, `/remove ${UID_B}`);
    expect(h.executor.contacts.has("bob")).toBe(false);
  });

  it("returns to home when the removed contact was the active one", async () => {
    await run(h.executor, "/chat bob");
    h.shell.prompts.length = 0;
    await run(h.executor, "/remove bob");
    expect(h.executor.active).toBeNull();
    expect(h.shell.prompts.at(-1)).toBe("> ");
  });

  it("leaves the active conversation intact when a different contact is removed", async () => {
    await run(h.executor, "/chat bob");
    await run(h.executor, "/remove alice");
    expect(h.executor.active?.uid).toBe(UID_B);
  });

  it("reports an unknown contact with E501", async () => {
    await run(h.executor, "/remove nobody");
    expect(h.output.text()).toContain("[E501]");
    expect(h.executor.contacts.size).toBe(2);
  });
});

describe("/remove all", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
    await seed(h, UID_A, "alice");
    await seed(h, UID_B, "bob");
  });

  it("clears every contact after a yes confirmation", async () => {
    h.shell.lines = ["yes"];
    await run(h.executor, "/remove all");
    expect(h.executor.contacts.size).toBe(0);
    expect(await h.store.getJson("session/" + UID_A)).toBeNull();
    expect(await h.store.getJson("session/" + UID_B)).toBeNull();
    // Default keeps history.
    expect(await h.store.listKeys(`msg/${UID_A}/`)).toHaveLength(2);
    expect(h.output.text()).toContain("removed all 2 contact(s)");
  });

  it("wipes history too with 'all purge'", async () => {
    h.shell.lines = ["yes"];
    await run(h.executor, "/remove all purge");
    expect(await h.store.listKeys(`msg/${UID_A}/`)).toHaveLength(0);
    expect(await h.store.listKeys(`msg/${UID_B}/`)).toHaveLength(0);
  });

  it("changes nothing when the confirmation is declined", async () => {
    h.shell.lines = ["no"];
    await run(h.executor, "/remove all");
    expect(h.executor.contacts.size).toBe(2);
    expect(await h.store.getJson("session/" + UID_A)).not.toBeNull();
    expect(h.output.text()).toContain("removal cancelled");
  });
});

describe("/rename", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
    await seed(h, UID_A, "alice");
    await seed(h, UID_B, "bob");
  });

  it("rekeys the contact and preserves its message history", async () => {
    await run(h.executor, "/rename alice ali");
    expect(h.executor.contacts.has("alice")).toBe(false);
    expect(h.executor.contacts.get("ali")?.uid).toBe(UID_A);
    // History is keyed by UID, so it is untouched by the rename.
    expect(await h.store.listKeys(`msg/${UID_A}/`)).toHaveLength(2);
    expect(h.output.text()).toContain("renamed alice to ali");
    const stored = await h.store.getJson<{ alias: string }[]>("contacts");
    expect(stored?.map((c) => c.alias).sort()).toEqual(["ali", "bob"]);
  });

  it("updates the active prompt when renaming the focused contact", async () => {
    await run(h.executor, "/chat alice");
    await run(h.executor, "/rename alice ali");
    expect(h.executor.active?.alias).toBe("ali");
    expect(h.shell.prompts.at(-1)).toBe("[ali] > ");
  });

  it("rejects a name already used by another contact with E510", async () => {
    await run(h.executor, "/rename alice bob");
    expect(h.output.text()).toContain("[E510]");
    expect(h.executor.contacts.has("alice")).toBe(true); // unchanged
  });

  it("no-ops when renaming to the current name", async () => {
    await run(h.executor, "/rename alice alice");
    expect(h.output.text()).toContain("already goes by that name");
  });

  it("reports an unknown contact with E501", async () => {
    await run(h.executor, "/rename nobody someone");
    expect(h.output.text()).toContain("[E501]");
  });
});
