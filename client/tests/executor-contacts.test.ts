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
import { CaptureSink, FakeShell } from "./helpers/executor-harness";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return { ApiError: actual.ApiError };
});

const FAST: Argon2Params = { mKib: 64, t: 1, p: 1 };
const UID_A = "A".repeat(26);
const UID_B = "B".repeat(26);

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
  extra: { pending?: boolean; favourite?: boolean } = {},
): Promise<void> {
  h.executor.contacts.set(alias, {
    uid,
    alias,
    ik: "aWs=",
    verified: true,
    keyChangeBlocked: false,
    timerSeconds: null,
    favourite: extra.favourite ?? false,
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
    expect(h.output.text()).toContain("Removed alice");
    expect(h.output.text()).toContain("Message history was kept");
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
    expect(h.output.text()).toContain("Removed all 2 contact(s)");
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
    expect(h.output.text()).toContain("Removal cancelled");
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
    expect(h.output.text()).toContain("Renamed alice to ali");
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

describe("/favourite", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await harness();
    await seed(h, UID_A, "alice");
    await seed(h, UID_B, "bob");
  });

  it("marks a contact and persists it", async () => {
    await run(h.executor, "/favourite bob");
    expect(h.executor.contacts.get("bob")?.favourite).toBe(true);
    expect(h.output.text()).toContain("bob favourited");
    const stored = await h.store.getJson<{ alias: string; favourite: boolean }[]>("contacts");
    expect(stored?.find((c) => c.alias === "bob")?.favourite).toBe(true);
  });

  it("unmarks with 'off'", async () => {
    await run(h.executor, "/favourite bob");
    await run(h.executor, "/favourite bob off");
    expect(h.executor.contacts.get("bob")?.favourite).toBe(false);
    expect(h.output.text()).toContain("bob unfavourited");
  });

  it("accepts a UID as well as an alias", async () => {
    await run(h.executor, `/favourite ${UID_A}`);
    expect(h.executor.contacts.get("alice")?.favourite).toBe(true);
  });

  it("sorts favourites to the top of /contacts, alphabetical within each group", async () => {
    await seed(h, "C".repeat(26), "carol");
    await run(h.executor, "/favourite carol");
    h.output.lines.length = 0;
    await run(h.executor, "/contacts");

    const listed = h.output
      .text()
      .split("\n")
      .filter((line) => /^\s+[* ] (alice|bob|carol)\b/.test(line))
      .map((line) => line.trim());
    expect(listed[0]).toMatch(/^\* carol/);
    expect(listed[1]).toMatch(/^alice/);
    expect(listed[2]).toMatch(/^bob/);
  });

  it("sorts favourites to the top of the home dashboard too", async () => {
    // The dashboard only lists contacts for an identified, unlocked session.
    h.executor.identity = { uid: UID_A, pub: new Uint8Array(1), sec: new Uint8Array(1) };
    await run(h.executor, "/favourite bob");
    h.output.lines.length = 0;
    await run(h.executor, "/home");

    const listed = h.output
      .text()
      .split("\n")
      .filter((line) => /^\s+[* ] (alice|bob)\b/.test(line))
      .map((line) => line.trim());
    expect(listed[0]).toMatch(/^\* bob/);
    expect(listed[1]).toMatch(/^alice/);
  });

  it("survives a re-/add of the same contact", async () => {
    await run(h.executor, "/favourite bob");
    await run(h.executor, `/add ${UID_B} bob`);
    expect(h.executor.contacts.get("bob")?.favourite).toBe(true);
  });

  it("no-ops when already in the requested state", async () => {
    await run(h.executor, "/favourite bob off");
    expect(h.output.text()).toContain("is not a favourite");
    await run(h.executor, "/favourite bob");
    h.output.lines.length = 0;
    await run(h.executor, "/favourite bob");
    expect(h.output.text()).toContain("already a favourite");
  });

  it("reports an unknown contact with E501", async () => {
    await run(h.executor, "/favourite nobody");
    expect(h.output.text()).toContain("[E501]");
  });

  it("needs an unlocked store", async () => {
    h.store.lock();
    await run(h.executor, "/favourite bob");
    expect(h.output.text()).toContain("[E403]");
  });
});
