// Smoke test for the two-executor fixture (client/tests/helpers/two-executor.ts):
// two REAL Executor instances, each with its own IDBFactory-backed store and
// identity, registering against a shared mocked api and exchanging genuinely
// encrypted envelopes. Every other executor-*.test.ts hand-rolls its second
// "peer" with raw crypto calls (see makeBob() in executor-ratchet.test.ts);
// this file exists to prove the alternative - two full Executors - works for
// ordinary 1:1 messaging before the group tests (executor-groups.test.ts)
// lean on it for properties that only show up on a real receiving side.

import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../src/net/api";
import { addContact, createPeer, deliver, run, wireTwoPeerNetwork } from "./helpers/two-executor";

vi.mock("../src/net/api", async () => {
  const actual = await vi.importActual<typeof import("../src/net/api")>("../src/net/api");
  return {
    ApiError: actual.ApiError,
    register: vi.fn(),
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

/** Assert a value is present and hand it back narrowed - this project's lint
 * config forbids the `!` non-null assertion. */
function must<T>(value: T | undefined | null, label = "value"): T {
  expect(value, `expected ${label} to be defined`).toBeDefined();
  if (value === undefined || value === null) {
    throw new Error(`expected ${label} to be defined`);
  }
  return value;
}

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) {
      (fn as { mockReset: () => void }).mockReset();
    }
  }
});

describe("two real executors", () => {
  it("complete a KX handshake and exchange messages in both directions", async () => {
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");
    await run(bob, "/chat alice"); // focused, so the inbound message renders inline below

    // Alice has no session with bob yet: her first send is a real PQ-KX
    // first message, built from bob's REAL uploaded signed prekey (fetched
    // through the mocked network's bundle registry), not a hand-rolled one.
    await run(alice, "/chat bob hello bob");
    expect(outbox).toHaveLength(1);
    expect(alice.output.text()).toContain("PQ-KX handshake established with bob");

    // Delivered straight into bob's real processEnvelope: his real store
    // finds the matching spk secret, respondKx succeeds, and his ratchet
    // boots as responder.
    const ack = await deliver(bob, must(outbox[0]).envelope);
    expect(ack).toBe("ack");
    expect(bob.output.text()).toContain("[alice] hello bob");

    // Bob replies over his freshly-initialised ratchet - a genuine
    // second-message MSG envelope, not a KX.
    outbox.length = 0;
    await run(bob, "/chat alice hi alice");
    expect(outbox).toHaveLength(1);

    // Alice receives it through her own real trial-decrypt loop.
    await deliver(alice, must(outbox[0]).envelope);
    expect(alice.output.text()).toContain("[bob] hi alice");
  });

  it("stamps a delivered message, and redraws it from its stored time on toggle", async () => {
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");
    await run(bob, "/chat alice");

    await run(alice, "/chat bob what time is it");
    await deliver(bob, must(outbox[0]).envelope);

    // The stored record is where the replay reads its time from, so it is also
    // what the on-screen stamp has to match.
    const key = must((await bob.store.listKeys("msg/"))[0], "stored message key");
    const record = must(await bob.store.getJson<{ ts: number }>(key), "stored message");
    const at = new Date(record.ts);
    const pad = (n: number): string => n.toString().padStart(2, "0");
    const stamp = `${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`;

    // The live line is stamped from the clock at print time, a hair after the
    // record was written, so it is asserted as a time rather than as this
    // exact one - the two can legitimately straddle a second boundary.
    const live = must(
      bob.output.lines.filter((l) => l.includes("what time is it")).at(-1),
      "delivered line",
    );
    expect(live).toMatch(/\d{2}:\d{2}:\d{2}/);

    // Off: the same message is reprinted by the view rebuild, unstamped.
    let mark = bob.output.lines.length;
    await run(bob, "/settings timestamps off");
    const unstamped = must(
      bob.output.lines.slice(mark).filter((l) => l.includes("what time is it")).at(-1),
      "redrawn line",
    );
    expect(unstamped).not.toContain(stamp);

    // On again: the stamp comes back, and it is the message's own time rather
    // than the moment of the redraw.
    mark = bob.output.lines.length;
    await run(bob, "/settings timestamps on");
    const restamped = must(
      bob.output.lines.slice(mark).filter((l) => l.includes("what time is it")).at(-1),
      "redrawn line",
    );
    expect(restamped).toContain(stamp);
  });

  it("dates every day of a rebuilt conversation from the stored records", async () => {
    wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(bob, alice, "alice");

    // A week apart, written straight into the history the rebuild reads: what
    // is under test is the view rebuild, not delivery.
    const before = new Date(2026, 6, 4, 21, 30, 15).getTime();
    const after = new Date(2026, 6, 11, 9, 5, 7).getTime();
    await bob.store.putJson(`msg/${alice.uid}/${before}`, {
      dir: "in",
      text: "see you next week",
      ts: before,
    });
    await bob.store.putJson(`msg/${alice.uid}/${after}`, {
      dir: "out",
      text: "morning",
      ts: after,
    });

    await run(bob, "/chat alice");
    const text = bob.output.text();
    const firstDay = text.indexOf("-- Saturday, 4 July 2026 --");
    const secondDay = text.indexOf("-- Saturday, 11 July 2026 --");
    expect(firstDay, "the older day is dated").toBeGreaterThan(-1);
    expect(secondDay, "the newer day is dated").toBeGreaterThan(-1);
    // Each divider opens its own day: above the message it belongs to, below
    // the one before it.
    expect(firstDay).toBeLessThan(text.indexOf("see you next week"));
    expect(text.indexOf("see you next week")).toBeLessThan(secondDay);
    expect(secondDay).toBeLessThan(text.indexOf("morning"));
  });

  it("never delivers an envelope that the test does not hand to the other side", async () => {
    // The fixture does nothing automatically: this is what lets a test model
    // a message that never arrives (dropped, suppressed, peer offline).
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");

    await run(alice, "/chat bob never sent anywhere");
    expect(outbox).toHaveLength(1);
    // Deliberately not delivered.
    expect(bob.output.text()).not.toContain("never sent anywhere");
    expect(await bob.store.listKeys("msg/")).toEqual([]);
  });
});
