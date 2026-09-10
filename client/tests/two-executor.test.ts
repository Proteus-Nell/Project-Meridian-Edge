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
import type { StoredMessage } from "../src/terminal/executor/records";
import { addContact, createPeer, deliver, run, wireTwoPeerNetwork } from "./helpers/two-executor";
import type { Peer } from "./helpers/two-executor";

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

/** Every stored one-to-one message on `peer`, keyed by its text. */
async function storedByText(peer: Peer): Promise<Map<string, StoredMessage>> {
  const out = new Map<string, StoredMessage>();
  for (const key of await peer.store.listKeys("msg/")) {
    const record = must(await peer.store.getJson<StoredMessage>(key), "stored message");
    out.set(record.text, record);
  }
  return out;
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

  it("dates a collected message from the sender's clock, not from the collection", async () => {
    // The reported bug, as its own timeline: Alice writes at 01:39 on Thursday
    // 3 September and Bob, offline, does not open the app until 17:25 on
    // Saturday the 5th. Before the send time travelled inside the payload,
    // every one of those queued messages was stamped with the moment the
    // inbox drained, so a two-day-old conversation read as though all of it
    // had happened at once, under a divider dated the wrong day.
    const { outbox } = wireTwoPeerNetwork();
    const SENT = new Date(2026, 8, 3, 1, 39, 12).getTime();
    const REPLIED = new Date(2026, 8, 3, 1, 41, 3).getTime();
    const COLLECTED = new Date(2026, 8, 5, 17, 25, 40).getTime();

    const aliceClock = { at: SENT };
    const bobClock = { at: COLLECTED };
    const alice = await createPeer("alice", () => aliceClock.at);
    const bob = await createPeer("bob", () => bobClock.at);
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");
    await run(bob, "/chat alice");

    // Two messages, because they take different paths in: the first is the
    // PQ-KX handshake, the second an ordinary ratchet MSG, and each carries
    // and parses the send time in its own code.
    await run(alice, "/chat bob are you awake");
    aliceClock.at = REPLIED;
    await run(alice, "still awake?");
    expect(outbox).toHaveLength(2);

    // Bob has been offline throughout; both envelopes drain into him now.
    for (const entry of outbox) {
      await deliver(bob, entry.envelope);
    }

    const stored = [];
    for (const key of (await bob.store.listKeys("msg/")).sort()) {
      stored.push(must(await bob.store.getJson<StoredMessage>(key), "stored message"));
    }
    expect(stored.map((r) => r.ts), "shown under the sender's clock").toEqual([SENT, REPLIED]);
    expect(
      stored.map((r) => r.receivedAt),
      "arrival kept alongside it, for the deadlines that must count from here",
    ).toEqual([COLLECTED, COLLECTED]);

    // Asserted on the conversation lines themselves, not the whole transcript:
    // Bob's own system events are stamped from his clock and legitimately read
    // 17:25:40, since they are things that really did happen at the drain.
    const line = (needle: string): string =>
      must(bob.output.lines.filter((l) => l.includes(needle)).at(-1), needle);
    expect(line("are you awake")).toContain("01:39:12");
    expect(line("still awake?")).toContain("01:41:03");
    expect(line("are you awake"), "not the moment it was collected").not.toContain("17:25:40");
    expect(line("still awake?"), "not the moment it was collected").not.toContain("17:25:40");

    const text = bob.output.text();
    expect(text).toContain("-- Thursday, 3 September 2026 --");
    expect(text, "no message happened on the day they were collected").not.toContain(
      "-- Saturday, 5 September 2026 --",
    );
  });

  it("bounds a peer whose clock is wrong in either direction", async () => {
    // The send time is authenticated as the peer's - it rides inside the
    // ratchet AEAD - but authenticated is not honest, and a peer whose clock
    // is wrong (or chosen) must not be able to pin a message to the top of the
    // transcript or backdate one out of the conversation.
    //
    // What bounds each direction is asserted at its exact boundary in
    // timestamps.test.ts; this is the end-to-end statement that both hold
    // through two real clients and a real ratchet.
    const { outbox } = wireTwoPeerNetwork();
    const COLLECTED = new Date(2026, 8, 5, 17, 25, 40).getTime();
    const DAY = 86_400_000;

    const aliceClock = { at: COLLECTED };
    const bobClock = { at: COLLECTED };
    const alice = await createPeer("alice", () => aliceClock.at);
    const bob = await createPeer("bob", () => bobClock.at);
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");

    // Establish the session while the two agree, so what follows is measuring
    // the clamp rather than a handshake.
    await run(alice, "/chat bob hello");
    await deliver(bob, must(outbox[0]).envelope);

    // Backdated first, so each assertion below names a different bound: the
    // floor for one, the ceiling for the other. Sent the other way round, the
    // fast message would raise the floor to the ceiling and both would land on
    // the same value, proving less.
    aliceClock.at = COLLECTED - 400 * DAY; // a clock years slow
    await run(alice, "from the past");
    aliceClock.at = COLLECTED + 400 * DAY; // and one years fast
    await run(alice, "from the future");
    await deliver(bob, must(outbox[1]).envelope);
    await deliver(bob, must(outbox[2]).envelope);

    const byText = await storedByText(bob);
    expect(
      must(byText.get("from the future")).ts,
      "a fast clock buys five minutes of skew allowance and no more",
    ).toBe(COLLECTED + 5 * 60_000);
    expect(
      must(byText.get("from the past")).ts,
      "and a slow one reaches back no further than the message that opened the session",
    ).toBe(COLLECTED);
  });

  it("runs a disappearing timer from arrival, so a queued message is not dead on arrival", async () => {
    // The trap in dating a message from the sender: a one-hour timer on a
    // message that spent two days in the queue would already have expired
    // before it was ever decrypted, and the purge that runs at the end of
    // delivery would sweep it before Bob could read it. Deadlines count from
    // arrival for exactly this reason.
    const { outbox } = wireTwoPeerNetwork();
    const SENT = new Date(2026, 8, 3, 1, 39, 12).getTime();
    const COLLECTED = new Date(2026, 8, 5, 17, 25, 40).getTime();

    const aliceClock = { at: SENT };
    const bobClock = { at: COLLECTED };
    const alice = await createPeer("alice", () => aliceClock.at);
    const bob = await createPeer("bob", () => bobClock.at);
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");
    await run(bob, "/chat alice");

    // Session first (the KX message carries no timer), then the timer, then
    // the message that has to survive the trip.
    await run(alice, "/chat bob hello");
    await deliver(bob, must(outbox[0]).envelope);
    await run(alice, "/timer bob 1h");
    await run(alice, "burn after reading");

    for (const entry of outbox.slice(1)) {
      await deliver(bob, entry.envelope);
    }

    const stored = [];
    for (const key of await bob.store.listKeys("msg/")) {
      stored.push(must(await bob.store.getJson<StoredMessage>(key), "stored message"));
    }
    const held = must(
      stored.find((r) => r.text === "burn after reading"),
      "the timed message survived delivery",
    );
    expect(held.ts, "still dated when it was written").toBe(SENT);
    expect(held.tmrExpiresAt, "but its hour starts when it got here").toBe(COLLECTED + 3_600_000);
    expect(bob.output.text()).toContain("burn after reading");
  });

  it("will not let a peer backdate a message below one it already sent", async () => {
    // The global clamp bounds how wrong any single message can be. It says
    // nothing about a peer reordering their OWN messages inside that window,
    // which the ratchet's counters can rule out: message n+1 cannot have been
    // written before message n.
    const { outbox } = wireTwoPeerNetwork();
    const BASE = new Date(2026, 8, 5, 12, 0, 0).getTime();
    const HOUR = 3_600_000;

    const aliceClock = { at: BASE };
    const bobClock = { at: BASE };
    const alice = await createPeer("alice", () => aliceClock.at);
    const bob = await createPeer("bob", () => bobClock.at);
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");
    await run(bob, "/chat alice");

    await run(alice, "/chat bob first");
    await deliver(bob, must(outbox[0]).envelope);
    await run(alice, "second");
    aliceClock.at = BASE - HOUR; // claiming the third was written before the first
    await run(alice, "third");

    await deliver(bob, must(outbox[1]).envelope);
    await deliver(bob, must(outbox[2]).envelope);

    const byText = await storedByText(bob);
    expect(must(byText.get("second")).ts).toBe(BASE);
    expect(
      must(byText.get("third")).ts,
      "floored to its predecessor rather than filed an hour earlier",
    ).toBe(BASE);
  });

  it("leaves a genuinely late message where it belongs, rather than dragging it forward", async () => {
    // The floor has to key off the ratchet's counters and not arrival order,
    // or bounded out-of-order delivery - which this ratchet supports - would be
    // clamped to the wrong times: a message overtaken in transit really did
    // come before the ones that passed it, and must keep its own time.
    const { outbox } = wireTwoPeerNetwork();
    const BASE = new Date(2026, 8, 5, 12, 0, 0).getTime();
    const MINUTE = 60_000;

    const aliceClock = { at: BASE };
    const bobClock = { at: BASE };
    const alice = await createPeer("alice", () => aliceClock.at);
    const bob = await createPeer("bob", () => bobClock.at);
    await addContact(alice, bob, "bob");
    await addContact(bob, alice, "alice");
    await run(bob, "/chat alice");

    await run(alice, "/chat bob one");
    await deliver(bob, must(outbox[0]).envelope);
    aliceClock.at = BASE + MINUTE;
    await run(alice, "two");
    aliceClock.at = BASE + 2 * MINUTE;
    await run(alice, "three");

    // "three" overtakes "two" in transit; "two" is delivered from the
    // skipped-key cache afterwards.
    await deliver(bob, must(outbox[2]).envelope);
    await deliver(bob, must(outbox[1]).envelope);

    const byText = await storedByText(bob);
    expect(must(byText.get("three")).ts).toBe(BASE + 2 * MINUTE);
    expect(
      must(byText.get("two")).ts,
      "late, so bounded by the global clamp alone and left at its own time",
    ).toBe(BASE + MINUTE);
    // And the transcript still reads in the order they were written, because
    // the view sorts on the stored time rather than on arrival.
    const text = bob.output.text();
    expect(text.indexOf("two")).toBeGreaterThan(-1);
    expect(must(byText.get("two")).ts).toBeLessThan(must(byText.get("three")).ts);
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
