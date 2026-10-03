// A send the server refuses because the recipient's queue is at its byte cap
// (507 queue_full): the sender has to be told it did not go, and why, rather
// than see it fail as though the server were down.

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

/** What the server answers a send once the recipient's queue is at its cap. */
const QUEUE_FULL = 507;

beforeEach(() => {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) {
      (fn as { mockReset: () => void }).mockReset();
    }
  }
});

describe("a recipient whose queue is full", () => {
  it("fails the send with E305 and a failed tick, and records nothing as sent", async () => {
    wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    await addContact(alice, bob, "bob");

    vi.mocked(api.sendMessage).mockRejectedValueOnce(new api.ApiError(QUEUE_FULL));
    await run(alice, "/chat bob are you there");

    const text = alice.output.text();
    expect(text).toContain("[E305]");
    expect(text).toContain("too many messages waiting on the server");
    expect(text).not.toContain("[E302]");
    expect(alice.chrome.rejects).toBe(1);
    expect(alice.chrome.confirms).toBe(0);
    expect(await alice.store.listKeys("msg/")).toEqual([]);
  });

  it("names the member it could not reach in a group, with the reason", async () => {
    const { outbox } = wireTwoPeerNetwork();
    const alice = await createPeer("alice");
    const bob = await createPeer("bob");
    const carol = await createPeer("carol");
    await addContact(alice, bob, "bob");
    await addContact(alice, carol, "carol");
    await addContact(bob, alice, "alice");
    await addContact(carol, alice, "alice");
    await run(alice, "/group new team bob carol");
    for (const entry of outbox) {
      await deliver(entry.to === bob.uid ? bob : carol, entry.envelope);
    }
    outbox.length = 0;

    // Bob's queue is the full one; Carol's still has room.
    const deliverToOutbox = vi.mocked(api.sendMessage).getMockImplementation();
    vi.mocked(api.sendMessage).mockImplementation((token, recipient, envelope) =>
      recipient === bob.uid
        ? Promise.reject(new api.ApiError(QUEUE_FULL))
        : (deliverToOutbox?.(token, recipient, envelope) ?? Promise.resolve()),
    );
    await run(alice, "/group open team");
    await run(alice, "hello team");

    const text = alice.output.text();
    expect(text).toContain(
      "Not delivered to: bob (too many messages waiting for them on the server).",
    );
    expect(text).toContain("reached 1 of 2 members");
    expect(outbox.map((entry) => entry.to)).toEqual([carol.uid]);
  });
});
