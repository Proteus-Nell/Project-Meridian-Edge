// /whoami and the copy button beside its UID: which line is offered one, what
// it would copy, and that every button goes when the store locks.

import { beforeEach, describe, expect, it, vi } from "vitest";

import { formatUid } from "../src/terminal/parser";
import { createPeer, run, wireTwoPeerNetwork } from "./helpers/two-executor";

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

beforeEach(() => {
  vi.clearAllMocks();
  wireTwoPeerNetwork();
});

describe("/whoami copy button", () => {
  it("offers the UID exactly as the line prints it", async () => {
    const alice = await createPeer("alice");
    await run(alice, "/whoami");

    const uid = formatUid(alice.uid);
    expect(alice.output.text()).toContain(`UID: ${uid}`);
    expect(alice.chrome.copyOffers).toHaveLength(1);
    expect(alice.chrome.copyOffers[0]).toMatchObject({ value: uid, label: "UID" });
  });

  it("offers nothing for the fingerprint, which is for comparing, not pasting", async () => {
    const alice = await createPeer("alice");
    await run(alice, "/whoami");
    expect(alice.output.text()).toContain("identity-key fingerprint");
    expect(alice.chrome.copyOffers.map((offer) => offer.label)).toEqual(["UID"]);
  });

  it("withdraws every copy button when the store locks", async () => {
    const alice = await createPeer("alice");
    await run(alice, "/whoami");
    const before = alice.chrome.copyWithdrawals;
    await run(alice, "/lock");
    expect(alice.chrome.copyWithdrawals).toBe(before + 1);
  });

  it("offers nothing while locked", async () => {
    const alice = await createPeer("alice");
    await run(alice, "/lock");
    await run(alice, "/whoami");
    expect(alice.chrome.copyOffers).toEqual([]);
    expect(alice.output.text()).toContain("Locked or not registered.");
  });
});
