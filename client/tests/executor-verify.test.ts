// Safety numbers & key-change teardown (-4.6).
// The network layer is mocked so these run offline; all crypto (ML-DSA
// signing/verification, ML-KEM keygen) is real.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import * as api from "../src/net/api";
import { generateSpk } from "../src/crypto/prekeys";
import { KeyStore } from "../src/crypto/store";
import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import { toBase64 } from "../src/util/base64";
import { CaptureSink, FakeShell } from "./helpers/executor-harness";

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


// Crockford Base32 excludes I, L, O, U - must build synthetic UIDs from its
// actual alphabet or normalizeUid() rejects them.
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
let uidCounter = 0;
function nextUid(): string {
  uidCounter += 1;
  let n = uidCounter;
  const tail: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    tail.unshift(CROCKFORD[n % CROCKFORD.length] ?? "0");
    n = Math.floor(n / CROCKFORD.length);
  }
  return "A".repeat(20) + tail.join(""); // 26 chars total, all valid
}

interface Rig {
  executor: Executor;
  shell: FakeShell;
  output: CaptureSink;
  store: KeyStore;
  uid: string;
}

async function bootstrap(): Promise<Rig> {
  const store = new KeyStore(`meridian-edge-verify-${Math.random()}`, new IDBFactory());
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store);

  const uid = nextUid();
  vi.mocked(api.register).mockResolvedValueOnce({ uid, recovery_codes: Array(10).fill("AAAA-AAAA") });
  vi.mocked(api.loginChallenge).mockResolvedValue({ nonce: "00".repeat(32), timestamp: 0, origin: "" });
  vi.mocked(api.loginVerify).mockResolvedValue({ token: "tok" });
  vi.mocked(api.uploadSpk).mockResolvedValue(undefined);
  vi.mocked(api.uploadOpks).mockResolvedValue(undefined);
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });

  shell.secrets = ["passphrase-123", "passphrase-123"];
  executor.handle(parseLine("/register"));
  await executor.idle();
  return { executor, shell, output, store, uid };
}

interface Peer {
  ikPub: Uint8Array;
  ikSec: Uint8Array;
  uid: string;
}

function makePeer(): Peer {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const keys = ml_dsa65.keygen(seed);
  return { ikPub: keys.publicKey, ikSec: keys.secretKey, uid: nextUid() };
}

function bundleFor(peer: Peer): api.WireBundle {
  const spk = generateSpk(peer.ikSec);
  return {
    ik_pub: toBase64(peer.ikPub),
    spk_pub: toBase64(spk.pub),
    spk_sig: toBase64(spk.sig),
    opk: null,
  };
}

/** Switch to strict manual verification (trust-on-first-use is the default). */
async function manualTrust(executor: Executor): Promise<void> {
  executor.handle(parseLine("/settings trust manual"));
  await executor.idle();
}

beforeEach(() => {
  vi.mocked(api.register).mockReset();
  vi.mocked(api.loginChallenge).mockReset();
  vi.mocked(api.loginVerify).mockReset();
  vi.mocked(api.uploadSpk).mockReset();
  vi.mocked(api.uploadOpks).mockReset();
  vi.mocked(api.fetchMessages).mockReset();
  vi.mocked(api.fetchBundle).mockReset();
  vi.mocked(api.sendMessage).mockReset();
});

describe("/verify and /verified", () => {
  it("prints a 12-group safety number and requires /verified to confirm", async () => {
    const { executor, output } = await bootstrap();
    const peer = makePeer();
    vi.mocked(api.fetchBundle).mockResolvedValue(bundleFor(peer));

    executor.handle(parseLine(`/add ${peer.uid} bob`));
    await executor.idle();
    executor.handle(parseLine("/verify bob"));
    await executor.idle();

    const text = output.text();
    expect(text).toContain("safety number with bob");
    // 12 groups of 5 digits across 3 printed rows of 4 groups each.
    const digitGroups = text.match(/\b\d{5}\b/g) ?? [];
    expect(digitGroups.length).toBeGreaterThanOrEqual(12);

    executor.handle(parseLine("/verified bob"));
    await executor.idle();
    expect(output.text()).toContain("bob marked verified");
  });

  it("/verified fails before /verify has cached a key", async () => {
    const { executor, output } = await bootstrap();
    const peer = makePeer();
    executor.handle(parseLine(`/add ${peer.uid} bob`));
    await executor.idle();

    executor.handle(parseLine("/verified bob"));
    await executor.idle();
    expect(output.text()).toContain("no known identity key");
  });

  it("/chat shows verified once confirmed, UNVERIFIED otherwise", async () => {
    const { executor, output } = await bootstrap();
    const peer = makePeer();
    vi.mocked(api.fetchBundle).mockResolvedValue(bundleFor(peer));
    executor.handle(parseLine(`/add ${peer.uid} bob`));
    await executor.idle();

    executor.handle(parseLine("/chat bob"));
    expect(output.text()).toContain("(UNVERIFIED)");

    executor.handle(parseLine("/verify bob"));
    await executor.idle();
    executor.handle(parseLine("/verified bob"));
    await executor.idle();
    executor.handle(parseLine("/chat bob"));
    expect(output.text()).toContain("(verified)");
  });
});

describe("key-change teardown", () => {
  it("detects a changed identity key during /verify, blocks, and requires /ack", async () => {
    const { executor, output } = await bootstrap();
    await manualTrust(executor); // strict flow: key change blocks until /ack
    const peerA = makePeer();
    const peerB = makePeer(); // stands in for a rotated/attacker key

    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerA));
    executor.handle(parseLine(`/add ${peerA.uid} bob`));
    await executor.idle();
    executor.handle(parseLine("/verify bob"));
    await executor.idle();
    executor.handle(parseLine("/verified bob"));
    await executor.idle();
    expect(output.text()).toContain("bob marked verified");

    // Server now returns a bundle signed by a DIFFERENT identity key for
    // the same UID - re-verifying must catch it, not silently accept it.
    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerB));
    executor.handle(parseLine("/verify bob"));
    await executor.idle();
    expect(output.text()).toContain("IDENTITY KEY CHANGED");

    // /verified refuses until acknowledged.
    executor.handle(parseLine("/verified bob"));
    await executor.idle();
    expect(output.text()).toContain("unacknowledged key change");

    executor.handle(parseLine("/ack bob"));
    await executor.idle();
    expect(output.text()).toContain("acknowledged");
    expect(output.text()).toContain("remains UNVERIFIED");

    // After ack, re-running /verify against the now-current key succeeds
    // and /verified can finally confirm it.
    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerB));
    executor.handle(parseLine("/verify bob"));
    await executor.idle();
    executor.handle(parseLine("/verified bob"));
    await executor.idle();
    expect(output.text()).toContain("bob marked verified");
  });

  it("blocks sending while a key change is unacknowledged", async () => {
    const { executor, output } = await bootstrap();
    await manualTrust(executor); // strict flow
    const peerA = makePeer();
    const peerB = makePeer();

    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerA));
    executor.handle(parseLine(`/add ${peerA.uid} bob`));
    await executor.idle();
    executor.handle(parseLine("/verify bob"));
    await executor.idle();

    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerB));
    vi.mocked(api.sendMessage).mockResolvedValue(undefined);
    executor.handle(parseLine("/chat bob"));
    executor.handle(parseLine("hello bob"));
    await executor.idle();
    expect(output.text()).toContain("IDENTITY KEY CHANGED");
    expect(api.sendMessage).not.toHaveBeenCalled();

    // Further attempts are blocked immediately, without even hitting the
    // network, until /ack.
    executor.handle(parseLine("hello again"));
    await executor.idle();
    expect(output.text()).toContain("sending to bob is blocked");
    expect(api.sendMessage).not.toHaveBeenCalled();

    executor.handle(parseLine("/ack bob"));
    await executor.idle();
    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerB));
    executor.handle(parseLine("hello once more"));
    await executor.idle();
    expect(api.sendMessage).toHaveBeenCalledTimes(1);
  });

  it("/ack is a no-op when nothing is blocked", async () => {
    const { executor, output } = await bootstrap();
    const peer = makePeer();
    executor.handle(parseLine(`/add ${peer.uid} bob`));
    await executor.idle();
    executor.handle(parseLine("/ack bob"));
    await executor.idle();
    expect(output.text()).toContain("nothing to acknowledge");
  });
});

describe("trust-on-first-use (default, /settings trust auto)", () => {
  it("auto-verifies a new contact's first key without /verified", async () => {
    const { executor, output } = await bootstrap();
    const peer = makePeer();
    vi.mocked(api.fetchBundle).mockResolvedValue(bundleFor(peer));

    executor.handle(parseLine(`/add ${peer.uid} bob`));
    await executor.idle();
    // /verify pins the key; auto-trust marks it verified on the spot.
    executor.handle(parseLine("/verify bob"));
    await executor.idle();
    executor.handle(parseLine("/chat bob"));
    expect(output.text()).toContain("(verified)");
  });

  it("auto-accepts a key change without blocking, dropping to UNVERIFIED", async () => {
    const { executor, output } = await bootstrap();
    const peerA = makePeer();
    const peerB = makePeer();

    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerA));
    executor.handle(parseLine(`/add ${peerA.uid} bob`));
    await executor.idle();
    executor.handle(parseLine("/verify bob"));
    await executor.idle();

    // Server swaps in a different key; auto-trust re-pins and lets the send go
    // through on the new key rather than blocking on /ack.
    vi.mocked(api.fetchBundle).mockResolvedValueOnce(bundleFor(peerB));
    vi.mocked(api.sendMessage).mockResolvedValue(undefined);
    executor.handle(parseLine("/chat bob"));
    executor.handle(parseLine("hello bob"));
    await executor.idle();
    expect(output.text()).toContain("IDENTITY KEY CHANGED");
    expect(output.text()).toContain("auto-accepted");
    expect(api.sendMessage).toHaveBeenCalledTimes(1);

    executor.handle(parseLine("/chat bob"));
    expect(output.text()).toContain("(UNVERIFIED)");
  });
});
