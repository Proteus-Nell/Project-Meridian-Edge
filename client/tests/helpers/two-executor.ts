// A pair of REAL Executor instances - own IDBFactory-backed store, own
// identity keypair, own uploaded prekeys - that register against a shared
// mocked ../src/net/api and can hand an envelope from one straight into the
// other's real receive pipeline.
//
// Every other executor-*.test.ts that needs "a peer" hand-rolls one with raw
// crypto calls (see makeBob() in executor-ratchet.test.ts / executor-
// lifecycle.test.ts): it runs respondKx/ratchetDecrypt directly rather than
// going through a second Executor. That is the right choice when the test is
// about Alice's side of the protocol and Bob is just there to read what she
// sent. It is the wrong choice for a test about what a *second real device*
// does with what it receives - a forged group sender, a roster carried on the
// very first (KX) message, a stale local roster after a suppressed removal
// notice - because those properties live in processEnvelope/applyIncomingGroup
// on the RECEIVING side, and a hand-rolled peer never calls that code.
//
// The test file must still declare its own `vi.mock("../src/net/api", ...)`:
// vi.mock is hoisted per-file and its factory path is resolved relative to
// the test, so it cannot be centralised here (see executor-harness.ts). Call
// `wireTwoPeerNetwork()` once per test (a fresh one each time - do not share
// across tests) to install the routing this module needs on top of that
// mock, then `createPeer()` for each side.

import { vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";

import * as api from "../../src/net/api";
import { KeyStore } from "../../src/crypto/store";
import type { Argon2Params } from "../../src/crypto/store";
import { Executor } from "../../src/terminal/executor";
import { processEnvelope } from "../../src/terminal/executor/messaging";
import { parseLine } from "../../src/terminal/parser";
import { Renderer } from "../../src/terminal/renderer";
import { toBase64 } from "../../src/util/base64";
import { CaptureSink, FakeChrome, FakeShell } from "./executor-harness";

/** Argon2 params fast enough to run in a test suite; matches the FAST params
 * every other executor-*.test.ts that creates a real store uses. */
export const FAST_ARGON2: Argon2Params = { mKib: 64, t: 1, p: 1 };

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
let uidCounter = 0;
/** A fresh, syntactically valid UID, distinct on every call. Every
 * executor-*.test.ts hand-rolls this same generator for its Bob peer; it is
 * centralised here since a peer pair needs two. */
export function nextPeerUid(): string {
  uidCounter += 1;
  let n = uidCounter;
  const tail: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    tail.unshift(CROCKFORD[n % CROCKFORD.length] ?? "0");
    n = Math.floor(n / CROCKFORD.length);
  }
  return "A".repeat(20) + tail.join("");
}

export interface Peer {
  readonly executor: Executor;
  readonly output: CaptureSink;
  readonly chrome: FakeChrome;
  readonly shell: FakeShell;
  readonly store: KeyStore;
  readonly uid: string;
}

/** One envelope handed to the mocked `sendMessage`, tagged with who sent it
 * and who it was addressed to (both real UIDs, recovered from the session
 * token). Nothing is delivered on its own - see `deliver` - so a test decides
 * exactly which envelopes reach their target. */
export interface OutboxEntry {
  readonly from: string;
  readonly to: string;
  readonly envelope: Uint8Array;
}

interface BundleParts {
  ikPub?: string;
  spkPub?: string;
  spkSig?: string;
}

function tokenFor(uid: string): string {
  return `tok-${uid}`;
}
function uidFromToken(token: string): string {
  return token.slice("tok-".length);
}

// Bridges wireTwoPeerNetwork()'s per-test registry to createPeer(), which is
// called separately for each side. Re-assigned (not mutated) by every
// wireTwoPeerNetwork() call, so tests never see a previous test's peers.
let currentBundleParts: Map<string, BundleParts> | null = null;

/** Install routing on the (already `vi.mock`ed) ../src/net/api surface so
 * that any Executors created with `createPeer` afterwards can register, fetch
 * each other's real uploaded prekey bundle, and exchange envelopes as two
 * real clients would against a real server.
 *
 * Returns the outbox `sendMessage` appends to. Call fresh in each test (or
 * `beforeEach`) - it replaces the mock implementations wholesale, so a stale
 * outbox from an earlier test is never read from by accident. */
export function wireTwoPeerNetwork(): { outbox: OutboxEntry[] } {
  const bundleParts = new Map<string, BundleParts>();
  currentBundleParts = bundleParts;
  const outbox: OutboxEntry[] = [];

  vi.mocked(api.loginChallenge).mockImplementation(() =>
    Promise.resolve({ nonce: "00".repeat(32), timestamp: 0, origin: "" }),
  );
  vi.mocked(api.loginVerify).mockImplementation((uid: string) =>
    Promise.resolve({ token: tokenFor(uid) }),
  );
  vi.mocked(api.uploadSpk).mockImplementation(
    (token: string, pub: Uint8Array, sig: Uint8Array) => {
      const uid = uidFromToken(token);
      const parts = bundleParts.get(uid) ?? {};
      bundleParts.set(uid, { ...parts, spkPub: toBase64(pub), spkSig: toBase64(sig) });
      return Promise.resolve();
    },
  );
  vi.mocked(api.uploadOpks).mockResolvedValue(undefined);
  vi.mocked(api.keysStatus).mockResolvedValue({ spk_uploaded_at: 0, opk_count: 50 });
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });
  vi.mocked(api.ackMessages).mockResolvedValue(undefined);
  // No one-time prekey: bundles here always carry opk: null, exactly like the
  // hand-rolled makeBob() peers in the other executor-*.test.ts files, so a
  // handshake through this fixture takes the same reduced-fs path they do.
  vi.mocked(api.fetchBundle).mockImplementation((_token: string, uid: string) => {
    const parts = bundleParts.get(uid);
    if (parts?.ikPub === undefined || parts.spkPub === undefined || parts.spkSig === undefined) {
      return Promise.reject(new api.ApiError(404));
    }
    return Promise.resolve({
      ik_pub: parts.ikPub,
      spk_pub: parts.spkPub,
      spk_sig: parts.spkSig,
      opk: null,
    });
  });
  vi.mocked(api.sendMessage).mockImplementation(
    (token: string, recipientUid: string, envelope: Uint8Array) => {
      outbox.push({ from: uidFromToken(token), to: recipientUid, envelope });
      return Promise.resolve();
    },
  );

  return { outbox };
}

/** Register one real Executor against the network `wireTwoPeerNetwork()` set
 * up. Its identity key and uploaded signed prekey are captured into the
 * shared bundle registry, so the OTHER peer's `fetchBundle` call returns
 * them exactly as a real server would. */
export async function createPeer(label = "peer"): Promise<Peer> {
  if (currentBundleParts === null) {
    throw new Error("wireTwoPeerNetwork() must be called before createPeer()");
  }
  const bundleParts = currentBundleParts;
  const uid = nextPeerUid();
  const output = new CaptureSink();
  const shell = new FakeShell();
  const chrome = new FakeChrome();
  const store = new KeyStore(
    `meridian-edge-pair-${label}-${Math.random()}`,
    new IDBFactory(),
    FAST_ARGON2,
  );
  const executor = new Executor(
    new Renderer(output, undefined, null, chrome),
    shell,
    store,
    undefined,
    chrome,
  );

  // register(ikPub) carries no uid yet (the server assigns it), so it cannot
  // be routed generically by token the way uploadSpk is; captured per call
  // instead, once, right before that call happens.
  vi.mocked(api.register).mockImplementationOnce((ikPub: Uint8Array) => {
    bundleParts.set(uid, { ikPub: toBase64(ikPub) });
    return Promise.resolve({ uid, recovery_codes: Array(10).fill("AAAA-AAAA") });
  });

  shell.secrets = ["a passphrase 12 chars!", "a passphrase 12 chars!"];
  executor.handle(parseLine("/register"));
  await executor.idle();

  return { executor, output, chrome, shell, store, uid };
}

/** Type a line into a peer's executor and wait for it (and any view rebuild
 * it enqueued) to settle. */
export async function run(peer: Peer, line: string): Promise<void> {
  peer.executor.handle(parseLine(line));
  await peer.executor.idle();
}

/** `/add` the other peer as a contact under `alias`. Purely local (no network
 * round trip), so both sides can do this before any message has been sent. */
export async function addContact(peer: Peer, other: Peer, alias: string): Promise<void> {
  await run(peer, `/add ${other.uid} ${alias}`);
}

/** Deliver one envelope straight into `to`'s real receive pipeline - the same
 * function its own inbox drain calls - then let any view rebuild it enqueued
 * settle. Nothing calls this automatically: a test names exactly which
 * envelopes get delivered, which is what makes "the peer never received the
 * removal notice" a normal thing to set up rather than a special case. */
export async function deliver(to: Peer, envelope: Uint8Array): Promise<"ack" | "skip"> {
  const result = await processEnvelope(to.executor, envelope);
  await to.executor.idle();
  return result;
}
