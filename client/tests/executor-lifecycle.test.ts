// Message lifecycle (CLAUDE.md §5.1-5.3): mutual disappearing timer and local
// purge. Alice is a real Executor with an injectable clock; Bob is a crypto-peer
// that runs the handshake + ratchet directly and speaks the executor's app
// payload ({m?, tmr}), so both the send and receive timer paths are exercised.
// The mutual timer is symmetric code, so "fires on both clients" is covered by
// driving Alice as sender (Bob reads the tmr) and as receiver (Bob sets it).

import { beforeEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import * as api from "../src/net/api";
import { generateSpk } from "../src/crypto/prekeys";
import { respondKx } from "../src/crypto/kx";
import type { PrekeyLookup } from "../src/crypto/kx";
import { initRatchet, ratchetDecrypt, ratchetEncrypt } from "../src/crypto/ratchet";
import type { RatchetState } from "../src/crypto/ratchet";
import { decodeMsgEnvelope, encodeMsgEnvelope } from "../src/crypto/envelope";
import { KeyStore } from "../src/crypto/store";
import { Executor } from "../src/terminal/executor";
import { parseLine } from "../src/terminal/parser";
import { Renderer } from "../src/terminal/renderer";
import type { LineSink } from "../src/terminal/renderer";
import type { ShellIO } from "../src/terminal/shell";
import { toBase64 } from "../src/util/base64";

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

class FakeShell implements ShellIO {
  secrets: (string | null)[] = [];
  readSecret(): Promise<string | null> {
    return Promise.resolve(this.secrets.shift() ?? null);
  }
  readLine(): Promise<string | null> {
    return Promise.resolve(null);
  }
  setPrompt(): void {}
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
  return "A".repeat(20) + tail.join("");
}

const enc = new TextEncoder();
const dec = new TextDecoder();

interface Bob {
  ikPub: Uint8Array;
  uid: string;
  bundle: api.WireBundle;
  lookup: PrekeyLookup;
  ratchet: RatchetState | null;
}

function makeBob(): Bob {
  const keys = ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const spk = generateSpk(keys.secretKey);
  const spkHash = bytesToHex(sha512(spk.pub));
  const lookup: PrekeyLookup = {
    spkByHash: (h) => (h === spkHash ? { pub: spk.pub, sec: spk.sec, storeKey: "spk/1" } : null),
    opkByHash: () => null,
  };
  return {
    ikPub: keys.publicKey,
    uid: nextUid(),
    bundle: {
      ik_pub: toBase64(keys.publicKey),
      spk_pub: toBase64(spk.pub),
      spk_sig: toBase64(spk.sig),
      opk: null,
    },
    lookup,
    ratchet: null,
  };
}

function bobReceiveKx(bob: Bob, kxEnvelope: Uint8Array): void {
  const res = respondKx(bob.ikPub, bob.lookup, kxEnvelope);
  if (!res.ok) {
    throw new Error(`respondKx failed: ${res.reason}`);
  }
  bob.ratchet = initRatchet(res.session.rk, res.session.role);
}

/** Bob reads a ratchet MSG and returns the executor app payload {m?, tmr}. */
function bobReceive(bob: Bob, msgEnvelope: Uint8Array): { text: string | null; tmr: number } {
  const body = decodeMsgEnvelope(msgEnvelope);
  if (body === null || bob.ratchet === null) {
    throw new Error("not a MSG / no ratchet");
  }
  const r = ratchetDecrypt(bob.ratchet, body);
  if (!r.ok) {
    throw new Error(`ratchetDecrypt failed: ${r.reason}`);
  }
  const parsed = JSON.parse(dec.decode(r.plaintext)) as { m?: string; tmr?: number };
  return { text: typeof parsed.m === "string" ? parsed.m : null, tmr: parsed.tmr ?? 0 };
}

function bobSend(bob: Bob, text: string | null, tmr: number): Uint8Array {
  if (bob.ratchet === null) {
    throw new Error("no ratchet");
  }
  const record: { m?: string; tmr: number } = { tmr };
  if (text !== null) {
    record.m = text;
  }
  return encodeMsgEnvelope(ratchetEncrypt(bob.ratchet, enc.encode(JSON.stringify(record))));
}

interface Alice {
  executor: Executor;
  output: CaptureSink;
  store: KeyStore;
  clock: { now: number };
}

const sent: Uint8Array[] = [];

async function bootstrapAlice(): Promise<Alice> {
  const clock = { now: 1_000_000 };
  const store = new KeyStore(`pqterm-life-${Math.random()}`, new IDBFactory());
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store, () => clock.now);

  const uid = nextUid();
  vi.mocked(api.register).mockResolvedValueOnce({ uid, recovery_codes: Array(10).fill("AAAA-AAAA") });
  vi.mocked(api.loginChallenge).mockResolvedValue({ nonce: "00".repeat(32), timestamp: 0, origin: "" });
  vi.mocked(api.loginVerify).mockResolvedValue({ token: "tok" });
  vi.mocked(api.uploadSpk).mockResolvedValue(undefined);
  vi.mocked(api.uploadOpks).mockResolvedValue(undefined);
  vi.mocked(api.keysStatus).mockResolvedValue({ spk_uploaded_at: 0, opk_count: 50 });
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });
  vi.mocked(api.ackMessages).mockResolvedValue(undefined);
  vi.mocked(api.sendMessage).mockImplementation((_t, _to, envelope) => {
    sent.push(envelope);
    return Promise.resolve();
  });

  shell.secrets = ["passphrase-123", "passphrase-123"];
  executor.handle(parseLine("/register"));
  await executor.idle();
  return { executor, output, store, clock };
}

async function run(alice: Alice, line: string): Promise<void> {
  alice.executor.handle(parseLine(line));
  await alice.executor.idle();
}

async function deliverToAlice(alice: Alice, envelope: Uint8Array): Promise<void> {
  vi.mocked(api.fetchMessages).mockResolvedValueOnce({
    messages: [{ id: 1, envelope: toBase64(envelope) }],
  });
  alice.executor.handle(parseLine("/login"));
  await alice.executor.idle();
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });
}

async function storedMessages(alice: Alice): Promise<{ text: string; tmrExpiresAt?: number }[]> {
  const out: { text: string; tmrExpiresAt?: number }[] = [];
  for (const key of await alice.store.listKeys("msg/")) {
    const rec = await alice.store.getJson<{ text: string; tmrExpiresAt?: number }>(key);
    if (rec !== null) {
      out.push(rec);
    }
  }
  return out;
}

beforeEach(() => {
  sent.length = 0;
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) {
      (fn as { mockReset: () => void }).mockReset();
    }
  }
});

const HOUR_MS = 60 * 60 * 1000;

describe("mutual disappearing timer (§5.2)", () => {
  it("sets a timer, announces it, and propagates it to the peer", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi"); // KX first message
    bobReceiveKx(bob, sent[0] as Uint8Array);

    await run(alice, "/timer bob 1h");
    expect(alice.output.text()).toContain("disappearing messages set to 1h for bob");

    // The timer control message reached Bob carrying tmr=3600.
    const control = bobReceive(bob, sent[1] as Uint8Array);
    expect(control.text).toBeNull();
    expect(control.tmr).toBe(3600);

    // A subsequent message is stamped with an expiry an hour out.
    await run(alice, "vanishing");
    const msgs = await storedMessages(alice);
    const vanishing = msgs.find((m) => m.text === "vanishing");
    expect(vanishing?.tmrExpiresAt).toBe(alice.clock.now + HOUR_MS);
  });

  it("adopts and announces a timer the peer sets, and stamps stored messages", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi");
    bobReceiveKx(bob, sent[0] as Uint8Array);

    // Bob turns on a 1h timer and sends a message under it.
    await deliverToAlice(alice, bobSend(bob, "tick", 3600));
    expect(alice.output.text()).toContain("bob set disappearing messages to 1h");
    const msgs = await storedMessages(alice);
    const tick = msgs.find((m) => m.text === "tick");
    expect(tick?.tmrExpiresAt).toBe(alice.clock.now + HOUR_MS);
  });

  it("sweeps expired messages once the clock passes the deadline", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi");
    bobReceiveKx(bob, sent[0] as Uint8Array);
    await run(alice, "/timer bob 1h");
    await run(alice, "ephemeral");
    expect((await storedMessages(alice)).some((m) => m.text === "ephemeral")).toBe(true);

    // Advance past the deadline; the next send runs purgeExpired and sweeps it (§5.2).
    alice.clock.now += HOUR_MS + 1;
    await run(alice, "trigger");
    const remaining = await storedMessages(alice);
    expect(remaining.some((m) => m.text === "ephemeral")).toBe(false);
  });

  it("turns the timer off again", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi");
    bobReceiveKx(bob, sent[0] as Uint8Array);
    await run(alice, "/timer bob 1d");
    await run(alice, "/timer bob off");
    expect(alice.output.text()).toContain("disappearing messages turned off for bob");
    await run(alice, "permanent");
    const permanent = (await storedMessages(alice)).find((m) => m.text === "permanent");
    expect(permanent).toBeDefined();
    expect(permanent?.tmrExpiresAt).toBeUndefined();
  });
});

describe("local purge (§5.3)", () => {
  it("/purge now [alias] deletes stored messages for one conversation", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi");
    alice.clock.now += 1000; // distinct msg/<uid>/<ts> keys
    await run(alice, "there");
    expect((await storedMessages(alice)).length).toBeGreaterThanOrEqual(2);

    await run(alice, "/purge now bob");
    expect(alice.output.text()).toContain("purged");
    expect(await storedMessages(alice)).toHaveLength(0);
  });

  it("/purge set caps retention and evicts older messages immediately", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "old");

    // Cap at 1h, then jump forward 2h and set the same cap again to trigger a sweep.
    await run(alice, "/purge set 1h");
    expect((await storedMessages(alice)).some((m) => m.text === "old")).toBe(true);
    alice.clock.now += 2 * HOUR_MS;
    await run(alice, "/purge set 1h");
    expect((await storedMessages(alice)).some((m) => m.text === "old")).toBe(false);
  });
});
