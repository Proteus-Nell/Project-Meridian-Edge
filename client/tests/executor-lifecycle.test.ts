// Message lifecycle (-5.3): mutual disappearing timer and local
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
import { formatUid, parseLine } from "../src/terminal/parser";
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

interface AppRecord {
  text: string | null;
  tmr: number;
  id: string | null;
  del: string[] | null;
  ds: boolean;
}

/** Bob reads a ratchet MSG and returns the executor app payload {m?, tmr, id?, del?, ds?}. */
function bobReceive(bob: Bob, msgEnvelope: Uint8Array): AppRecord {
  const body = decodeMsgEnvelope(msgEnvelope);
  if (body === null || bob.ratchet === null) {
    throw new Error("not a MSG / no ratchet");
  }
  const r = ratchetDecrypt(bob.ratchet, body);
  if (!r.ok) {
    throw new Error(`ratchetDecrypt failed: ${r.reason}`);
  }
  const parsed = JSON.parse(dec.decode(r.plaintext)) as {
    m?: string;
    tmr?: number;
    id?: string;
    del?: string[];
    ds?: boolean;
  };
  return {
    text: typeof parsed.m === "string" ? parsed.m : null,
    tmr: parsed.tmr ?? 0,
    id: typeof parsed.id === "string" ? parsed.id : null,
    del: Array.isArray(parsed.del) ? parsed.del : null,
    ds: parsed.ds === true,
  };
}

function bobSend(bob: Bob, text: string | null, tmr: number, mid?: string): Uint8Array {
  if (bob.ratchet === null) {
    throw new Error("no ratchet");
  }
  const record: { m?: string; tmr: number; id?: string } = { tmr };
  if (text !== null) {
    record.m = text;
  }
  if (mid !== undefined) {
    record.id = mid;
  }
  return encodeMsgEnvelope(ratchetEncrypt(bob.ratchet, enc.encode(JSON.stringify(record))));
}

/** Bob sends a cooperative delete directive for messages he had sent Alice. */
function bobSendDelete(bob: Bob, mids: string[], silent: boolean): Uint8Array {
  if (bob.ratchet === null) {
    throw new Error("no ratchet");
  }
  const record: { tmr: number; del: string[]; ds?: boolean } = { tmr: 0, del: mids };
  if (silent) {
    record.ds = true;
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
  const store = new KeyStore(`meridian-edge-life-${Math.random()}`, new IDBFactory());
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

interface StoredMsg {
  text: string;
  dir: "in" | "out";
  tmrExpiresAt?: number;
  mid?: string;
}

async function storedMessages(alice: Alice): Promise<StoredMsg[]> {
  const out: StoredMsg[] = [];
  for (const key of await alice.store.listKeys("msg/")) {
    const rec = await alice.store.getJson<StoredMsg>(key);
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

describe("mutual disappearing timer", () => {
  it("sets a timer, announces it, and propagates it to the peer", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi"); // KX first message
    bobReceiveKx(bob, sent[0] as Uint8Array);

    await run(alice, "/timer bob 1h");
    expect(alice.output.text()).toContain("Disappearing messages set to 1h for bob");

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

    // Advance past the deadline; the next send runs purgeExpired and sweeps it.
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
    expect(alice.output.text()).toContain("Disappearing messages turned off for bob");
    await run(alice, "permanent");
    const permanent = (await storedMessages(alice)).find((m) => m.text === "permanent");
    expect(permanent).toBeDefined();
    expect(permanent?.tmrExpiresAt).toBeUndefined();
  });
});

describe("local purge", () => {
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
    expect(alice.output.text()).toContain("Purged");
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

describe("/delete own messages, bilateral", () => {
  // Set up Alice with a live session to bob, kept in ratchet sync (bob decodes
  // each of Alice's sends), plus one incoming message from bob so we can prove
  // it survives deletion of Alice's own messages.
  async function withHistory(): Promise<{ alice: Alice; bob: Bob }> {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "first"); // KX first message (out)
    bobReceiveKx(bob, sent[0] as Uint8Array);
    alice.clock.now += 1000; // distinct msg/<uid>/<ts> keys
    await run(alice, "second");
    bobReceive(bob, sent[1] as Uint8Array);
    alice.clock.now += 1000;
    await run(alice, "third");
    bobReceive(bob, sent[2] as Uint8Array);
    // One incoming message from bob so we can prove it survives deletion.
    alice.clock.now += 1000;
    await deliverToAlice(alice, bobSend(bob, "from-bob", 0));
    return { alice, bob };
  }

  it("/delete last removes only your newest outgoing message", async () => {
    const { alice } = await withHistory();
    await run(alice, "/delete last");
    const texts = (await storedMessages(alice)).map((m) => m.text).sort();
    expect(texts).toEqual(["first", "from-bob", "second"]);
    expect(alice.output.text()).toContain("Deleted 1 of your message(s) with bob");
  });

  it("/delete N removes your newest N outgoing messages, leaving incoming intact", async () => {
    const { alice } = await withHistory();
    await run(alice, "/delete 2");
    const remaining = await storedMessages(alice);
    expect(remaining.filter((m) => m.dir === "out").map((m) => m.text)).toEqual(["first"]);
    expect(remaining.some((m) => m.text === "from-bob")).toBe(true);
  });

  it("/delete all removes every outgoing message in the conversation only", async () => {
    const { alice } = await withHistory();
    await run(alice, "/delete all");
    const remaining = await storedMessages(alice);
    expect(remaining.every((m) => m.dir === "in")).toBe(true);
    expect(remaining.map((m) => m.text)).toEqual(["from-bob"]);
  });

  it("/delete purge removes your outgoing messages across all conversations", async () => {
    const { alice } = await withHistory();
    // A second contact with its own outgoing message.
    const carol = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(carol.bundle);
    await run(alice, `/add ${carol.uid} carol`);
    await run(alice, "/chat carol");
    alice.clock.now += 1000;
    await run(alice, "hey-carol");

    await run(alice, "/delete purge");
    const remaining = await storedMessages(alice);
    expect(remaining.every((m) => m.dir === "in")).toBe(true);
    expect(remaining.map((m) => m.text)).toEqual(["from-bob"]);
  });

  it("/delete last /s deletes silently: no confirmation line, but the view still redraws", async () => {
    const { alice } = await withHistory();
    await run(alice, "/delete last /s");
    // The message is gone from storage...
    expect((await storedMessages(alice)).some((m) => m.text === "third")).toBe(false);
    // ...with no "deleted N message(s)" confirmation printed (that is what /s
    // suppresses). The screen is still redrawn so your own deleted line actually
    // disappears from view rather than lingering in the append-only transcript.
    expect(alice.output.text()).not.toContain("Deleted 1 of your message");
  });

  it("pushes a delete directive naming the same message id to the peer", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "first");
    bobReceiveKx(bob, sent[0] as Uint8Array);
    alice.clock.now += 1000;
    await run(alice, "second");
    bobReceive(bob, sent[1] as Uint8Array);
    const midSecond = (await storedMessages(alice)).find((m) => m.text === "second")?.mid;
    expect(midSecond).toBeDefined();

    await run(alice, "/delete last");
    // The latest thing on the wire is the delete-control message.
    const control = bobReceive(bob, sent[sent.length - 1] as Uint8Array);
    expect(control.text).toBeNull();
    expect(control.del).toEqual([midSecond]);
    expect(control.ds).toBe(false);
    expect((await storedMessages(alice)).some((m) => m.text === "second")).toBe(false);
  });

  it("removes a peer's messages when they send a delete directive, and announces it", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "first");
    bobReceiveKx(bob, sent[0] as Uint8Array);

    await deliverToAlice(alice, bobSend(bob, "keeper", 0, "mid-keep"));
    alice.clock.now += 1000;
    await deliverToAlice(alice, bobSend(bob, "gone", 0, "mid-gone"));
    expect(
      (await storedMessages(alice)).filter((m) => m.dir === "in").map((m) => m.text).sort(),
    ).toEqual(["gone", "keeper"]);

    await deliverToAlice(alice, bobSendDelete(bob, ["mid-gone"], false));
    const remaining = await storedMessages(alice);
    expect(remaining.some((m) => m.text === "gone")).toBe(false);
    expect(remaining.some((m) => m.text === "keeper")).toBe(true);
    expect(alice.output.text()).toContain("bob deleted 1 message");
  });

  it("honors a silent peer delete without any notice", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "first");
    bobReceiveKx(bob, sent[0] as Uint8Array);
    await deliverToAlice(alice, bobSend(bob, "quiet", 0, "mid-quiet"));

    const before = alice.output.lines.length;
    await deliverToAlice(alice, bobSendDelete(bob, ["mid-quiet"], true));
    const emitted = alice.output.lines.slice(before).join("\n");

    expect((await storedMessages(alice)).some((m) => m.text === "quiet")).toBe(false);
    // Silent: no "bob deleted N message(s)" notice anywhere.
    expect(alice.output.text()).not.toContain("deleted");
    // ...but the focused view is still redrawn, so the removed line actually
    // disappears from the recipient's screen instead of lingering in the
    // append-only transcript while it is already gone from the store.
    expect(emitted).toContain("conversation with bob");
    expect(emitted).not.toContain("quiet");
  });
});

describe("focused chat view & /home", () => {
  it("/chat switches into a focused conversation view with a header", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    expect(alice.output.text()).toContain("conversation with bob");
  });

  it("/contacts lists saved contacts with their UIDs and trust", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    const carol = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, `/add ${carol.uid} carol`);

    await run(alice, "/contacts");
    const text = alice.output.text();
    expect(text).toContain("Contacts (2)");
    expect(text).toContain("bob");
    expect(text).toContain(formatUid(bob.uid));
    expect(text).toContain(formatUid(carol.uid));
    expect(text).toContain("UNVERIFIED");
  });

  it("/contacts reports an empty list before any contact is added", async () => {
    const alice = await bootstrapAlice();
    await run(alice, "/contacts");
    expect(alice.output.text()).toContain("No contacts yet");
  });

  it("/return toggles between the last two screens and names where it went", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob"); // home -> chat bob (previous = home)
    await run(alice, "/home"); // chat bob -> home (previous = chat bob)

    let before = alice.output.lines.length;
    await run(alice, "/return"); // back to the bob conversation
    let out = alice.output.lines.slice(before).join("\n");
    expect(out).toContain("Returned to the conversation with bob");
    expect(out).toContain("conversation with bob"); // the focused view was rebuilt

    before = alice.output.lines.length;
    await run(alice, "/return"); // toggle forward to home again
    out = alice.output.lines.slice(before).join("\n");
    expect(out).toContain("Returned to home");
  });

  it("/return reports when there is no previous screen", async () => {
    const alice = await bootstrapAlice();
    await run(alice, "/return");
    expect(alice.output.text()).toContain("no previous screen");
  });

  it("/home renders the contacts dashboard", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/home");
    const after = alice.output.text();
    expect(after).toContain("home");
    expect(after).toContain("bob");
  });

  it("holds an off-screen message, surfaces it as unread on /home, and shows it on /chat", async () => {
    const alice = await bootstrapAlice();
    const bob = makeBob();
    const carol = makeBob();

    // Establish a live session bob<->alice (Alice sends the KX first message).
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await run(alice, `/add ${bob.uid} bob`);
    await run(alice, "/chat bob");
    await run(alice, "hi bob");
    bobReceiveKx(bob, sent[0] as Uint8Array);

    // Focus a different contact.
    vi.mocked(api.fetchBundle).mockResolvedValue(carol.bundle);
    await run(alice, `/add ${carol.uid} carol`);
    await run(alice, "/chat carol");
    const before = alice.output.lines.length;

    // Bob messages Alice while she is focused on carol: stored, but not appended
    // to the carol-focused transcript.
    await deliverToAlice(alice, bobSend(bob, "psst-offscreen", 0, "mid-off"));
    expect((await storedMessages(alice)).some((m) => m.text === "psst-offscreen")).toBe(true);
    expect(alice.output.lines.slice(before).join("\n")).not.toContain("psst-offscreen");

    // The home dashboard surfaces it as unread.
    await run(alice, "/home");
    expect(alice.output.text()).toContain("1 unread");

    // Opening bob's conversation shows the held message and clears the unread mark.
    await run(alice, "/chat bob");
    expect(alice.output.text()).toContain("psst-offscreen");
    const afterOpen = alice.output.lines.length;
    await run(alice, "/home");
    expect(alice.output.lines.slice(afterOpen).join("\n")).not.toContain("unread");
  });
});
