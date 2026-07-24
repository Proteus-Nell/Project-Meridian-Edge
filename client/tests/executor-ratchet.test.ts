// Ratchet integration through the executor: a registered Alice
// (real Executor + encrypted store) converses with a Bob crypto-peer that runs
// the handshake and ratchet directly. Exercises the KX→ratchet handoff, the
// serialize→store→deserialize round trip on every send, and the trial-decrypt
// routing on receive. The network layer is mocked; all crypto is real.

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
import { toBase64 } from "../src/util/base64";
import { CaptureSink, FakeChrome, FakeShell } from "./helpers/executor-harness";

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

/** Bob decapsulates Alice's KX first message and boots his ratchet as responder. */
function bobReceiveKx(bob: Bob, kxEnvelope: Uint8Array): string {
  const res = respondKx(bob.ikPub, bob.lookup, kxEnvelope);
  if (!res.ok) {
    throw new Error(`respondKx failed: ${res.reason}`);
  }
  bob.ratchet = initRatchet(res.session.rk, res.session.role);
  const parsed = JSON.parse(dec.decode(res.plaintext)) as { m: string };
  return parsed.m;
}

// Ratchet payloads are the executor's app format: JSON {m?, tmr}. Bob mirrors
// it so he speaks the same wire contract a real peer (running the executor) would.
function bobReceive(bob: Bob, msgEnvelope: Uint8Array): string {
  const body = decodeMsgEnvelope(msgEnvelope);
  if (body === null || bob.ratchet === null) {
    throw new Error("not a MSG envelope / no ratchet");
  }
  const r = ratchetDecrypt(bob.ratchet, body);
  if (!r.ok) {
    throw new Error(`ratchetDecrypt failed: ${r.reason}`);
  }
  const parsed = JSON.parse(dec.decode(r.plaintext)) as { m?: string };
  return parsed.m ?? "";
}

function bobSend(bob: Bob, text: string): Uint8Array {
  if (bob.ratchet === null) {
    throw new Error("no ratchet");
  }
  const payload = enc.encode(JSON.stringify({ tmr: 0, m: text }));
  return encodeMsgEnvelope(ratchetEncrypt(bob.ratchet, payload));
}

const sent: Uint8Array[] = [];

async function bootstrapAlice(): Promise<{
  executor: Executor;
  output: CaptureSink;
  chrome: FakeChrome;
}> {
  const store = new KeyStore(`meridian-edge-ratchet-${Math.random()}`, new IDBFactory());
  const output = new CaptureSink();
  const shell = new FakeShell();
  const chrome = new FakeChrome();
  // chrome doubles as the NoticeSink so inbound-discard notices are asserted
  // where they actually land (the right-side panel), as main.ts wires it.
  const executor = new Executor(
    new Renderer(output, undefined, null, chrome),
    shell,
    store,
    undefined,
    chrome,
  );

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
  return { executor, output, chrome };
}

async function send(executor: Executor, text: string): Promise<void> {
  executor.handle(parseLine(text));
  await executor.idle();
}

/** Deliver an envelope to Alice's inbox and pump it (a re-login drains the queue). */
async function deliverToAlice(executor: Executor, envelope: Uint8Array): Promise<void> {
  vi.mocked(api.fetchMessages).mockResolvedValueOnce({
    messages: [{ id: 1, envelope: toBase64(envelope) }],
  });
  executor.handle(parseLine("/login"));
  await executor.idle();
  vi.mocked(api.fetchMessages).mockResolvedValue({ messages: [] });
}

beforeEach(() => {
  sent.length = 0;
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockReset" in fn) {
      (fn as { mockReset: () => void }).mockReset();
    }
  }
});

describe("continued messaging over the ratchet", () => {
  it("hands off from the KX first message to ratchet follow-ups (send side)", async () => {
    const { executor, chrome } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);

    await send(executor, `/add ${bob.uid} bob`);
    await send(executor, "/chat bob");
    await send(executor, "first"); // KX envelope
    await send(executor, "second"); // ratchet MSG
    await send(executor, "third"); // ratchet MSG

    expect(sent.length).toBe(3);
    // The first send is a KX handshake; the rest are ratchet MSG envelopes.
    expect(bobReceiveKx(bob, sent[0] as Uint8Array)).toBe("first");
    expect(bobReceive(bob, sent[1] as Uint8Array)).toBe("second");
    expect(bobReceive(bob, sent[2] as Uint8Array)).toBe("third");
    // Each delivered message raised a right-edge tick, not a transcript line;
    // the two /add + /chat commands are not sends and raise none.
    expect(chrome.confirms).toBe(3);
    expect(chrome.rejects).toBe(0);
  });

  it("/chat <target> <message> switches to the conversation and sends in one line", async () => {
    const { executor, chrome } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);

    await send(executor, `/add ${bob.uid} bob`);
    // One line: switch to bob AND fire the first message.
    await send(executor, "/chat bob hey there");

    // The conversation is now the active/focused one...
    expect(chrome.context).toBe("[chatting with: bob (UNVERIFIED)]");
    // ...the inline message was echoed as a bright message (not a dim command)...
    expect(chrome.echoes).toContainEqual({ line: "hey there", kind: "message" });
    // ...and it was actually delivered (a KX first message Bob decrypts) + ticked.
    expect(sent.length).toBe(1);
    expect(bobReceiveKx(bob, sent[0] as Uint8Array)).toBe("hey there");
    expect(chrome.confirms).toBe(1);
    expect(chrome.rejects).toBe(0);
  });

  it("a follow-up /chat <target> <message> rides the ratchet after the handshake", async () => {
    const { executor } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);

    await send(executor, `/add ${bob.uid} bob`);
    await send(executor, "/chat bob first"); // one-liner: KX handshake
    await send(executor, "/chat bob second"); // one-liner again: ratchet MSG

    expect(sent.length).toBe(2);
    expect(bobReceiveKx(bob, sent[0] as Uint8Array)).toBe("first");
    expect(bobReceive(bob, sent[1] as Uint8Array)).toBe("second");
  });

  it("drives the emblem medallion: active after login, idle after /lock", async () => {
    const { executor, chrome } = await bootstrapAlice();
    // bootstrapAlice registers, which auto-logs-in: a live session spins.
    expect(chrome.emblem).toBe("active");
    await send(executor, "/lock");
    expect(chrome.emblem).toBe("idle");
  });

  it("keeps the chat-context line in sync with /chat and /timer", async () => {
    const { executor, chrome } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);

    await send(executor, `/add ${bob.uid} bob`);
    expect(chrome.context).toBeNull(); // no active conversation yet
    await send(executor, "/chat bob");
    expect(chrome.context).toBe("[chatting with: bob (UNVERIFIED)]");
    await send(executor, "/timer bob 1h");
    expect(chrome.context).toBe("[chatting with: bob (UNVERIFIED)] [timer: 1h]");
    await send(executor, "/timer bob off");
    expect(chrome.context).toBe("[chatting with: bob (UNVERIFIED)]");
  });

  it("decrypts a ratchet reply and heals across a full round trip (receive side)", async () => {
    const { executor, output } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);

    await send(executor, `/add ${bob.uid} bob`);
    await send(executor, "/chat bob");
    await send(executor, "hi"); // KX
    await send(executor, "again"); // ratchet MSG (offers a KEM key)
    bobReceiveKx(bob, sent[0] as Uint8Array);
    bobReceive(bob, sent[1] as Uint8Array);

    // Bob replies through the ratchet; Alice receives via trial decryption.
    await deliverToAlice(executor, bobSend(bob, "hello alice"));
    expect(output.text()).toContain("[bob] hello alice");

    // Continue: Alice → Bob → Alice, exercising further KEM steps.
    sent.length = 0;
    await send(executor, "still here");
    expect(bobReceive(bob, sent[0] as Uint8Array)).toBe("still here");
    await deliverToAlice(executor, bobSend(bob, "me too"));
    expect(output.text()).toContain("[bob] me too");
  });

  it("sends a MSG matching no session to the notice panel, not the transcript", async () => {
    const { executor, output, chrome } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await send(executor, `/add ${bob.uid} bob`);
    await send(executor, "/chat bob");
    await send(executor, "hi");
    bobReceiveKx(bob, sent[0] as Uint8Array);

    // A ratchet message from a *different*, unknown session.
    const stranger = makeBob();
    const strangerRk = new Uint8Array(64).fill(42);
    stranger.ratchet = initRatchet(strangerRk, "initiator");
    await deliverToAlice(executor, bobSend(stranger, "who am i"));

    // It lands in the right-side discarded panel with its code...
    expect(chrome.discarded.map((d) => d.code)).toContain("E505");
    const notice = chrome.discarded.find((d) => d.code === "E505");
    expect(notice?.text).toContain("cannot read");
    expect(notice?.text).toContain("/chat"); // tells the user how to recover
    // ...and never reaches the transcript, which is the whole point of the
    // panel: an unreadable inbound message must not interrupt the conversation.
    expect(output.text()).not.toContain("E505");
    expect(output.text()).not.toContain("cannot read");
  });

  it("explains a lost session after the contact is removed", async () => {
    const { executor, chrome } = await bootstrapAlice();
    const bob = makeBob();
    vi.mocked(api.fetchBundle).mockResolvedValue(bob.bundle);
    await send(executor, `/add ${bob.uid} bob`);
    await send(executor, "/chat bob");
    await send(executor, "hi");
    bobReceiveKx(bob, sent[0] as Uint8Array);

    // Alice removes bob, which tears down her side of the session; bob's
    // client does not know and keeps ratcheting.
    await send(executor, "/remove bob");
    await deliverToAlice(executor, bobSend(bob, "are you there"));

    const notice = chrome.discarded.find((d) => d.code === "E505");
    expect(notice, "a removed contact's message should raise E505").toBeDefined();
    expect(notice?.text).toContain("removed contact");
  });
});
