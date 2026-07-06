// Ratchet integration through the executor (CLAUDE.md §4): a registered Alice
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

function bobReceive(bob: Bob, msgEnvelope: Uint8Array): string {
  const body = decodeMsgEnvelope(msgEnvelope);
  if (body === null || bob.ratchet === null) {
    throw new Error("not a MSG envelope / no ratchet");
  }
  const r = ratchetDecrypt(bob.ratchet, body);
  if (!r.ok) {
    throw new Error(`ratchetDecrypt failed: ${r.reason}`);
  }
  return dec.decode(r.plaintext);
}

function bobSend(bob: Bob, text: string): Uint8Array {
  if (bob.ratchet === null) {
    throw new Error("no ratchet");
  }
  return encodeMsgEnvelope(ratchetEncrypt(bob.ratchet, enc.encode(text)));
}

const sent: Uint8Array[] = [];

async function bootstrapAlice(): Promise<{ executor: Executor; output: CaptureSink }> {
  const store = new KeyStore(`pqterm-ratchet-${Math.random()}`, new IDBFactory());
  const output = new CaptureSink();
  const shell = new FakeShell();
  const executor = new Executor(new Renderer(output), shell, store);

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
  return { executor, output };
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
    const { executor } = await bootstrapAlice();
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

  it("drops a MSG that matches no established session", async () => {
    const { executor, output } = await bootstrapAlice();
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
    expect(output.text()).toContain("no matching session");
  });
});
