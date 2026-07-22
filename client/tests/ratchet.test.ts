// KEM double-ratchet (CLAUDE.md §4 DoD): forward secrecy, post-compromise
// security, out-of-order delivery with a bounded skip cache, and the MSG
// envelope/header codec. Both peers run in-process from a shared RK0.

import { describe, expect, it } from "vitest";

import {
  initRatchet,
  ratchetDecrypt,
  ratchetEncrypt,
  KEM_STEP_INTERVAL,
  MAX_SKIP,
} from "../src/crypto/ratchet";
import type { RatchetState } from "../src/crypto/ratchet";
import {
  decodeMsgEnvelope,
  decodeMsgHeader,
  encodeMsgEnvelope,
  encodeMsgHeader,
} from "../src/crypto/envelope";

const enc = new TextEncoder();
const dec = new TextDecoder();

function pair(seed = 7): { a: RatchetState; b: RatchetState } {
  const rk = new Uint8Array(64).fill(seed);
  return { a: initRatchet(rk, "initiator"), b: initRatchet(rk, "responder") };
}

/** Deep snapshot; a ratchet mutates and replaces its typed arrays in place, so
 * slicing the current references is a faithful point-in-time copy. */
function snapshot(s: RatchetState): RatchetState {
  return {
    ...s,
    rk: s.rk.slice(),
    cks: s.cks.slice(),
    ckr: s.ckr === null ? null : s.ckr.slice(),
    hks: s.hks.slice(),
    hkr: s.hkr.slice(),
    nhkr: s.nhkr === null ? null : s.nhkr.slice(),
    sendKemSk: s.sendKemSk === null ? null : s.sendKemSk.slice(),
    sendKemPk: s.sendKemPk === null ? null : s.sendKemPk.slice(),
    peerKemPk: s.peerKemPk === null ? null : s.peerKemPk.slice(),
    skipped: new Map([...s.skipped].map(([k, v]) => [k, v.slice()])),
  };
}

function send(from: RatchetState, text: string): Uint8Array {
  return ratchetEncrypt(from, enc.encode(text));
}

function recv(to: RatchetState, body: Uint8Array): string {
  const r = ratchetDecrypt(to, body);
  if (!r.ok) {
    throw new Error(`decrypt failed: ${r.reason}`);
  }
  return dec.decode(r.plaintext);
}

describe("ratchet round-trip", () => {
  it("carries messages both ways", () => {
    const { a, b } = pair();
    expect(recv(b, send(a, "hello"))).toBe("hello");
    expect(recv(a, send(b, "hi back"))).toBe("hi back");
    expect(recv(b, send(a, "how are you"))).toBe("how are you");
  });

  it("survives a long ping-pong across many KEM steps", () => {
    const { a, b } = pair();
    let left = a;
    let right = b;
    for (let i = 0; i < 40; i += 1) {
      const text = `msg-${i}`;
      expect(recv(right, send(left, text))).toBe(text);
      [left, right] = [right, left];
    }
  });

  it("advances a KEM step every ~KEM_STEP_INTERVAL messages within one turn", () => {
    const { a, b } = pair();
    // A sends a long unbroken burst; B receives all in order.
    for (let i = 0; i < KEM_STEP_INTERVAL * 2 + 1; i += 1) {
      expect(recv(b, send(a, `burst-${i}`))).toBe(`burst-${i}`);
    }
    // Then B can still reply and A reads it (offer made mid-burst is accepted).
    expect(recv(a, send(b, "ack"))).toBe("ack");
  });
});

describe("forward secrecy (§4.1)", () => {
  it("a captured ciphertext is undecryptable from later state", () => {
    const { a, b } = pair();
    const c0 = send(a, "secret-0");
    expect(recv(b, c0)).toBe("secret-0");
    // B advances past it.
    expect(recv(b, send(a, "secret-1"))).toBe("secret-1");
    // The message key for c0 was wiped after use; B's current (or dumped) state
    // cannot recover it.
    const dumped = snapshot(b);
    const replay = ratchetDecrypt(dumped, c0);
    expect(replay.ok).toBe(false);
  });
});

describe("post-compromise security (§4.2)", () => {
  it("a leaked state loses decryption ability within a round trip", () => {
    const { a, b } = pair();
    // Establish and exercise a couple of KEM steps.
    recv(b, send(a, "m1"));
    recv(a, send(b, "m2"));

    // Attacker exfiltrates B's full state here.
    const leaked = snapshot(b);

    // Sanity: at leak time the attacker's copy is as capable as B - it can read
    // the next message A sends (verified on independent clones so the mutation
    // of one does not disturb the other).
    const probe = send(a, "m3");
    expect(recv(snapshot(b), probe)).toBe("m3"); // real B could read it
    expect(recv(snapshot(leaked), probe)).toBe("m3"); // so could the leaked copy

    // The session heals: A and B complete a full round trip, injecting fresh KEM
    // entropy the attacker never saw. (Advance the *real* B with probe first.)
    recv(b, probe);
    recv(a, send(b, "m4"));
    const healed = send(a, "m5");

    // Real B still decrypts; the frozen leaked copy cannot.
    expect(recv(b, healed)).toBe("m5");
    const attacker = ratchetDecrypt(snapshot(leaked), healed);
    expect(attacker.ok).toBe(false);
  });
});

describe("out-of-order delivery (§4.1)", () => {
  it("decrypts messages delivered 3, 1, 2", () => {
    const { a, b } = pair();
    // One unbroken sending turn → a single chain, no KEM step between them.
    const m1 = send(a, "one");
    const m2 = send(a, "two");
    const m3 = send(a, "three");
    expect(recv(b, m3)).toBe("three");
    expect(recv(b, m1)).toBe("one");
    expect(recv(b, m2)).toBe("two");
  });

  it("refuses a gap larger than the skip bound", () => {
    const { a, b } = pair();
    let last = send(a, "0");
    for (let i = 1; i <= MAX_SKIP + 1; i += 1) {
      last = send(a, `${i}`);
    }
    // Delivering only the final message forces skipping > MAX_SKIP keys.
    const r = ratchetDecrypt(b, last);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("skip-overflow");
    }
  });

  it("caches exactly up to the skip bound", () => {
    const { a, b } = pair();
    send(a, "0"); // n=0
    let target: Uint8Array | null = null;
    for (let i = 1; i <= MAX_SKIP; i += 1) {
      const body = send(a, `${i}`);
      if (i === MAX_SKIP) {
        target = body;
      }
    }
    // Skipping exactly MAX_SKIP keys (n=0..MAX_SKIP-1) to reach n=MAX_SKIP is allowed.
    expect(target).not.toBeNull();
    expect(recv(b, target as Uint8Array)).toBe(`${MAX_SKIP}`);
  });
});

describe("tamper resistance", () => {
  it("rejects a flipped ciphertext byte", () => {
    const { a, b } = pair();
    const body = send(a, "authentic");
    const tampered = body.slice();
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 0x01;
    const r = ratchetDecrypt(b, tampered);
    expect(r.ok).toBe(false);
  });

  it("rejects a body under the wrong session", () => {
    const { a } = pair(1);
    const { b } = pair(2); // different RK0
    const r = ratchetDecrypt(b, send(a, "cross"));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("unreadable-header");
    }
  });

  it("returns a typed reason for malformed input", () => {
    const { b } = pair();
    const r = ratchetDecrypt(b, new Uint8Array(3));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("malformed");
    }
  });
});

describe("MSG envelope + header codec", () => {
  it("round-trips the envelope wrapper", () => {
    const { a } = pair();
    const body = send(a, "framed");
    const wrapped = encodeMsgEnvelope(body);
    const unwrapped = decodeMsgEnvelope(wrapped);
    expect(unwrapped).not.toBeNull();
    expect([...(unwrapped as Uint8Array)]).toEqual([...body]);
  });

  it("rejects a non-MSG envelope", () => {
    expect(decodeMsgEnvelope(new Uint8Array([1, 99, 0, 0]))).toBeNull();
    expect(decodeMsgEnvelope(new Uint8Array([0]))).toBeNull();
  });

  it("round-trips a header with and without KEM material", () => {
    const plain = { n: 5, pn: 3, kemPk: null, kemCt: null };
    const decoded = decodeMsgHeader(encodeMsgHeader(plain));
    expect(decoded).toEqual(plain);

    const pk = new Uint8Array(1184).fill(9);
    const ct = new Uint8Array(1088).fill(4);
    const withKem = decodeMsgHeader(encodeMsgHeader({ n: 0, pn: 0, kemPk: pk, kemCt: ct }));
    expect(withKem?.n).toBe(0);
    expect(withKem?.kemPk).toEqual(pk);
    expect(withKem?.kemCt).toEqual(ct);
  });

  it("rejects a truncated header", () => {
    expect(decodeMsgHeader(new Uint8Array(4))).toBeNull();
  });
});
