// PQ-KX end-to-end (CLAUDE.md §3 DoD): both roles in-process, tampered
// bundle aborts, tampered ciphertext fails AEAD, reduced-fs without an OPK.

import { describe, expect, it } from "vitest";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { initiateKx, respondKx, verifyBundle } from "../src/crypto/kx";
import type { Bundle, PrekeyLookup, PrekeySecret } from "../src/crypto/kx";
import { generateOpkBatch, generateSpk } from "../src/crypto/prekeys";

const alice = ml_dsa65.keygen(new Uint8Array(32).fill(1));
const bob = ml_dsa65.keygen(new Uint8Array(32).fill(2));

interface BobSide {
  bundle: Bundle;
  lookup: PrekeyLookup;
}

function makeBob(withOpk: boolean): BobSide {
  const spk = generateSpk(bob.secretKey);
  const batch = generateOpkBatch(bob.secretKey, 2);
  const spkMap = new Map<string, PrekeySecret>([
    [bytesToHex(sha512(spk.pub)), { pub: spk.pub, sec: spk.sec, storeKey: "spk/1" }],
  ]);
  const opkMap = new Map<string, PrekeySecret>();
  batch.pubs.forEach((pub, i) => {
    const sec = batch.secs[i];
    if (sec !== undefined) {
      opkMap.set(bytesToHex(sha512(pub)), { pub, sec, storeKey: `opk/1/${i}` });
    }
  });
  const opkPub = batch.pubs[0];
  return {
    bundle: {
      ikPub: bob.publicKey,
      spkPub: spk.pub,
      spkSig: spk.sig,
      opk:
        withOpk && opkPub !== undefined
          ? { pub: opkPub, index: 0, leaves: batch.leaves, rootSig: batch.rootSig }
          : null,
    },
    lookup: {
      spkByHash: (h) => spkMap.get(h) ?? null,
      opkByHash: (h) => opkMap.get(h) ?? null,
    },
  };
}

const PLAINTEXT = new TextEncoder().encode('{"u":"AAAA","m":"hello bob"}');

describe("PQ-KX", () => {
  it("initiator -> responder round-trip agrees on plaintext and root key", () => {
    const side = makeBob(true);
    const { envelope, session } = initiateKx(alice.publicKey, alice.secretKey, side.bundle, PLAINTEXT);
    const result = respondKx(bob.publicKey, side.lookup, envelope);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(new TextDecoder().decode(result.plaintext)).toBe(new TextDecoder().decode(PLAINTEXT));
      expect(Buffer.from(result.session.rk)).toEqual(Buffer.from(session.rk));
      expect(result.session.reducedFs).toBe(false);
      expect(result.consumedOpkStoreKey).toBe("opk/1/0");
      expect(Buffer.from(result.senderIk)).toEqual(Buffer.from(alice.publicKey));
    }
  });

  it("proceeds without an OPK at reduced forward secrecy", () => {
    const side = makeBob(false);
    const { envelope, session } = initiateKx(alice.publicKey, alice.secretKey, side.bundle, PLAINTEXT);
    expect(session.reducedFs).toBe(true);
    const result = respondKx(bob.publicKey, side.lookup, envelope);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.reducedFs).toBe(true);
      expect(result.consumedOpkStoreKey).toBeNull();
    }
  });

  it("a tampered bundle signature aborts before any encapsulation", () => {
    const side = makeBob(true);
    const badSig = side.bundle.spkSig.slice();
    badSig[0] = (badSig[0] ?? 0) ^ 0xff;
    const tampered: Bundle = { ...side.bundle, spkSig: badSig };
    expect(verifyBundle(tampered)).toBe(false);
    expect(() => initiateKx(alice.publicKey, alice.secretKey, tampered, PLAINTEXT)).toThrow();
  });

  it("a substituted OPK in the bundle fails batch verification", () => {
    const side = makeBob(true);
    const foreign = generateOpkBatch(bob.secretKey, 1);
    const foreignPub = foreign.pubs[0];
    expect(foreignPub).toBeDefined();
    if (foreignPub !== undefined && side.bundle.opk !== null) {
      const tampered: Bundle = {
        ...side.bundle,
        opk: { ...side.bundle.opk, pub: foreignPub },
      };
      expect(verifyBundle(tampered)).toBe(false);
    }
  });

  it("a tampered envelope signature is rejected before decapsulation", () => {
    const side = makeBob(true);
    const { envelope } = initiateKx(alice.publicKey, alice.secretKey, side.bundle, PLAINTEXT);
    // sig sits between ct2 and the 24-byte nonce + 4-byte length + ciphertext.
    const sigOffset = envelope.length - PLAINTEXT.length - 16 - 4 - 24 - 3309;
    const tampered = envelope.slice();
    tampered[sigOffset + 100] = (tampered[sigOffset + 100] ?? 0) ^ 0xff;
    const result = respondKx(bob.publicKey, side.lookup, tampered);
    expect(result).toEqual({ ok: false, reason: "bad-signature" });
  });

  it("a tampered ciphertext fails the AEAD", () => {
    const side = makeBob(true);
    const { envelope } = initiateKx(alice.publicKey, alice.secretKey, side.bundle, PLAINTEXT);
    const tampered = envelope.slice();
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
    const result = respondKx(bob.publicKey, side.lookup, tampered);
    expect(result).toEqual({ ok: false, reason: "decrypt-failed" });
  });

  it("unknown SPK or OPK hints are typed failures, not throws", () => {
    const side = makeBob(true);
    const { envelope } = initiateKx(alice.publicKey, alice.secretKey, side.bundle, PLAINTEXT);
    const empty: PrekeyLookup = { spkByHash: () => null, opkByHash: () => null };
    expect(respondKx(bob.publicKey, empty, envelope)).toEqual({
      ok: false,
      reason: "unknown-spk",
    });
    const spkOnly: PrekeyLookup = {
      spkByHash: side.lookup.spkByHash,
      opkByHash: () => null,
    };
    expect(respondKx(bob.publicKey, spkOnly, envelope)).toEqual({
      ok: false,
      reason: "unknown-opk",
    });
  });

  it("garbage bytes are malformed, not a throw", () => {
    const side = makeBob(true);
    expect(respondKx(bob.publicKey, side.lookup, new Uint8Array(100))).toEqual({
      ok: false,
      reason: "malformed",
    });
  });
});
