import { describe, expect, it } from "vitest";

import { decodeKxEnvelope, encodeKxEnvelope } from "../src/crypto/envelope";
import type { KxEnvelope } from "../src/crypto/envelope";

function sample(withOpk: boolean): KxEnvelope {
  const fill = (length: number, value: number): Uint8Array => new Uint8Array(length).fill(value);
  return {
    spkHash: fill(64, 1),
    opkHash: withOpk ? fill(64, 2) : null,
    ikA: fill(1952, 3),
    ct1: fill(1088, 4),
    ct2: withOpk ? fill(1088, 5) : null,
    sig: fill(3309, 6),
    nonce: fill(24, 7),
    ciphertext: fill(48, 8),
  };
}

/** Deterministic PRNG - test-only; app code uses the CSPRNG. */
function makeRng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x100000000;
  };
}

describe("KX envelope codec", () => {
  it("round-trips with and without an OPK", () => {
    for (const withOpk of [true, false]) {
      const original = sample(withOpk);
      const decoded = decodeKxEnvelope(encodeKxEnvelope(original));
      expect(decoded).not.toBeNull();
      expect(decoded).toEqual(original);
    }
  });

  it("rejects wrong version, type, and unknown flags", () => {
    const bytes = encodeKxEnvelope(sample(true));
    for (const [offset, value] of [
      [0, 2],
      [1, 9],
      [2, 4],
    ] as const) {
      const mutated = bytes.slice();
      mutated[offset] = value;
      expect(decodeKxEnvelope(mutated)).toBeNull();
    }
  });

  it("rejects truncation and trailing garbage", () => {
    const bytes = encodeKxEnvelope(sample(true));
    expect(decodeKxEnvelope(bytes.slice(0, bytes.length - 1))).toBeNull();
    expect(decodeKxEnvelope(bytes.slice(0, 100))).toBeNull();
    const extended = new Uint8Array(bytes.length + 1);
    extended.set(bytes);
    expect(decodeKxEnvelope(extended)).toBeNull();
  });

  it("rejects a lying ciphertext length", () => {
    const withOpk = sample(true);
    const bytes = encodeKxEnvelope(withOpk);
    // ctLen field sits 4 bytes before the ciphertext.
    const ctLenOffset = bytes.length - withOpk.ciphertext.length - 4;
    const view = new DataView(bytes.buffer);
    view.setUint32(ctLenOffset, withOpk.ciphertext.length + 1, false);
    expect(decodeKxEnvelope(bytes)).toBeNull();
  });

  it("never throws on random garbage (fuzz)", () => {
    const rng = makeRng(0xfeedface);
    for (let i = 0; i < 2000; i += 1) {
      const length = Math.floor(rng() * 9000);
      const junk = new Uint8Array(length);
      for (let j = 0; j < length; j += 1) {
        junk[j] = Math.floor(rng() * 256);
      }
      // Must return null or a structurally valid envelope, never throw.
      decodeKxEnvelope(junk);
    }
  });
});
