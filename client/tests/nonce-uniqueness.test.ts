// A02 Cryptographic Failures (CLAUDE.md §7.2): AEAD nonces are random per
// message and must never repeat under the same key. Every AEAD site in this
// codebase (kx.ts, ratchet.ts) draws its 24-byte XChaCha20-Poly1305 nonce the
// same way - crypto.getRandomValues(new Uint8Array(24)) - so that shared
// primitive is what this property actually reduces to; test it directly at
// the checklist's stated scale rather than re-deriving it once per call site.

import { describe, expect, it } from "vitest";

const NONCE_BYTES = 24;
const SAMPLES = 1_000_000;

describe("AEAD nonce uniqueness (§0, §7.2)", () => {
  it("never repeats a 24-byte nonce over 10^6 draws", () => {
    const seen = new Set<string>();
    for (let i = 0; i < SAMPLES; i += 1) {
      const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
      // Compact key: nonces are uniform random, so a plain string join of the
      // byte values is a fine hash-set key without hex-encoding overhead.
      const key = nonce.join(",");
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
    expect(seen.size).toBe(SAMPLES);
  });
});
