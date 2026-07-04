import { describe, expect, it } from "vitest";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  batchRoot,
  generateOpkBatch,
  generateSpk,
  verifyOpkInBatch,
  verifySpk,
} from "../src/crypto/prekeys";
import {
  ML_DSA_65_SIG_BYTES,
  ML_KEM_768_PUBKEY_BYTES,
} from "../src/crypto/constants";

const seed = new Uint8Array(32).fill(7);
const ik = ml_dsa65.keygen(seed);

describe("signed prekey", () => {
  it("generates an ML-KEM-768 key signed by the identity key", () => {
    const spk = generateSpk(ik.secretKey);
    expect(spk.pub.length).toBe(ML_KEM_768_PUBKEY_BYTES);
    expect(spk.sig.length).toBe(ML_DSA_65_SIG_BYTES);
    expect(verifySpk(spk.pub, spk.sig, ik.publicKey)).toBe(true);
  });

  it("rejects a substituted prekey (malicious server)", () => {
    const spk = generateSpk(ik.secretKey);
    const other = generateSpk(ik.secretKey);
    expect(verifySpk(other.pub, spk.sig, ik.publicKey)).toBe(false);
    const wrongIk = ml_dsa65.keygen(new Uint8Array(32).fill(9));
    expect(verifySpk(spk.pub, spk.sig, wrongIk.publicKey)).toBe(false);
  });
});

describe("one-time prekey batch", () => {
  it("batch-signs 5 OPKs and verifies each against the root", () => {
    const batch = generateOpkBatch(ik.secretKey, 5);
    expect(batch.pubs).toHaveLength(5);
    expect(batch.leaves).toHaveLength(5);
    expect(batch.root).toEqual(batchRoot(batch.leaves));
    for (let i = 0; i < 5; i += 1) {
      const pub = batch.pubs[i];
      expect(pub).toBeDefined();
      if (pub !== undefined) {
        expect(verifyOpkInBatch(pub, i, batch.leaves, batch.rootSig, ik.publicKey)).toBe(true);
      }
    }
  });

  it("rejects an OPK swapped into the wrong slot or batch", () => {
    const batch = generateOpkBatch(ik.secretKey, 3);
    const foreign = generateOpkBatch(ik.secretKey, 1);
    const foreignPub = foreign.pubs[0];
    const ownPub = batch.pubs[0];
    expect(foreignPub).toBeDefined();
    expect(ownPub).toBeDefined();
    if (foreignPub !== undefined && ownPub !== undefined) {
      // Foreign key against this batch's leaves: leaf mismatch.
      expect(verifyOpkInBatch(foreignPub, 0, batch.leaves, batch.rootSig, ik.publicKey)).toBe(
        false,
      );
      // Right key, wrong index: leaf mismatch.
      expect(verifyOpkInBatch(ownPub, 1, batch.leaves, batch.rootSig, ik.publicKey)).toBe(false);
      // Out-of-range index.
      expect(verifyOpkInBatch(ownPub, 7, batch.leaves, batch.rootSig, ik.publicKey)).toBe(false);
    }
  });

  it("rejects a tampered root signature", () => {
    const batch = generateOpkBatch(ik.secretKey, 2);
    const pub = batch.pubs[0];
    const badSig = batch.rootSig.slice();
    badSig[0] = (badSig[0] ?? 0) ^ 0xff;
    if (pub !== undefined) {
      expect(verifyOpkInBatch(pub, 0, batch.leaves, badSig, ik.publicKey)).toBe(false);
    }
  });
});
