// Prekey generation and batch signing (CLAUDE.md §2.6).
//
// The SPK is individually signed by the identity key. OPKs are batch-signed:
// root = SHA-512(leaf_0 ‖ ... ‖ leaf_n) with leaf_i = SHA-512(opk_pub_i).
// The server retains the leaf list, so a fetching client can verify any
// single OPK against the root signature (used in W3).

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";

export interface GeneratedSpk {
  readonly pub: Uint8Array;
  readonly sec: Uint8Array;
  readonly sig: Uint8Array;
}

export interface GeneratedOpkBatch {
  readonly pubs: readonly Uint8Array[];
  readonly secs: readonly Uint8Array[];
  readonly leaves: readonly Uint8Array[];
  readonly root: Uint8Array;
  readonly rootSig: Uint8Array;
}

export function generateSpk(ikSecret: Uint8Array): GeneratedSpk {
  const keys = ml_kem768.keygen();
  return {
    pub: keys.publicKey,
    sec: keys.secretKey,
    sig: ml_dsa65.sign(keys.publicKey, ikSecret),
  };
}

export function batchRoot(leaves: readonly Uint8Array[]): Uint8Array {
  return sha512(concatBytes(...leaves));
}

export function generateOpkBatch(ikSecret: Uint8Array, count: number): GeneratedOpkBatch {
  const pubs: Uint8Array[] = [];
  const secs: Uint8Array[] = [];
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < count; i += 1) {
    const keys = ml_kem768.keygen();
    pubs.push(keys.publicKey);
    secs.push(keys.secretKey);
    leaves.push(sha512(keys.publicKey));
  }
  const root = batchRoot(leaves);
  return { pubs, secs, leaves, root, rootSig: ml_dsa65.sign(root, ikSecret) };
}

export function verifySpk(pub: Uint8Array, sig: Uint8Array, ikPub: Uint8Array): boolean {
  return ml_dsa65.verify(sig, pub, ikPub);
}

/** Verify one OPK against its batch: leaf matches, root signature valid. */
export function verifyOpkInBatch(
  opkPub: Uint8Array,
  index: number,
  leaves: readonly Uint8Array[],
  rootSig: Uint8Array,
  ikPub: Uint8Array,
): boolean {
  const leaf = leaves[index];
  if (leaf === undefined) {
    return false;
  }
  const computed = sha512(opkPub);
  if (computed.length !== leaf.length || !computed.every((b, i) => b === leaf[i])) {
    return false;
  }
  return ml_dsa65.verify(rootSig, batchRoot(leaves), ikPub);
}
