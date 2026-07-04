// PQ-KX: the asynchronous handshake (CLAUDE.md §3, PQXDH analog, no DH).
//
//   transcript = SHA-512(version ‖ IK_A ‖ IK_B ‖ SPK_B ‖ ct1 [‖ OPK_B ‖ ct2])
//   RK0 = HKDF-SHA-512(ss1 ‖ ss2, salt=∅, info = KDF_INFO_KX ‖ transcript)
//   sig_A = ML-DSA.Sign(sk_IK_A, transcript)
//   message key = HKDF(RK0, KDF_INFO_CK); AEAD ad = transcript
//
// Responder order is prescribed: verify sig_A first, then decapsulate,
// derive, decrypt, and the caller deletes the consumed OPK secret
// immediately (§3.7). respondKx is total - every failure is a typed reason.

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import { KDF_INFO_CK, KDF_INFO_KX, PROTOCOL_VERSION } from "./constants";
import { verifyOpkInBatch, verifySpk } from "./prekeys";
import { decodeKxEnvelope, encodeKxEnvelope } from "./envelope";

export interface Bundle {
  readonly ikPub: Uint8Array;
  readonly spkPub: Uint8Array;
  readonly spkSig: Uint8Array;
  readonly opk: {
    readonly pub: Uint8Array;
    readonly index: number;
    readonly leaves: readonly Uint8Array[];
    readonly rootSig: Uint8Array;
  } | null;
}

/** Both prekey signatures must verify against the bundle's identity key
 * before any encapsulation happens (§3.1). */
export function verifyBundle(bundle: Bundle): boolean {
  if (!verifySpk(bundle.spkPub, bundle.spkSig, bundle.ikPub)) {
    return false;
  }
  if (bundle.opk !== null) {
    return verifyOpkInBatch(
      bundle.opk.pub,
      bundle.opk.index,
      bundle.opk.leaves,
      bundle.opk.rootSig,
      bundle.ikPub,
    );
  }
  return true;
}

export interface KxSession {
  readonly rk: Uint8Array; // 64-byte root key
  readonly transcript: Uint8Array;
  readonly peerIk: Uint8Array;
  readonly role: "initiator" | "responder";
  readonly reducedFs: boolean;
}

function computeTranscript(
  ikA: Uint8Array,
  ikB: Uint8Array,
  spkPub: Uint8Array,
  ct1: Uint8Array,
  opkPub: Uint8Array | null,
  ct2: Uint8Array | null,
): Uint8Array {
  const parts = [Uint8Array.of(PROTOCOL_VERSION), ikA, ikB, spkPub, ct1];
  if (opkPub !== null && ct2 !== null) {
    parts.push(opkPub, ct2);
  }
  return sha512(concatBytes(...parts));
}

const encoder = new TextEncoder();

function deriveRootKey(ss1: Uint8Array, ss2: Uint8Array | null, transcript: Uint8Array): Uint8Array {
  const ikm = ss2 === null ? ss1 : concatBytes(ss1, ss2);
  const rk = hkdf(sha512, ikm, undefined, concatBytes(encoder.encode(KDF_INFO_KX), transcript), 64);
  if (ss2 !== null) {
    ikm.fill(0); // concat copy; callers own ss1/ss2
  }
  return rk;
}

function deriveMessageKey(rk: Uint8Array): Uint8Array {
  return hkdf(sha512, rk, undefined, encoder.encode(KDF_INFO_CK), 32);
}

export function initiateKx(
  myIkPub: Uint8Array,
  myIkSec: Uint8Array,
  bundle: Bundle,
  plaintext: Uint8Array,
): { envelope: Uint8Array; session: KxSession } {
  if (!verifyBundle(bundle)) {
    // Callers surface this as a security event; encapsulating to an
    // unverified key is never acceptable (§3.1).
    throw new Error("bundle verification failed");
  }
  const enc1 = ml_kem768.encapsulate(bundle.spkPub);
  const ss1 = enc1.sharedSecret;
  const ct1 = enc1.cipherText;
  let ss2: Uint8Array | null = null;
  let ct2: Uint8Array | null = null;
  if (bundle.opk !== null) {
    const enc2 = ml_kem768.encapsulate(bundle.opk.pub);
    ss2 = enc2.sharedSecret;
    ct2 = enc2.cipherText;
  }

  const transcript = computeTranscript(
    myIkPub,
    bundle.ikPub,
    bundle.spkPub,
    ct1,
    bundle.opk?.pub ?? null,
    ct2,
  );
  const rk = deriveRootKey(ss1, ss2, transcript);
  ss1.fill(0);
  ss2?.fill(0);
  const sig = ml_dsa65.sign(transcript, myIkSec);
  const messageKey = deriveMessageKey(rk);
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const ciphertext = xchacha20poly1305(messageKey, nonce, transcript).encrypt(plaintext);
  messageKey.fill(0);

  const envelope = encodeKxEnvelope({
    spkHash: sha512(bundle.spkPub),
    opkHash: bundle.opk === null ? null : sha512(bundle.opk.pub),
    ikA: myIkPub,
    ct1,
    ct2,
    sig,
    nonce,
    ciphertext,
  });
  return {
    envelope,
    session: {
      rk,
      transcript,
      peerIk: bundle.ikPub,
      role: "initiator",
      reducedFs: bundle.opk === null,
    },
  };
}

export interface PrekeySecret {
  readonly pub: Uint8Array;
  readonly sec: Uint8Array;
  /** Store key of the record, so consumed OPKs can be deleted immediately. */
  readonly storeKey: string;
}

export interface PrekeyLookup {
  spkByHash(hashHex: string): PrekeySecret | null;
  opkByHash(hashHex: string): PrekeySecret | null;
}

export type RespondResult =
  | {
      readonly ok: true;
      readonly plaintext: Uint8Array;
      readonly session: KxSession;
      readonly senderIk: Uint8Array;
      readonly consumedOpkStoreKey: string | null;
    }
  | {
      readonly ok: false;
      readonly reason: "malformed" | "unknown-spk" | "unknown-opk" | "bad-signature" | "decrypt-failed";
    };

export function respondKx(
  myIkPub: Uint8Array,
  lookup: PrekeyLookup,
  envelopeBytes: Uint8Array,
): RespondResult {
  const envelope = decodeKxEnvelope(envelopeBytes);
  if (envelope === null) {
    return { ok: false, reason: "malformed" };
  }
  const spk = lookup.spkByHash(bytesToHex(envelope.spkHash));
  if (spk === null) {
    return { ok: false, reason: "unknown-spk" };
  }
  let opk: PrekeySecret | null = null;
  if (envelope.opkHash !== null) {
    opk = lookup.opkByHash(bytesToHex(envelope.opkHash));
    if (opk === null) {
      return { ok: false, reason: "unknown-opk" };
    }
  }

  const transcript = computeTranscript(
    envelope.ikA,
    myIkPub,
    spk.pub,
    envelope.ct1,
    opk?.pub ?? null,
    envelope.ct2,
  );
  if (!ml_dsa65.verify(envelope.sig, transcript, envelope.ikA)) {
    return { ok: false, reason: "bad-signature" };
  }

  const ss1 = ml_kem768.decapsulate(envelope.ct1, spk.sec);
  const ss2 =
    opk !== null && envelope.ct2 !== null ? ml_kem768.decapsulate(envelope.ct2, opk.sec) : null;
  const rk = deriveRootKey(ss1, ss2, transcript);
  ss1.fill(0);
  ss2?.fill(0);
  const messageKey = deriveMessageKey(rk);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(messageKey, envelope.nonce, transcript).decrypt(
      envelope.ciphertext,
    );
  } catch {
    rk.fill(0);
    return { ok: false, reason: "decrypt-failed" };
  } finally {
    messageKey.fill(0);
  }

  return {
    ok: true,
    plaintext,
    senderIk: envelope.ikA,
    consumedOpkStoreKey: opk?.storeKey ?? null,
    session: {
      rk,
      transcript,
      peerIk: envelope.ikA,
      role: "responder",
      reducedFs: opk === null,
    },
  };
}
