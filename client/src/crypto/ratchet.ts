// KEM double-ratchet. A Signal-Double-Ratchet analog
// with every asymmetric step replaced by ML-KEM-768 (FIPS 203); no DH anywhere.
//
// Bootstrapping: the PQ-KX first message (kx.ts, envelope type KX) is a one-off
// that only establishes RK0. This ratchet governs every *subsequent* message
// (envelope type MSG) and is initialised from { rk: RK0, role }. Leaving kx.ts
// untouched keeps the audited handshake stable.
//
// Per-message forward secrecy: sending/receiving symmetric chains advance
//   MK_n     = HKDF(CK_n, KDF_INFO_CK ‖ 0x01)
//   CK_{n+1} = HKDF(CK_n, KDF_INFO_CK ‖ 0x02)
// and the message key is wiped immediately after use. A dumped chain key cannot
// recover an earlier message key (HKDF is one-way).
//
// Post-compromise security: on the first send of a new turn - or every
// KEM_STEP_INTERVAL messages of an unbroken turn - the sender offers a fresh
// ML-KEM-768 public key in its (encrypted) header. The peer encapsulates to it
// on its next send; both mix the shared secret into the root:
//   RK_{i+1} = HKDF(RK_i ‖ ss_new, KDF_INFO_RK)
// and derive fresh chains from RK_{i+1}. Continuous entropy injection heals the
// session within one round trip after a transient leak.
//
// Header encryption: the header (counters + KEM material) is encrypted
// under HK = HKDF(root, KDF_INFO_HDR). The header key is snapshotted per turn to
// the root both parties provably share when the turn begins, so a KEM-accept
// header - which itself carries the ciphertext the peer needs to derive the new
// root - stays readable by the peer that is exactly one root behind. Concretely
// we keep three header roots, mirroring Signal's HKs/HKr/NHKr:
//   hks  - root keying the headers of our current sending turn
//   hkr  - root keying the peer's current turn (what we decrypt with)
//   nhkr - root keying the peer's *next* turn (set whenever the root rolls)
// A receiver tries hkr, then nhkr; success under nhkr means a new turn began.

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

import { KDF_INFO_CK, KDF_INFO_HDR, KDF_INFO_RK } from "./constants";
import { decodeMsgHeader, encodeMsgHeader } from "./envelope";
import type { MsgHeader } from "./envelope";

/** A KEM offer is refreshed at least this often within one unbroken turn. */
export const KEM_STEP_INTERVAL = 10;
/** Skipped-message-key cache bound per session; beyond this we refuse. */
export const MAX_SKIP = 256;

const NONCE_BYTES = 24;

const encoder = new TextEncoder();
const CK_INFO = encoder.encode(KDF_INFO_CK);
const RK_INFO = encoder.encode(KDF_INFO_RK);
const HDR_INFO = encoder.encode(KDF_INFO_HDR);

// Domain-separation tags so the two symmetric-chain outputs, and the two
// directions, never collide.
const TAG_MK = Uint8Array.of(0x01); // message key from a chain key
const TAG_CK = Uint8Array.of(0x02); // next chain key from a chain key
const DIR_I2R = Uint8Array.of(0x01); // initiator → responder chain
const DIR_R2I = Uint8Array.of(0x02); // responder → initiator chain

type Role = "initiator" | "responder";

function kdf(ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdf(sha512, ikm, undefined, info, length);
}

/** MK_n and CK_{n+1} from CK_n. CK_n is wiped by the caller. */
function chainStep(ck: Uint8Array): { mk: Uint8Array; next: Uint8Array } {
  const mk = kdf(ck, concatBytes(CK_INFO, TAG_MK), 32);
  const next = kdf(ck, concatBytes(CK_INFO, TAG_CK), 32);
  return { mk, next };
}

/** RK_{i+1} from RK_i and a fresh KEM shared secret. */
function rootStep(rk: Uint8Array, ss: Uint8Array): Uint8Array {
  const ikm = concatBytes(rk, ss);
  const next = kdf(ikm, RK_INFO, 64);
  ikm.fill(0);
  return next;
}

/** The chain key for `dir`, derived from a root. Both parties compute the same
 * value for a given (root, direction), so sender and receiver chains match. */
function chainFromRoot(root: Uint8Array, dir: Uint8Array): Uint8Array {
  return kdf(root, concatBytes(CK_INFO, dir), 32);
}

function sendDir(role: Role): Uint8Array {
  return role === "initiator" ? DIR_I2R : DIR_R2I;
}
function recvDir(role: Role): Uint8Array {
  return role === "initiator" ? DIR_R2I : DIR_I2R;
}

function headerKey(root: Uint8Array): Uint8Array {
  return kdf(root, HDR_INFO, 32);
}

/** In-memory ratchet state. All key material is raw bytes; the executor's
 * serialize/deserialize handle persistence. Mutated in place by
 * ratchetEncrypt/ratchetDecrypt - never share one object across two peers. */
export interface RatchetState {
  role: Role;
  rk: Uint8Array; // current root (governs message *bodies*)
  cks: Uint8Array; // sending chain key
  ckr: Uint8Array | null; // receiving chain key
  ns: number; // messages sent in the current sending chain
  nr: number; // messages received in the current receiving chain
  pn: number; // length of the previous sending chain (for skip accounting)
  lastAction: "send" | "recv";
  // Header roots.
  hks: Uint8Array; // keys our current sending turn's headers
  hkr: Uint8Array; // keys the peer's current turn (decrypt with this)
  nhkr: Uint8Array | null; // keys the peer's next turn (set on every root roll)
  // KEM offer/accept bookkeeping.
  sendKemSk: Uint8Array | null; // secret for the public we are currently offering
  sendKemPk: Uint8Array | null; // the public we are offering (echoed until accepted)
  peerKemPk: Uint8Array | null; // peer's latest offer, awaiting our encapsulation
  sinceOffer: number; // sends since our last fresh offer (drives the every-N rule)
  // Out-of-order: skipped keys, keyed `${chainId}:${n}`, insertion-ordered.
  recvChainId: number; // increments each time a new receiving chain starts
  skipped: Map<string, Uint8Array>;
}

/** Initialise from the KX root key. The initiator has just "sent" (the KX
 * message); the responder has just "received". `sinceOffer` starts at the
 * interval so the very first ratchet send always makes a KEM offer, seeding
 * PCS immediately. */
export function initRatchet(rk: Uint8Array, role: Role): RatchetState {
  const root = rk.slice(); // own our copy; caller may wipe theirs
  return {
    role,
    rk: root,
    cks: chainFromRoot(root, sendDir(role)),
    ckr: chainFromRoot(root, recvDir(role)),
    ns: 0,
    nr: 0,
    pn: 0,
    lastAction: role === "initiator" ? "send" : "recv",
    hks: root.slice(),
    hkr: root.slice(),
    nhkr: null,
    sendKemSk: null,
    sendKemPk: null,
    peerKemPk: null,
    sinceOffer: KEM_STEP_INTERVAL,
    recvChainId: 0,
    skipped: new Map(),
  };
}

/** Encrypt one message, advancing the sending ratchet. Returns the MSG-envelope
 * body (framed header + payload); the caller wraps it with envelope type MSG. */
export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): Uint8Array {
  const newTurn = state.lastAction === "recv";

  // 1. On a new turn, snapshot the header key to the root both parties share now
  //    (pre-roll). A KEM accept then rolls the root for a fresh sending chain and
  //    records that the peer's next turn will arrive under the rolled root.
  let kemCt: Uint8Array | null = null;
  if (newTurn) {
    state.hks.fill(0);
    state.hks = state.rk.slice();
    if (state.peerKemPk !== null) {
      const enc = ml_kem768.encapsulate(state.peerKemPk);
      kemCt = enc.cipherText;
      const rolled = rootStep(state.rk, enc.sharedSecret);
      enc.sharedSecret.fill(0);
      state.rk.fill(0);
      state.rk = rolled;
      state.cks.fill(0);
      state.pn = state.ns;
      state.cks = chainFromRoot(rolled, sendDir(state.role));
      state.ns = 0;
      state.peerKemPk.fill(0);
      state.peerKemPk = null;
      if (state.nhkr !== null) {
        state.nhkr.fill(0);
      }
      state.nhkr = rolled.slice();
    }
  }

  // 2. Fresh offer on a new turn or every KEM_STEP_INTERVAL messages; otherwise
  //    keep echoing an unaccepted offer so a dropped one still propagates.
  let kemPk: Uint8Array | null = null;
  if (newTurn || state.sinceOffer >= KEM_STEP_INTERVAL) {
    if (state.sendKemSk !== null) {
      state.sendKemSk.fill(0);
    }
    const keys = ml_kem768.keygen();
    state.sendKemSk = keys.secretKey;
    state.sendKemPk = keys.publicKey;
    kemPk = keys.publicKey;
    state.sinceOffer = 0;
  } else if (state.sendKemPk !== null) {
    kemPk = state.sendKemPk;
  }

  // 3. Symmetric chain step → message key.
  const { mk, next } = chainStep(state.cks);
  state.cks.fill(0);
  state.cks = next;
  const n = state.ns;
  state.ns += 1;
  state.sinceOffer += 1;

  // 4. Encrypt header under the turn's header key, then the body with the header
  //    ciphertext as associated data (binds counters/KEM material to the payload).
  const header: MsgHeader = { n, pn: state.pn, kemPk, kemCt };
  const headerPlain = encodeMsgHeader(header);
  const headerNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const headerCipher = xchacha20poly1305(headerKey(state.hks), headerNonce).encrypt(headerPlain);

  const bodyNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const bodyCipher = xchacha20poly1305(mk, bodyNonce, headerCipher).encrypt(plaintext);
  mk.fill(0);

  state.lastAction = "send";
  return frameMsg(headerNonce, headerCipher, bodyNonce, bodyCipher);
}

export type DecryptResult =
  | { ok: true; plaintext: Uint8Array }
  | { ok: false; reason: "malformed" | "unreadable-header" | "decrypt-failed" | "skip-overflow" };

/** Decrypt one MSG-envelope body, advancing the receiving ratchet. Total: every
 * failure is a typed reason, never a throw. On failure the real state is left
 * unchanged (all mutation happens on a scratch copy, committed only on success),
 * so a later, in-order copy can still be processed. */
export function ratchetDecrypt(state: RatchetState, body: Uint8Array): DecryptResult {
  const framed = unframeMsg(body);
  if (framed === null) {
    return { ok: false, reason: "malformed" };
  }

  // Pick the header key: current turn (hkr), else the peer's next turn (nhkr).
  let header = tryReadHeader(state.hkr, framed);
  let usedNext = false;
  if (header === null && state.nhkr !== null) {
    header = tryReadHeader(state.nhkr, framed);
    usedNext = header !== null;
  }
  if (header === null) {
    return { ok: false, reason: "unreadable-header" };
  }

  // A new turn is entered only via its KEM-accept (the first message carries the
  // ciphertext that rolls the root). A *later* message of a new turn arriving
  // before that accept cannot be advanced to - the transport delivers per-sender
  // roughly in order, so we defer it (: cross-turn reordering unsupported
  // under header encryption). It stays queued server-side for a re-read.
  if (usedNext && header.kemCt === null) {
    return { ok: false, reason: "decrypt-failed" };
  }

  // Served from the skip cache (an out-of-order earlier message of the *current*
  // receiving chain). A new-chain message (usedNext) can never be a cache hit -
  // it is the first time we touch that chain.
  if (!usedNext) {
    const cacheKey = `${state.recvChainId}:${header.n}`;
    const cached = state.skipped.get(cacheKey);
    if (cached !== undefined) {
      const pt = tryDecryptBody(cached, framed);
      if (pt === null) {
        return { ok: false, reason: "decrypt-failed" };
      }
      cached.fill(0);
      state.skipped.delete(cacheKey);
      return { ok: true, plaintext: pt };
    }
  }

  // Mutate a scratch copy; commit only on full success (crash/replay safety ).
  const scratch = cloneRecvScratch(state);
  if (usedNext) {
    scratch.hkr.fill(0);
    scratch.hkr = (state.nhkr as Uint8Array).slice();
    if (scratch.nhkr !== null) {
      scratch.nhkr.fill(0);
      scratch.nhkr = null;
    }
  }

  // A KEM-accept header advances the root and opens a new receiving chain.
  if (header.kemCt !== null) {
    if (state.sendKemSk === null) {
      return { ok: false, reason: "decrypt-failed" }; // no offer to accept
    }
    // Flush the tail of the current receiving chain before switching, so any
    // still-missing message from it can be recovered from the skip cache.
    if (!skipTo(scratch, header.pn)) {
      return { ok: false, reason: "skip-overflow" };
    }
    let ss: Uint8Array;
    try {
      ss = ml_kem768.decapsulate(header.kemCt, state.sendKemSk);
    } catch {
      return { ok: false, reason: "decrypt-failed" };
    }
    const rolled = rootStep(scratch.rk, ss);
    ss.fill(0);
    scratch.rk.fill(0);
    scratch.rk = rolled;
    scratch.ckr?.fill(0);
    scratch.ckr = chainFromRoot(rolled, recvDir(state.role));
    scratch.nr = 0;
    scratch.recvChainId += 1;
    if (scratch.nhkr !== null) {
      scratch.nhkr.fill(0);
    }
    scratch.nhkr = rolled.slice();
  }

  if (scratch.ckr === null) {
    return { ok: false, reason: "decrypt-failed" };
  }
  // Already consumed in this chain and not in the skip cache: a duplicate or an
  // evicted key. Reject rather than rewind nr.
  if (header.n < scratch.nr) {
    return { ok: false, reason: "decrypt-failed" };
  }

  // Skip forward to header.n, caching intermediate message keys.
  if (!skipTo(scratch, header.n)) {
    return { ok: false, reason: "skip-overflow" };
  }
  const step = chainStep(scratch.ckr);
  scratch.ckr.fill(0);
  scratch.ckr = step.next;
  scratch.nr = header.n + 1;

  const pt = tryDecryptBody(step.mk, framed);
  step.mk.fill(0);
  if (pt === null) {
    return { ok: false, reason: "decrypt-failed" };
  }

  // Commit: record the peer's new offer, then adopt the scratch receive fields.
  if (header.kemPk !== null) {
    if (state.peerKemPk !== null) {
      state.peerKemPk.fill(0);
    }
    state.peerKemPk = header.kemPk.slice();
  }
  commitRecvScratch(state, scratch);
  state.lastAction = "recv";
  return { ok: true, plaintext: pt };
}

// ----- skip / scratch helpers ---------------------------------------------

interface RecvScratch {
  rk: Uint8Array;
  ckr: Uint8Array | null;
  nr: number;
  recvChainId: number;
  hkr: Uint8Array;
  nhkr: Uint8Array | null;
  skipped: Map<string, Uint8Array>;
}

function cloneRecvScratch(state: RatchetState): RecvScratch {
  const skipped = new Map<string, Uint8Array>();
  for (const [k, v] of state.skipped) {
    skipped.set(k, v.slice());
  }
  return {
    rk: state.rk.slice(),
    ckr: state.ckr === null ? null : state.ckr.slice(),
    nr: state.nr,
    recvChainId: state.recvChainId,
    hkr: state.hkr.slice(),
    nhkr: state.nhkr === null ? null : state.nhkr.slice(),
    skipped,
  };
}

function commitRecvScratch(state: RatchetState, scratch: RecvScratch): void {
  state.rk.fill(0);
  state.rk = scratch.rk;
  state.ckr?.fill(0);
  state.ckr = scratch.ckr;
  state.nr = scratch.nr;
  state.recvChainId = scratch.recvChainId;
  state.hkr.fill(0);
  state.hkr = scratch.hkr;
  if (state.nhkr !== null) {
    state.nhkr.fill(0);
  }
  state.nhkr = scratch.nhkr;
  for (const v of state.skipped.values()) {
    v.fill(0);
  }
  state.skipped = scratch.skipped;
}

/** Cache message keys nr..target-1 of the current receiving chain, so an
 * out-of-order earlier message can still be decrypted. Returns false if
 * the skip cache would exceed MAX_SKIP. */
function skipTo(scratch: RecvScratch, target: number): boolean {
  if (scratch.ckr === null || target <= scratch.nr) {
    return true;
  }
  if (target - scratch.nr > MAX_SKIP || scratch.skipped.size + (target - scratch.nr) > MAX_SKIP) {
    return false;
  }
  for (let i = scratch.nr; i < target; i += 1) {
    const step = chainStep(scratch.ckr);
    scratch.ckr.fill(0);
    scratch.ckr = step.next;
    scratch.skipped.set(`${scratch.recvChainId}:${i}`, step.mk);
  }
  scratch.nr = target;
  return true;
}

// ----- header/body crypto over a framed body ------------------------------

interface FramedMsg {
  headerNonce: Uint8Array;
  headerCipher: Uint8Array;
  bodyNonce: Uint8Array;
  bodyCipher: Uint8Array;
}

function tryReadHeader(root: Uint8Array, framed: FramedMsg): MsgHeader | null {
  let plain: Uint8Array;
  try {
    plain = xchacha20poly1305(headerKey(root), framed.headerNonce).decrypt(framed.headerCipher);
  } catch {
    return null;
  }
  return decodeMsgHeader(plain);
}

function tryDecryptBody(mk: Uint8Array, framed: FramedMsg): Uint8Array | null {
  try {
    return xchacha20poly1305(mk, framed.bodyNonce, framed.headerCipher).decrypt(framed.bodyCipher);
  } catch {
    return null;
  }
}

// ----- framing (nonce/len prefixed; the envelope adds version+type) --------

function frameMsg(
  headerNonce: Uint8Array,
  headerCipher: Uint8Array,
  bodyNonce: Uint8Array,
  bodyCipher: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(
    NONCE_BYTES + 2 + headerCipher.length + NONCE_BYTES + 4 + bodyCipher.length,
  );
  const view = new DataView(out.buffer);
  let off = 0;
  out.set(headerNonce, off);
  off += NONCE_BYTES;
  view.setUint16(off, headerCipher.length, false);
  off += 2;
  out.set(headerCipher, off);
  off += headerCipher.length;
  out.set(bodyNonce, off);
  off += NONCE_BYTES;
  view.setUint32(off, bodyCipher.length, false);
  off += 4;
  out.set(bodyCipher, off);
  return out;
}

function unframeMsg(body: Uint8Array): FramedMsg | null {
  if (body.length < NONCE_BYTES + 2) {
    return null;
  }
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let off = 0;
  const headerNonce = body.slice(off, off + NONCE_BYTES);
  off += NONCE_BYTES;
  const headerLen = view.getUint16(off, false);
  off += 2;
  if (off + headerLen + NONCE_BYTES + 4 > body.length) {
    return null;
  }
  const headerCipher = body.slice(off, off + headerLen);
  off += headerLen;
  const bodyNonce = body.slice(off, off + NONCE_BYTES);
  off += NONCE_BYTES;
  const bodyLen = view.getUint32(off, false);
  off += 4;
  if (off + bodyLen !== body.length) {
    return null;
  }
  const bodyCipher = body.slice(off, off + bodyLen);
  return { headerNonce, headerCipher, bodyNonce, bodyCipher };
}
