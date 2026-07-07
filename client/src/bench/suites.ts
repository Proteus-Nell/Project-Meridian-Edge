// Benchmark suites B1-B3 (MVP_DOC.md §8): primitive latency and size overhead,
// PQC (@noble/post-quantum) vs classical baselines (@noble/curves).
//
// The classical baselines are the ONLY classical asymmetric crypto in the
// client, and they exist purely as a measurement yardstick (B1/B2). They live
// under client/src/bench/ (excluded from scripts/audit.py, mirroring the
// top-level bench/ rule) and are pulled in via dynamic import(), so they land
// in a lazy chunk that is fetched only when /bench runs - never in the main
// bundle, keeping the B5 "PQC bundle delta" measurement honest.

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  ML_DSA_65_PUBKEY_BYTES,
  ML_DSA_65_SIG_BYTES,
  ML_KEM_768_CT_BYTES,
  ML_KEM_768_PUBKEY_BYTES,
  OPK_BATCH_MAX,
} from "../crypto/constants";
import { initiateKx, respondKx } from "../crypto/kx";
import type { Bundle, PrekeyLookup } from "../crypto/kx";
import { generateOpkBatch, generateSpk } from "../crypto/prekeys";
import { initRatchet, ratchetDecrypt, ratchetEncrypt } from "../crypto/ratchet";
import { timeit } from "./harness";
import type { Stats } from "./harness";

export interface BenchConfig {
  readonly warmup: number;
  readonly iters: number;
  /** Yield to the event loop every N samples (interactive responsiveness). */
  readonly yieldEvery: number;
}

export const DEFAULT_CONFIG: BenchConfig = { warmup: 100, iters: 1000, yieldEvery: 64 };

export interface LatencyRow {
  readonly op: string;
  readonly pqc: Stats;
  readonly classical: Stats;
}

export interface LatencyResult {
  readonly kind: "latency";
  readonly suite: "B1" | "B2";
  readonly title: string;
  readonly pqcName: string;
  readonly classicalName: string;
  readonly note?: string;
  readonly rows: readonly LatencyRow[];
}

export interface SizeRow {
  readonly object: string;
  readonly classicalBytes: number;
  readonly pqcBytes: number;
}

export interface SizeResult {
  readonly kind: "size";
  readonly suite: "B3";
  readonly title: string;
  readonly rows: readonly SizeRow[];
}

export interface ProtocolRow {
  readonly metric: string;
  readonly stats: Stats;
  /** latency rows report median/p95; throughput rows headline ops/sec. */
  readonly display: "latency" | "throughput";
  readonly unit: string;
}

export interface ProtocolResult {
  readonly kind: "protocol";
  readonly suite: "B4";
  readonly title: string;
  readonly note?: string;
  readonly rows: readonly ProtocolRow[];
}

export type SuiteResult = LatencyResult | SizeResult | ProtocolResult;

// Classical primitives run ~100x faster than the PQC ones, near the browser's
// clamped timer resolution, so they time more calls per sample (see harness).
const PQC_SLOW_BATCH = 1; // ML-DSA sign/keygen: ~1-2 ms each
const PQC_FAST_BATCH = 8; // ML-KEM ops: ~0.1 ms each
const CLASSICAL_BATCH = 64; // X25519/Ed25519: tens of microseconds

const MESSAGE = new TextEncoder().encode("PQTerm benchmark fixed message");

type Classical = {
  ed25519: typeof import("@noble/curves/ed25519.js")["ed25519"];
  x25519: typeof import("@noble/curves/ed25519.js")["x25519"];
};

async function loadClassical(): Promise<Classical> {
  const mod = await import("@noble/curves/ed25519.js");
  return { ed25519: mod.ed25519, x25519: mod.x25519 };
}

/** B1 - KEM primitive latency: ML-KEM-768 vs X25519.
 *
 * DH has no split encaps/decaps, so X25519's shared-secret derivation is the
 * closest analog to both; the classical encaps/decaps rows report that single
 * `getSharedSecret` measurement (noted in the report). */
export async function benchB1(cfg: BenchConfig): Promise<LatencyResult> {
  const { warmup, iters, yieldEvery } = cfg;
  const { x25519 } = await loadClassical();

  // Fixed inputs prepared outside the timed regions.
  const kem = ml_kem768.keygen();
  const kemCt = ml_kem768.encapsulate(kem.publicKey).cipherText;
  const xSk = x25519.utils.randomSecretKey();
  const xPeer = x25519.getPublicKey(x25519.utils.randomSecretKey());

  const kemKeygen = await timeit("ml-kem keygen", () => void ml_kem768.keygen(), {
    warmup,
    iters,
    batch: PQC_FAST_BATCH,
    yieldEvery,
  });
  const kemEncaps = await timeit("ml-kem encaps", () => void ml_kem768.encapsulate(kem.publicKey), {
    warmup,
    iters,
    batch: PQC_FAST_BATCH,
    yieldEvery,
  });
  const kemDecaps = await timeit(
    "ml-kem decaps",
    () => void ml_kem768.decapsulate(kemCt, kem.secretKey),
    { warmup, iters, batch: PQC_FAST_BATCH, yieldEvery },
  );
  const xKeygen = await timeit(
    "x25519 keygen",
    () => void x25519.getPublicKey(x25519.utils.randomSecretKey()),
    { warmup, iters, batch: CLASSICAL_BATCH, yieldEvery },
  );
  const xDerive = await timeit("x25519 derive", () => void x25519.getSharedSecret(xSk, xPeer), {
    warmup,
    iters,
    batch: CLASSICAL_BATCH,
    yieldEvery,
  });

  return {
    kind: "latency",
    suite: "B1",
    title: "B1 - KEM primitive latency",
    pqcName: "ML-KEM-768",
    classicalName: "X25519",
    note: "X25519 has no split encaps/decaps; both rows show the single DH getSharedSecret.",
    rows: [
      { op: "keygen", pqc: kemKeygen, classical: xKeygen },
      { op: "encaps", pqc: kemEncaps, classical: xDerive },
      { op: "decaps", pqc: kemDecaps, classical: xDerive },
    ],
  };
}

/** B2 - signature primitive latency: ML-DSA-65 vs Ed25519. */
export async function benchB2(cfg: BenchConfig): Promise<LatencyResult> {
  const { warmup, iters, yieldEvery } = cfg;
  const { ed25519 } = await loadClassical();

  const dsa = ml_dsa65.keygen();
  const dsaSig = ml_dsa65.sign(MESSAGE, dsa.secretKey);
  const edSk = ed25519.utils.randomSecretKey();
  const edPk = ed25519.getPublicKey(edSk);
  const edSig = ed25519.sign(MESSAGE, edSk);

  const dsaKeygen = await timeit("ml-dsa keygen", () => void ml_dsa65.keygen(), {
    warmup,
    iters,
    batch: PQC_SLOW_BATCH,
    yieldEvery,
  });
  const dsaSign = await timeit("ml-dsa sign", () => void ml_dsa65.sign(MESSAGE, dsa.secretKey), {
    warmup,
    iters,
    batch: PQC_SLOW_BATCH,
    yieldEvery,
  });
  const dsaVerify = await timeit(
    "ml-dsa verify",
    () => void ml_dsa65.verify(dsaSig, MESSAGE, dsa.publicKey),
    { warmup, iters, batch: PQC_FAST_BATCH, yieldEvery },
  );
  const edKeygen = await timeit(
    "ed25519 keygen",
    () => void ed25519.getPublicKey(ed25519.utils.randomSecretKey()),
    { warmup, iters, batch: CLASSICAL_BATCH, yieldEvery },
  );
  const edSign = await timeit("ed25519 sign", () => void ed25519.sign(MESSAGE, edSk), {
    warmup,
    iters,
    batch: CLASSICAL_BATCH,
    yieldEvery,
  });
  const edVerify = await timeit("ed25519 verify", () => void ed25519.verify(edSig, MESSAGE, edPk), {
    warmup,
    iters,
    batch: CLASSICAL_BATCH,
    yieldEvery,
  });

  return {
    kind: "latency",
    suite: "B2",
    title: "B2 - signature primitive latency",
    pqcName: "ML-DSA-65",
    classicalName: "Ed25519",
    rows: [
      { op: "keygen", pqc: dsaKeygen, classical: edKeygen },
      { op: "sign", pqc: dsaSign, classical: edSign },
      { op: "verify", pqc: dsaVerify, classical: edVerify },
    ],
  };
}

// Classical baseline sizes (bytes) for the analytic composite rows.
const X25519_KEY = 32;
const X25519_SHARE = 32;
const ED25519_SIG = 64;
const ED25519_PUBKEY = 32;
const SHA512_HASH = 64; // OPK leaf-hash size, same both worlds

/** B3 - size overhead: PQC key/ciphertext/signature sizes vs classical, plus
 * composite protocol objects. Primitive sizes are measured from real generated
 * objects; the classical composites are analytic (there is no classical
 * implementation of this protocol - the point is what it *would* cost). */
export function benchB3(): SizeResult {
  // Measured from real objects (asserts the constants match the library).
  const kemPub = ml_kem768.keygen().publicKey.length;
  const kemCt = ml_kem768.encapsulate(ml_kem768.keygen().publicKey).cipherText.length;
  const dsaPub = ml_dsa65.keygen().publicKey.length;
  const dsaSig = ml_dsa65.sign(MESSAGE, ml_dsa65.keygen().secretKey).length;

  // Per-registration bundle: IK pub + SPK pub + SPK sig + N one-time prekey
  // pubs + a batch signature + N leaf hashes (server-retained for per-OPK
  // verification). Classical analog swaps each PQC object for its baseline.
  const n = OPK_BATCH_MAX;
  const pqcBundle = dsaPub + kemPub + dsaSig + n * kemPub + dsaSig + n * SHA512_HASH;
  const classicalBundle =
    ED25519_PUBKEY + X25519_KEY + ED25519_SIG + n * X25519_KEY + ED25519_SIG + n * SHA512_HASH;

  // Per-handshake (PQ-KX first message, no OPK path shown): IK_A + ct1 + sig_A
  // + a small AEAD payload. Classical X3DH-style analog: IK + ephemeral share
  // + signature.
  const AEAD_OVERHEAD = 24 + 16; // XChaCha nonce + Poly1305 tag
  const pqcHandshake = dsaPub + kemCt + dsaSig + AEAD_OVERHEAD;
  const classicalHandshake = ED25519_PUBKEY + X25519_SHARE + ED25519_SIG + AEAD_OVERHEAD;

  // Per-ratchet-step: a KEM step carries a fresh public key + a ciphertext in
  // the header. Classical DH ratchet carries a single ephemeral public key.
  const pqcRatchetStep = kemPub + kemCt;
  const classicalRatchetStep = X25519_KEY;

  return {
    kind: "size",
    suite: "B3",
    title: "B3 - size overhead (bytes)",
    rows: [
      { object: "KEM/DH public key", classicalBytes: X25519_KEY, pqcBytes: kemPub },
      { object: "KEM ciphertext / DH share", classicalBytes: X25519_SHARE, pqcBytes: kemCt },
      { object: "Signature", classicalBytes: ED25519_SIG, pqcBytes: dsaSig },
      { object: "Signature public key", classicalBytes: ED25519_PUBKEY, pqcBytes: dsaPub },
      {
        object: `Registration bundle (${n} OPKs)`,
        classicalBytes: classicalBundle,
        pqcBytes: pqcBundle,
      },
      { object: "Handshake first message", classicalBytes: classicalHandshake, pqcBytes: pqcHandshake },
      { object: "Ratchet KEM step header", classicalBytes: classicalRatchetStep, pqcBytes: pqcRatchetStep },
    ],
  };
}

interface ProtocolFixture {
  readonly alicePub: Uint8Array;
  readonly aliceSec: Uint8Array;
  readonly bobPub: Uint8Array;
  readonly bundle: Bundle;
  readonly lookup: PrekeyLookup;
}

/** A self-contained handshake fixture: two ML-DSA identities and a signed
 * prekey bundle for Bob, exactly as the real protocol builds one. */
function buildProtocolFixture(): ProtocolFixture {
  const alice = ml_dsa65.keygen();
  const bob = ml_dsa65.keygen();
  const spk = generateSpk(bob.secretKey);
  const batch = generateOpkBatch(bob.secretKey, 1);
  const opkPub = batch.pubs[0];
  const opkSec = batch.secs[0];
  if (opkPub === undefined || opkSec === undefined) {
    throw new Error("prekey fixture generation failed");
  }
  const spkHash = bytesToHex(sha512(spk.pub));
  const opkHash = bytesToHex(sha512(opkPub));
  return {
    alicePub: alice.publicKey,
    aliceSec: alice.secretKey,
    bobPub: bob.publicKey,
    bundle: {
      ikPub: bob.publicKey,
      spkPub: spk.pub,
      spkSig: spk.sig,
      opk: { pub: opkPub, index: 0, leaves: batch.leaves, rootSig: batch.rootSig },
    },
    lookup: {
      spkByHash: (h) => (h === spkHash ? { pub: spk.pub, sec: spk.sec, storeKey: "spk/1" } : null),
      opkByHash: (h) => (h === opkHash ? { pub: opkPub, sec: opkSec, storeKey: "opk/1" } : null),
    },
  };
}

/** B4 - protocol-level latency and throughput (MVP §8). Measures the crypto
 * cost of the real handshake and ratchet paths; network RTT is excluded (it is
 * identical for classical and PQC). Protocol metrics use >=100 iterations. */
export async function benchB4(cfg: BenchConfig): Promise<ProtocolResult> {
  const warmup = Math.min(cfg.warmup, 20);
  const iters = Math.min(cfg.iters, 200);
  const { yieldEvery } = cfg;
  const fx = buildProtocolFixture();

  // Time-to-first-message: the initiator's cost to produce the first sealed
  // message (verifyBundle + ML-KEM encaps + ML-DSA sign + AEAD).
  const ttfm = await timeit(
    "ttfm",
    () => void initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE),
    { warmup, iters, batch: 1, yieldEvery },
  );

  // Full handshake, both sides: initiate + respond (decaps + verify + derive).
  const handshake = await timeit(
    "handshake",
    () => {
      const { envelope } = initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE);
      respondKx(fx.bobPub, fx.lookup, envelope);
    },
    { warmup, iters, batch: 1, yieldEvery },
  );

  // Sustained ratchet throughput on one established session, alternating
  // direction so every message drives a fresh KEM step (the PQC-heavy path).
  const opened = initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE);
  const responded = respondKx(fx.bobPub, fx.lookup, opened.envelope);
  if (!responded.ok) {
    throw new Error(`protocol fixture handshake failed: ${responded.reason}`);
  }
  const aState = initRatchet(opened.session.rk, opened.session.role);
  const bState = initRatchet(responded.session.rk, responded.session.role);
  let aToB = true;
  const throughput = await timeit(
    "ratchet-msg",
    () => {
      const result = aToB
        ? ratchetDecrypt(bState, ratchetEncrypt(aState, MESSAGE))
        : ratchetDecrypt(aState, ratchetEncrypt(bState, MESSAGE));
      if (!result.ok) {
        throw new Error(`ratchet throughput desync: ${result.reason}`);
      }
      aToB = !aToB;
    },
    { warmup, iters, batch: 1, yieldEvery },
  );

  return {
    kind: "protocol",
    suite: "B4",
    title: "B4 - protocol level",
    note: "Crypto only, no network RTT. A 4x-CPU-throttle handshake (browser devtools) is ~4x the handshake row.",
    rows: [
      { metric: "time-to-first-message (send)", stats: ttfm, display: "latency", unit: "op" },
      { metric: "handshake round-trip", stats: handshake, display: "latency", unit: "op" },
      { metric: "sustained ratchet message", stats: throughput, display: "throughput", unit: "msg" },
    ],
  };
}

// Re-exported so the executor path and tests share one source of truth for the
// measured primitive sizes matching the constants.
export const MEASURED_PRIMITIVE_SIZES = {
  kemPub: ML_KEM_768_PUBKEY_BYTES,
  kemCt: ML_KEM_768_CT_BYTES,
  dsaPub: ML_DSA_65_PUBKEY_BYTES,
  dsaSig: ML_DSA_65_SIG_BYTES,
} as const;
