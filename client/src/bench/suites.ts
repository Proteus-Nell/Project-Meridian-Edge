// Benchmark suites B1-B3: primitive latency and size overhead,
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
import {
  initRatchet,
  ratchetDecrypt,
  ratchetEncrypt,
  KEM_STEP_INTERVAL,
  MAX_SKIP,
} from "../crypto/ratchet";
import type { RatchetState } from "../crypto/ratchet";
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
  /** Absent when the classical side has no operation of its own to time, and
   * its baseline is reported once on a different row (B1 decaps - see the
   * result's note). Renders as "-" rather than repeating the other row's
   * number, which would read as a second measurement. */
  readonly classical?: Stats;
}

/** How many times a suite actually ran each of its rows. A "sample" is one
 * timed region, and each one executes `Stats.batch` calls - so a row runs
 * `samples x batch` calls in total, which is what the report states. B4 caps
 * these below the configured values, so every suite declares its own. */
export interface RunCounts {
  /** Timed samples per row (each one a batch of calls). */
  readonly samples: number;
  /** Untimed runs discarded before sampling, per row. */
  readonly warmup: number;
}

export interface LatencyResult extends RunCounts {
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
  /** How the *PQC* figure was obtained: "measured" from a real generated object
   * or a real serialized envelope, "analytic" from a byte-layout model. The
   * classical column is analytic on every row - there is no classical
   * implementation of this protocol to measure (see the result's note). */
  readonly basis: "measured" | "analytic";
}

export interface SizeResult {
  readonly kind: "size";
  readonly suite: "B3";
  readonly title: string;
  readonly note?: string;
  readonly rows: readonly SizeRow[];
}

export interface ProtocolRow {
  readonly metric: string;
  readonly stats: Stats;
  /** latency rows report median/p95; throughput rows headline ops/sec. */
  readonly display: "latency" | "throughput";
  readonly unit: string;
}

/** One primitive's contribution to a protocol operation: how many times it is
 * called, and what B1/B2 measured one call to cost. */
export interface BreakdownComponent {
  readonly label: string;
  readonly count: number;
  readonly eachMs: number;
}

/** A protocol row priced from its constituent primitives, so "where does the
 * time go" is answered in the report rather than left as arithmetic for the
 * reader. The residual (measured - predicted) is everything the composition
 * does not name: hashing, HKDF, AEAD, framing, allocation. */
export interface BreakdownEntry {
  readonly metric: string;
  readonly components: readonly BreakdownComponent[];
  readonly predictedMs: number;
  readonly measuredMs: number;
}

/** B1/B2 medians for the four primitives a handshake calls. */
export interface PrimitiveMedians {
  readonly kemName: string;
  readonly dsaName: string;
  readonly encapsMs: number;
  readonly decapsMs: number;
  readonly signMs: number;
  readonly verifyMs: number;
}

/** Pull the primitive medians out of B1/B2 results that have already run.
 *
 * Returns null unless both suites are present, which is what makes the
 * breakdown optional: `/bench b4` on its own has nothing to predict from, and
 * B4 must never re-run B1/B2 to get it - that would add their cost to the
 * session B4 is timing. */
export function primitiveMedians(results: readonly SuiteResult[]): PrimitiveMedians | null {
  let kem: LatencyResult | undefined;
  let dsa: LatencyResult | undefined;
  for (const result of results) {
    if (result.kind !== "latency") {
      continue;
    }
    if (result.suite === "B1") {
      kem = result;
    } else {
      dsa = result;
    }
  }
  if (kem === undefined || dsa === undefined) {
    return null;
  }
  const median = (result: LatencyResult, op: string): number | undefined =>
    result.rows.find((row) => row.op === op)?.pqc.medianMs;
  const encapsMs = median(kem, "encaps");
  const decapsMs = median(kem, "decaps");
  const signMs = median(dsa, "sign");
  const verifyMs = median(dsa, "verify");
  if (
    encapsMs === undefined ||
    decapsMs === undefined ||
    signMs === undefined ||
    verifyMs === undefined
  ) {
    return null;
  }
  return { kemName: kem.pqcName, dsaName: dsa.pqcName, encapsMs, decapsMs, signMs, verifyMs };
}

export interface ProtocolResult extends RunCounts {
  readonly kind: "protocol";
  readonly suite: "B4";
  readonly title: string;
  /** Present only when B1/B2 ran first (see primitiveMedians). */
  readonly breakdown?: readonly BreakdownEntry[];
  readonly note?: string;
  readonly rows: readonly ProtocolRow[];
}

export type SuiteResult = LatencyResult | SizeResult | ProtocolResult;

// Batch sizes keep one timed sample well above the browser's clamped
// performance.now() resolution: the faster the primitive, the more calls per
// sample (see harness). The per-op costs behind this ordering are not asserted
// here - B1/B2 measure and report them.
//
// The batch also sets each row's quantisation floor (CLOCK_CLAMP_MS / batch),
// which the report states per suite. Bigger is finer, at the cost of a longer
// uninterruptible sample: at batch 32 an ML-KEM row spends roughly 16 ms per
// sample, which the event-loop yield between samples keeps comfortable.
const PQC_SLOW_BATCH = 1; // ML-DSA keygen/sign: slowest, one call per sample
const PQC_FAST_BATCH = 32; // ML-KEM ops (and ML-DSA verify)
const CLASSICAL_BATCH = 64; // X25519/Ed25519: fastest, closest to the timer floor

const MESSAGE = new TextEncoder().encode("Meridian Edge benchmark fixed message");

/** The payload every measured handshake row carries, exported so the test can
 * reconstruct the expected envelope length from envelope.ts's byte layout
 * rather than trusting the harness's own arithmetic. */
export const BENCH_MESSAGE_BYTES = MESSAGE.length;

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
 * closest analog to both ML-KEM halves. It is timed once and reported on the
 * encaps row; the decaps row carries no classical cell at all, so the one
 * measurement can never be mistaken for two. */
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
    samples: iters,
    warmup,
    note:
      "X25519 has no split encaps/decaps. The single getSharedSecret measurement shown on the " +
      "encaps row is the classical baseline for both ML-KEM encaps and decaps; the decaps row " +
      "leaves its classical cells blank rather than repeat that one number as if it were two.",
    rows: [
      { op: "keygen", pqc: kemKeygen, classical: xKeygen },
      { op: "encaps", pqc: kemEncaps, classical: xDerive },
      // No classical cell: the baseline for decaps is the encaps row's figure.
      { op: "decaps", pqc: kemDecaps },
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
    samples: iters,
    warmup,
    rows: [
      { op: "keygen", pqc: dsaKeygen, classical: edKeygen },
      { op: "sign", pqc: dsaSign, classical: edSign },
      { op: "verify", pqc: dsaVerify, classical: edVerify },
    ],
  };
}

/** Steady-state ratchet message sizes, measured off real `ratchetEncrypt`
 * output in both directions of the KEM-step rule.
 *
 * The two modes are not the same size, and the difference is not the one the
 * timings suggest. `ratchetEncrypt` echoes an unaccepted offer on every send
 * (`sendKemPk` is replaced by a fresh keygen, never cleared), so a burst - where
 * the peer never replies to accept - carries the 1,184-byte public key on every
 * message while paying the keygen only every KEM_STEP_INTERVAL. The interval
 * buys a 10x cut in keygen cost and nothing at all on the wire.
 *
 * Alternating is measured on the *second* send: the first send of a session has
 * no offer to accept yet, so it is a burst-shaped message. */
function measureRatchetBodies(): { alternating: number; burst: number } {
  const open = (): { a: RatchetState; b: RatchetState } => {
    const fx = buildProtocolFixture();
    const opened = initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE);
    const responded = respondKx(fx.bobPub, fx.lookup, opened.envelope);
    if (!responded.ok) {
      throw new Error(`ratchet size fixture failed: ${responded.reason}`);
    }
    return {
      a: initRatchet(opened.session.rk, opened.session.role),
      b: initRatchet(responded.session.rk, responded.session.role),
    };
  };

  // Burst: one party sends without a reply, so no offer is ever accepted.
  const burstPair = open();
  const burst = ratchetEncrypt(burstPair.a, MESSAGE).length;

  // Alternating: A sends, B reads it, and B's reply both accepts A's offer and
  // makes its own - the steady state where every message carries a KEM step.
  const turnPair = open();
  const first = ratchetEncrypt(turnPair.a, MESSAGE);
  const read = ratchetDecrypt(turnPair.b, first);
  if (!read.ok) {
    throw new Error(`ratchet size fixture desync: ${read.reason}`);
  }
  const alternating = ratchetEncrypt(turnPair.b, MESSAGE).length;
  return { alternating, burst };
}

// Classical baseline sizes (bytes) for the analytic composite rows.
const X25519_KEY = 32;
const X25519_SHARE = 32;
const ED25519_SIG = 64;
const ED25519_PUBKEY = 32;
const SHA512_HASH = 64; // OPK leaf-hash size, same both worlds

/** B3 - size overhead: PQC key/ciphertext/signature sizes vs classical, plus
 * composite protocol objects.
 *
 * Every row states its `basis`. The primitives are measured from real generated
 * objects, the handshake rows are the length of a real `encodeKxEnvelope`
 * output, and the ratchet rows the length of a real `ratchetEncrypt` body - not
 * byte-layout sums, so the table cannot drift from the wire format the way an
 * analytic figure silently did. Only the registration bundle stays a model.
 *
 * The classical column is analytic on every row: there is no classical
 * implementation of this protocol, so it prices *this* construction with
 * classical primitives rather than quoting a deployed X3DH stack. It includes
 * the envelope framing, because the PQC side is a whole measured message and
 * comparing that against bare classical crypto flattered the factor. The note
 * spells out where the modelling matters most (the batch-leaf hashes). */
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
  // Those leaf hashes exist because *this* protocol batch-signs its OPKs, and
  // they dominate the classical figure. A real X3DH bundle carries none, so the
  // note quotes the leaf-free factor too - otherwise the headline reads as a
  // comparison against deployed X3DH, which it is not.
  const bundleLeafBytes = n * SHA512_HASH;
  const bundleFactor = Math.round(pqcBundle / classicalBundle);
  const bundleFactorNoLeaves = Math.round(pqcBundle / (classicalBundle - bundleLeafBytes));

  // Per-handshake: the real serialized KX envelope, measured both ways round.
  // A first contact normally consumes an OPK (its ct2 + a routing hash); the
  // SPK-only path is the reduced-FS degradation, and is 1,152 bytes lighter.
  const fx = buildProtocolFixture();
  const withOpkBytes = initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE).envelope.length;
  // A bundle the server hands out when a UID's one-time prekeys are exhausted:
  // the same bundle with no OPK, exactly as `Bundle.opk === null` models it.
  const noOpkBytes = initiateKx(fx.alicePub, fx.aliceSec, { ...fx.bundle, opk: null }, MESSAGE)
    .envelope.length;
  // Classical analog, priced at the same payload AND the same envelope framing
  // so the columns are like-for-like. The PQC figure is a measured envelope, so
  // pricing the classical side as bare crypto (IK + share + sig + AEAD) was
  // comparing a whole message against its payload: it understated the classical
  // row by 71-135 bytes and inflated the with-OPK factor from x22 to x37.
  // Framing is algorithm-independent - transcribed from crypto/envelope.ts:
  //   u8 version | u8 type | u8 flags | spkHash(64) | [opkHash(64)] | u32be len
  const KX_FRAME_FIXED = 3 + SHA512_HASH + 4;
  const AEAD_OVERHEAD = 24 + 16; // XChaCha nonce + Poly1305 tag
  const classicalCrypto =
    ED25519_PUBKEY + X25519_SHARE + ED25519_SIG + AEAD_OVERHEAD + MESSAGE.length;
  const classicalNoOpk = classicalCrypto + KX_FRAME_FIXED;
  // The OPK costs the classical side only its routing hash; the KEM path pays
  // that plus a second ciphertext, which is the whole 1,152-byte difference.
  const classicalWithOpk = classicalNoOpk + SHA512_HASH;

  // Per ratchet message, measured off real `ratchetEncrypt` output rather than
  // priced as bare KEM material. The two modes differ on the wire, and only one
  // of them was ever represented here.
  const ratchetBodies = measureRatchetBodies();
  // Same body with the KEM material swapped for a DH ratchet key: classical
  // carries one ephemeral public key in either mode, with no accept ciphertext.
  const classicalAlternating = ratchetBodies.alternating - (kemPub + kemCt) + X25519_KEY;
  const classicalBurst = ratchetBodies.burst - kemPub + X25519_KEY;

  return {
    kind: "size",
    suite: "B3",
    title: "B3 - size overhead (bytes)",
    note:
      "The classical column is analytic on every row: there is no classical implementation of " +
      "this protocol, so it prices this construction with classical primitives - including its " +
      "envelope framing and the same payload, so a measured PQC message is compared against a " +
      "whole classical message rather than against its payload. That matters most on the bundle " +
      `row, where ${bundleLeafBytes.toLocaleString("en-US")} of the classical ` +
      `${classicalBundle.toLocaleString("en-US")} bytes are SHA-512 batch-leaf hashes carried only ` +
      "because this protocol batch-signs its OPKs; a real X3DH bundle has none, which puts that " +
      `row nearer x${bundleFactorNoLeaves} than the x${bundleFactor} shown. The handshake and ` +
      `ratchet rows are measured, carrying the fixed ${MESSAGE.length}-byte message. A one-time ` +
      "prekey costs the classical side only its routing hash, against a routing hash plus a whole " +
      "second ciphertext for the KEM. The two ratchet rows differ because an unaccepted KEM offer " +
      "is echoed on every send: a burst pays the keygen once per KEM_STEP_INTERVAL but carries " +
      "the public key every single message, so the interval buys compute, not bytes.",
    rows: [
      {
        object: "KEM/DH public key",
        classicalBytes: X25519_KEY,
        pqcBytes: kemPub,
        basis: "measured",
      },
      {
        object: "KEM ciphertext / DH share",
        classicalBytes: X25519_SHARE,
        pqcBytes: kemCt,
        basis: "measured",
      },
      { object: "Signature", classicalBytes: ED25519_SIG, pqcBytes: dsaSig, basis: "measured" },
      {
        object: "Signature public key",
        classicalBytes: ED25519_PUBKEY,
        pqcBytes: dsaPub,
        basis: "measured",
      },
      {
        object: `Registration bundle (${n} OPKs)`,
        classicalBytes: classicalBundle,
        pqcBytes: pqcBundle,
        basis: "analytic",
      },
      {
        object: "Handshake first message (no OPK)",
        classicalBytes: classicalNoOpk,
        pqcBytes: noOpkBytes,
        basis: "measured",
      },
      {
        object: "Handshake first message (with OPK)",
        classicalBytes: classicalWithOpk,
        pqcBytes: withOpkBytes,
        basis: "measured",
      },
      {
        object: "Ratchet message (alternating turns)",
        classicalBytes: classicalAlternating,
        pqcBytes: ratchetBodies.alternating,
        basis: "measured",
      },
      {
        object: "Ratchet message (unidirectional burst)",
        classicalBytes: classicalBurst,
        pqcBytes: ratchetBodies.burst,
        basis: "measured",
      },
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

/** B4 - protocol-level latency and throughput. Measures the crypto
 * cost of the real handshake and ratchet paths; network RTT is excluded (it is
 * identical for classical and PQC). The ratchet is reported twice, at the two
 * ends of the range the KEM-step rule creates: alternating turns pay a step per
 * message, a unidirectional burst amortises one over KEM_STEP_INTERVAL sends.
 *
 * The counts are capped below whatever the config asks for: one sample here is
 * a whole handshake or ratchet step rather than a single primitive, so B1/B2's
 * default 1000 would run for minutes. The caps travel out on the result and the
 * report states them, because a reader comparing B4 against B1/B2 is otherwise
 * comparing different sample sizes without being told. */
export const B4_MAX_WARMUP = 20;
export const B4_MAX_SAMPLES = 200;

/** What one handshake actually calls, traced by hand through crypto/kx.ts:
 *
 *   initiateKx  verifyBundle -> verifySpk           1 ML-DSA verify
 *                            -> verifyOpkInBatch    1 ML-DSA verify
 *               encapsulate(spkPub), encapsulate(opk.pub)  2 ML-KEM encaps
 *               ml_dsa65.sign(transcript)           1 ML-DSA sign
 *   respondKx   ml_dsa65.verify(sig)                1 ML-DSA verify
 *               decapsulate(ct1), decapsulate(ct2)  2 ML-KEM decaps
 *
 * The fixture bundle carries an OPK, so both ct2 paths run; an SPK-only
 * handshake would drop one encaps and one decaps. Nothing else is listed, so
 * the SHA-512 transcript and prekey hashing, HKDF, XChaCha20-Poly1305,
 * envelope framing and allocation all land in the reported residual.
 *
 * These counts are a reading of the source, not an instrumented count - the
 * crypto modules are not instrumented for the benchmark. A wrong count would
 * show up as an implausible residual, which is one reason to print it. */
function buildBreakdown(
  primitives: PrimitiveMedians,
  ttfmMs: number,
  handshakeMs: number,
): BreakdownEntry[] {
  const { kemName, dsaName, encapsMs, decapsMs, signMs, verifyMs } = primitives;
  const verify = (count: number): BreakdownComponent => ({
    label: `${dsaName} verify`,
    count,
    eachMs: verifyMs,
  });
  const encaps: BreakdownComponent = { label: `${kemName} encaps`, count: 2, eachMs: encapsMs };
  const sign: BreakdownComponent = { label: `${dsaName} sign`, count: 1, eachMs: signMs };
  const decaps: BreakdownComponent = { label: `${kemName} decaps`, count: 2, eachMs: decapsMs };

  // The initiator's two bundle verifies plus the responder's signature verify
  // are one line of 3, not two lines of 2 and 1 - the table prices operations,
  // not call sites, and the doc comment above traces where each one comes from.
  const entries: { metric: string; components: BreakdownComponent[]; measuredMs: number }[] = [
    { metric: TTFM_METRIC, components: [verify(2), encaps, sign], measuredMs: ttfmMs },
    {
      metric: HANDSHAKE_METRIC,
      components: [verify(3), encaps, sign, decaps],
      measuredMs: handshakeMs,
    },
  ];
  return entries.map((entry) => ({
    ...entry,
    predictedMs: entry.components.reduce((total, c) => total + c.count * c.eachMs, 0),
  }));
}

const TTFM_METRIC = "time-to-first-message (send)";
const HANDSHAKE_METRIC = "handshake round-trip";

export async function benchB4(
  cfg: BenchConfig,
  primitives?: PrimitiveMedians,
): Promise<ProtocolResult> {
  const warmup = Math.min(cfg.warmup, B4_MAX_WARMUP);
  const iters = Math.min(cfg.iters, B4_MAX_SAMPLES);
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

  // Ratchet throughput, measured at both ends of the range the KEM-step rule
  // creates. First end: alternating direction, so every message begins a new
  // turn and therefore carries a fresh KEM offer and accepts the peer's - a
  // step per message, the PQC-heavy worst case.
  const opened = initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE);
  const responded = respondKx(fx.bobPub, fx.lookup, opened.envelope);
  if (!responded.ok) {
    throw new Error(`protocol fixture handshake failed: ${responded.reason}`);
  }
  const aState = initRatchet(opened.session.rk, opened.session.role);
  const bState = initRatchet(responded.session.rk, responded.session.role);
  let aToB = true;
  const alternating = await timeit(
    "ratchet-msg-alternating",
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

  // Other end: one party sends without a reply, so the turn never changes. No
  // offer is ever accepted and a fresh one falls only on every
  // KEM_STEP_INTERVAL-th send, which is the amortised floor. A second session
  // keeps this run independent of the state the alternating loop left behind.
  const burst = initiateKx(fx.alicePub, fx.aliceSec, fx.bundle, MESSAGE);
  const burstPeer = respondKx(fx.bobPub, fx.lookup, burst.envelope);
  if (!burstPeer.ok) {
    throw new Error(`protocol fixture handshake failed: ${burstPeer.reason}`);
  }
  const senderState = initRatchet(burst.session.rk, burst.session.role);
  const receiverState = initRatchet(burstPeer.session.rk, burstPeer.session.role);
  const unidirectional = await timeit(
    "ratchet-msg-unidirectional",
    () => {
      // Each message is decrypted as it is sent. The sender's counter climbs
      // for the whole burst, so a receiver left behind would start caching
      // skipped keys and the row would time recovery, not steady state.
      const result = ratchetDecrypt(receiverState, ratchetEncrypt(senderState, MESSAGE));
      if (!result.ok) {
        throw new Error(`ratchet burst desync: ${result.reason}`);
      }
    },
    { warmup, iters, batch: 1, yieldEvery },
  );
  // In-order delivery cannot skip anything, so a cached key here means the loop
  // above lost sync - a bug in this benchmark rather than a ratchet property,
  // and the run would be measuring the wrong thing well before MAX_SKIP.
  if (receiverState.skipped.size !== 0) {
    throw new Error(
      `ratchet burst skipped ${receiverState.skipped.size} message(s) (bound ${MAX_SKIP})`,
    );
  }

  // Omitted rather than set to undefined: `exactOptionalPropertyTypes` treats
  // an explicit undefined as a different thing from an absent property, and
  // absent is what "B1/B2 did not run" means here.
  const breakdown =
    primitives === undefined
      ? {}
      : { breakdown: buildBreakdown(primitives, ttfm.medianMs, handshake.medianMs) };

  return {
    kind: "protocol",
    suite: "B4",
    title: "B4 - protocol level",
    samples: iters,
    warmup,
    ...breakdown,
    note:
      "Crypto only, no network RTT. The two ratchet rows bracket the real cost: alternating turns " +
      "force a KEM step on every message (worst case), a unidirectional burst amortises one over " +
      `KEM_STEP_INTERVAL=${KEM_STEP_INTERVAL} sends (floor). The gap between them is what the ` +
      "interval buys; real traffic sits somewhere inside it. That floor is compute only: an " +
      "unaccepted offer is echoed on every send, so a burst carries the KEM public key on every " +
      "message while paying its keygen once per interval - a 10x cut in keygen, none on the wire. " +
      "B3 prices both modes.",
    rows: [
      { metric: TTFM_METRIC, stats: ttfm, display: "latency", unit: "op" },
      { metric: HANDSHAKE_METRIC, stats: handshake, display: "latency", unit: "op" },
      {
        metric: "ratchet message (alternating turns)",
        stats: alternating,
        display: "throughput",
        unit: "msg",
      },
      {
        metric: "ratchet message (unidirectional burst)",
        stats: unidirectional,
        display: "throughput",
        unit: "msg",
      },
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
