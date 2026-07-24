// Safety numbers: a human-comparable
// fingerprint of both parties' identity keys, used for out-of-band
// verification. This is the sole mechanism that defeats an actively
// malicious server at handshake time (A2 in the threat model) - the UI
// must make it prominent, not buried.
//
// SN = SHA-512(min(IK_A,IK_B) ‖ max(IK_A,IK_B) ‖ UID_min ‖ UID_max)
// rendered as 60 decimal digits in 12 groups of 5.
//
// The spec's formula names a fixed "A"/"B" but for Alice and Bob to derive
// the IDENTICAL number regardless of whose terminal computes it, both the
// key pair and its corresponding UID must be ordered by the same criterion.
// We sort by identity-key bytes (lexicographic) and carry each UID along
// with its own key, rather than sorting keys and UIDs independently.

import { sha512 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";

const GROUP_COUNT = 12;
const GROUP_BYTES = 5; // 40 bits -> mod 100000 gives a 5-digit group
const GROUP_DIGITS = 5;

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) {
      return av - bv;
    }
  }
  return a.length - b.length;
}

function digitGroup(bytes: Uint8Array): string {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  return (value % 100_000n).toString().padStart(GROUP_DIGITS, "0");
}

export interface SafetyNumber {
  /** 12 groups of 5 digits each, 60 digits total. */
  readonly groups: readonly string[];
}

export function computeSafetyNumber(
  myIk: Uint8Array,
  myUid: string,
  peerIk: Uint8Array,
  peerUid: string,
): SafetyNumber {
  const mineFirst = compareBytes(myIk, peerIk) <= 0;
  const ikMin = mineFirst ? myIk : peerIk;
  const ikMax = mineFirst ? peerIk : myIk;
  const uidMin = mineFirst ? myUid : peerUid;
  const uidMax = mineFirst ? peerUid : myUid;

  const hash = sha512(
    concatBytes(ikMin, ikMax, new TextEncoder().encode(uidMin), new TextEncoder().encode(uidMax)),
  );
  const groups: string[] = [];
  for (let i = 0; i < GROUP_COUNT; i += 1) {
    groups.push(digitGroup(hash.slice(i * GROUP_BYTES, (i + 1) * GROUP_BYTES)));
  }
  return { groups };
}

/** 3 rows of 4 groups, Signal-style, for terminal display. */
export function formatSafetyNumber(sn: SafetyNumber): string[] {
  const rows: string[] = [];
  for (let i = 0; i < sn.groups.length; i += 4) {
    rows.push(sn.groups.slice(i, i + 4).join(" "));
  }
  return rows;
}
