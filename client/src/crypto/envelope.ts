// KX envelope v1 (CLAUDE.md §3.6): versioned fixed binary layout, no JSON
// for crypto payloads. The spk/opk hashes are routing hints so the responder
// finds the right retained secrets in O(1); they are not covered by the
// transcript — tampering them only makes decryption fail (ADR 0002).
//
//   u8 version | u8 type | u8 flags(bit0=hasOpk)
//   spkHash(64) | [opkHash(64)]
//   IK_A(1952) | ct1(1088) | [ct2(1088)]
//   sig(3309) | nonce(24) | u32be ctLen | ciphertext(ctLen)
//
// decode() is total: malformed input returns null, never throws.

import {
  MAX_PAYLOAD_BYTES,
  ML_DSA_65_PUBKEY_BYTES,
  ML_DSA_65_SIG_BYTES,
  ML_KEM_768_CT_BYTES,
  PROTOCOL_VERSION,
} from "./constants";

export const ENVELOPE_TYPE_KX = 1;

const HASH_BYTES = 64;
const AEAD_NONCE_BYTES = 24;
const AEAD_TAG_BYTES = 16;
const HEADER_BYTES = 3;

export interface KxEnvelope {
  readonly spkHash: Uint8Array;
  readonly opkHash: Uint8Array | null;
  readonly ikA: Uint8Array;
  readonly ct1: Uint8Array;
  readonly ct2: Uint8Array | null;
  readonly sig: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

function fixedLength(hasOpk: boolean, ciphertextLength: number): number {
  return (
    HEADER_BYTES +
    HASH_BYTES +
    (hasOpk ? HASH_BYTES : 0) +
    ML_DSA_65_PUBKEY_BYTES +
    ML_KEM_768_CT_BYTES +
    (hasOpk ? ML_KEM_768_CT_BYTES : 0) +
    ML_DSA_65_SIG_BYTES +
    AEAD_NONCE_BYTES +
    4 +
    ciphertextLength
  );
}

export function encodeKxEnvelope(envelope: KxEnvelope): Uint8Array {
  const hasOpk = envelope.opkHash !== null;
  if (hasOpk !== (envelope.ct2 !== null)) {
    throw new Error("opkHash and ct2 must be present together");
  }
  const out = new Uint8Array(fixedLength(hasOpk, envelope.ciphertext.length));
  let offset = 0;
  const put = (bytes: Uint8Array): void => {
    out.set(bytes, offset);
    offset += bytes.length;
  };
  out[offset] = PROTOCOL_VERSION;
  out[offset + 1] = ENVELOPE_TYPE_KX;
  out[offset + 2] = hasOpk ? 1 : 0;
  offset += HEADER_BYTES;
  put(envelope.spkHash);
  if (envelope.opkHash !== null) {
    put(envelope.opkHash);
  }
  put(envelope.ikA);
  put(envelope.ct1);
  if (envelope.ct2 !== null) {
    put(envelope.ct2);
  }
  put(envelope.sig);
  put(envelope.nonce);
  new DataView(out.buffer).setUint32(offset, envelope.ciphertext.length, false);
  offset += 4;
  put(envelope.ciphertext);
  return out;
}

export function decodeKxEnvelope(bytes: Uint8Array): KxEnvelope | null {
  if (bytes.length < HEADER_BYTES || bytes.length > MAX_PAYLOAD_BYTES) {
    return null;
  }
  if (bytes[0] !== PROTOCOL_VERSION || bytes[1] !== ENVELOPE_TYPE_KX) {
    return null;
  }
  const flags = bytes[2] ?? 0;
  if ((flags & ~1) !== 0) {
    return null;
  }
  const hasOpk = (flags & 1) === 1;
  const minimum = fixedLength(hasOpk, AEAD_TAG_BYTES);
  if (bytes.length < minimum) {
    return null;
  }

  let offset = HEADER_BYTES;
  const take = (length: number): Uint8Array => {
    const slice = bytes.slice(offset, offset + length);
    offset += length;
    return slice;
  };
  const spkHash = take(HASH_BYTES);
  const opkHash = hasOpk ? take(HASH_BYTES) : null;
  const ikA = take(ML_DSA_65_PUBKEY_BYTES);
  const ct1 = take(ML_KEM_768_CT_BYTES);
  const ct2 = hasOpk ? take(ML_KEM_768_CT_BYTES) : null;
  const sig = take(ML_DSA_65_SIG_BYTES);
  const nonce = take(AEAD_NONCE_BYTES);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ciphertextLength = view.getUint32(offset, false);
  offset += 4;
  if (ciphertextLength < AEAD_TAG_BYTES || offset + ciphertextLength !== bytes.length) {
    return null;
  }
  const ciphertext = take(ciphertextLength);
  return { spkHash, opkHash, ikA, ct1, ct2, sig, nonce, ciphertext };
}
