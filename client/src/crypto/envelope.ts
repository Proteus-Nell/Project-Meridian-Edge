// KX envelope v1: versioned fixed binary layout, no JSON
// for crypto payloads. The spk/opk hashes are routing hints so the responder
// finds the right retained secrets in O(1); they are not covered by the
// transcript - tampering them only makes decryption fail.
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
  ML_KEM_768_PUBKEY_BYTES,
  PROTOCOL_VERSION,
} from "./constants";

export const ENVELOPE_TYPE_KX = 1;
export const ENVELOPE_TYPE_MSG = 2;

/** Peek the envelope type of a framed payload without decoding it, so the
 * receiver can route a KX handshake vs. a ratchet MSG. Returns null if the
 * version byte is wrong or the buffer is too short. */
export function envelopeType(bytes: Uint8Array): number | null {
  if (bytes.length < 2 || bytes[0] !== PROTOCOL_VERSION) {
    return null;
  }
  return bytes[1] ?? null;
}

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
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
    offset,
    envelope.ciphertext.length,
    false,
  );
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

// ----- MSG envelope v1 (ratchet) -----------------------------
//
// The ratchet frames a message body itself (encrypted header + encrypted
// payload); this layer only prepends version+type so the server still routes an
// opaque blob and the receiver can tell KX from MSG.
//
//   u8 version | u8 type=MSG | body(...)
//
// The plaintext ratchet header (encrypted before it ever hits the wire) is:
//
//   u32be n | u32be pn | u8 flags(bit0=kemPk, bit1=kemCt)
//     | [kemPk(1184)] | [kemCt(1088)]

const MSG_HEADER_FIXED = 4 + 4 + 1;
const KEM_PK_FLAG = 1;
const KEM_CT_FLAG = 2;

export interface MsgHeader {
  readonly n: number; // message number within the sending chain
  readonly pn: number; // length of the sender's previous sending chain
  readonly kemPk: Uint8Array | null; // fresh KEM offer, if any
  readonly kemCt: Uint8Array | null; // KEM accept ciphertext, if any
}

export function encodeMsgHeader(header: MsgHeader): Uint8Array {
  const hasPk = header.kemPk !== null;
  const hasCt = header.kemCt !== null;
  const out = new Uint8Array(
    MSG_HEADER_FIXED +
      (hasPk ? ML_KEM_768_PUBKEY_BYTES : 0) +
      (hasCt ? ML_KEM_768_CT_BYTES : 0),
  );
  const view = new DataView(out.buffer);
  view.setUint32(0, header.n, false);
  view.setUint32(4, header.pn, false);
  out[8] = (hasPk ? KEM_PK_FLAG : 0) | (hasCt ? KEM_CT_FLAG : 0);
  let offset = MSG_HEADER_FIXED;
  if (header.kemPk !== null) {
    out.set(header.kemPk, offset);
    offset += ML_KEM_768_PUBKEY_BYTES;
  }
  if (header.kemCt !== null) {
    out.set(header.kemCt, offset);
  }
  return out;
}

export function decodeMsgHeader(bytes: Uint8Array): MsgHeader | null {
  if (bytes.length < MSG_HEADER_FIXED) {
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const n = view.getUint32(0, false);
  const pn = view.getUint32(4, false);
  const flags = bytes[8] ?? 0;
  if ((flags & ~(KEM_PK_FLAG | KEM_CT_FLAG)) !== 0) {
    return null;
  }
  const hasPk = (flags & KEM_PK_FLAG) !== 0;
  const hasCt = (flags & KEM_CT_FLAG) !== 0;
  let offset = MSG_HEADER_FIXED;
  const expected =
    MSG_HEADER_FIXED + (hasPk ? ML_KEM_768_PUBKEY_BYTES : 0) + (hasCt ? ML_KEM_768_CT_BYTES : 0);
  if (bytes.length !== expected) {
    return null;
  }
  let kemPk: Uint8Array | null = null;
  if (hasPk) {
    kemPk = bytes.slice(offset, offset + ML_KEM_768_PUBKEY_BYTES);
    offset += ML_KEM_768_PUBKEY_BYTES;
  }
  let kemCt: Uint8Array | null = null;
  if (hasCt) {
    kemCt = bytes.slice(offset, offset + ML_KEM_768_CT_BYTES);
  }
  return { n, pn, kemPk, kemCt };
}

/** Frame a ratchet body as a MSG envelope (version+type prefix). */
export function encodeMsgEnvelope(body: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + body.length);
  out[0] = PROTOCOL_VERSION;
  out[1] = ENVELOPE_TYPE_MSG;
  out.set(body, 2);
  return out;
}

/** Strip the MSG envelope prefix, returning the ratchet body. Total: returns
 * null on a wrong version/type or an over-cap payload. */
export function decodeMsgEnvelope(bytes: Uint8Array): Uint8Array | null {
  if (bytes.length < 2 || bytes.length > MAX_PAYLOAD_BYTES) {
    return null;
  }
  if (bytes[0] !== PROTOCOL_VERSION || bytes[1] !== ENVELOPE_TYPE_MSG) {
    return null;
  }
  return bytes.slice(2);
}
