// Login challenge message (CLAUDE.md §2.3): the client signs
// nonce ‖ origin ‖ timestamp, where origin and timestamp are the values the
// server bound to the nonce (echoed in the challenge response) and the
// timestamp is encoded as 8 bytes big-endian unix seconds. Must match
// server/app/routes/login.py::login_message byte for byte.

export function buildLoginMessage(
  nonce: Uint8Array,
  origin: string,
  timestamp: number,
): Uint8Array {
  const originBytes = new TextEncoder().encode(origin);
  const out = new Uint8Array(nonce.length + originBytes.length + 8);
  out.set(nonce, 0);
  out.set(originBytes, nonce.length);
  new DataView(out.buffer).setBigUint64(nonce.length + originBytes.length, BigInt(timestamp), false);
  return out;
}
