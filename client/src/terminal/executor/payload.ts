// The encrypted ratchet payload (§4 body). Carries the message text and
// the sender's current mutual-timer view so a /timer change propagates and
// both sides converge last-writer-wins; a pure timer-control message has no
// text. It can also carry `mid` (this message's shared id) and a cooperative
// deletion directive: `deletes` names peer-side message ids to remove and
// `deleteSilent` suppresses the peer-side notice (§5.3a).

export interface AppPayload {
  readonly text: string | null;
  readonly timerSeconds: number | null;
  readonly mid: string | null;
  readonly deletes: readonly string[] | null;
  readonly deleteSilent: boolean;
}

export function encodeAppPayload(payload: AppPayload): Uint8Array {
  const record: { m?: string; tmr: number; id?: string; del?: readonly string[]; ds?: boolean } = {
    tmr: payload.timerSeconds ?? 0,
  };
  if (payload.text !== null) {
    record.m = payload.text;
  }
  if (payload.mid !== null) {
    record.id = payload.mid;
  }
  if (payload.deletes !== null && payload.deletes.length > 0) {
    record.del = payload.deletes;
    if (payload.deleteSilent) {
      record.ds = true;
    }
  }
  return new TextEncoder().encode(JSON.stringify(record));
}

export function decodeAppPayload(bytes: Uint8Array): AppPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const record = parsed as { m?: unknown; tmr?: unknown; id?: unknown; del?: unknown; ds?: unknown };
  const text = typeof record.m === "string" ? record.m : null;
  const tmr = typeof record.tmr === "number" && record.tmr > 0 ? record.tmr : null;
  const mid = typeof record.id === "string" ? record.id : null;
  const deletes =
    Array.isArray(record.del) && record.del.every((x) => typeof x === "string")
      ? (record.del as string[])
      : null;
  return { text, timerSeconds: tmr, mid, deletes, deleteSilent: record.ds === true };
}
