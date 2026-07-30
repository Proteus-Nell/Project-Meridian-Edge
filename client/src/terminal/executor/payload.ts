import { normalizeUid } from "../parser";

// The encrypted ratchet payload (body). Carries the message text and
// the sender's current mutual-timer view so a /timer change propagates and
// both sides converge last-writer-wins; a pure timer-control message has no
// text. It can also carry `mid` (this message's shared id) and a cooperative
// deletion directive: `deletes` names peer-side message ids to remove and
// `deleteSilent` suppresses the peer-side notice (a).

/** What a group-bearing payload is doing. `msg` is ordinary group text; the
 * rest are membership events, announced in-band so every member sees who did
 * what rather than discovering a roster change by accident. */
export type GroupAction = "msg" | "invite" | "add" | "remove" | "leave";

export const GROUP_ACTIONS: readonly GroupAction[] = ["msg", "invite", "add", "remove", "leave"];

/** The group envelope, carried INSIDE the encrypted ratchet payload.
 *
 * Groups add nothing to the wire format and nothing to the server: a group
 * message is N ordinary pairwise messages, each encrypted to one member over
 * the ratchet already established with them. The server still sees N opaque
 * envelopes addressed to N recipients and learns no group structure from the
 * protocol (it can still infer one from the timing of a fan-out, which is
 * stated plainly in the README rather than papered over).
 *
 * `members` is the SENDER'S view of the roster. There is no cryptographic
 * agreement on membership here, which is the honest limitation of this design:
 * a malicious member can tell different people different things. Carrying the
 * full roster on every message is what makes that detectable, since a recipient
 * whose own roster disagrees can say so loudly. */
export interface GroupEnvelope {
  /** 128-bit hex, minted by the creator. Opaque; never derived from members. */
  readonly gid: string;
  readonly name: string;
  /** The sender's roster as canonical UIDs, including the sender. */
  readonly members: readonly string[];
  readonly action: GroupAction;
  /** UID the action refers to, for add/remove. Null otherwise. */
  readonly subject: string | null;
}

export interface AppPayload {
  readonly text: string | null;
  readonly timerSeconds: number | null;
  readonly mid: string | null;
  readonly deletes: readonly string[] | null;
  readonly deleteSilent: boolean;
  /** Present when this message belongs to a group. */
  readonly group: GroupEnvelope | null;
}

export function encodeAppPayload(payload: AppPayload): Uint8Array {
  const record: {
    m?: string;
    tmr: number;
    id?: string;
    del?: readonly string[];
    ds?: boolean;
    g?: string;
    gn?: string;
    gm?: readonly string[];
    ga?: GroupAction;
    gs?: string;
  } = {
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
  if (payload.group !== null) {
    record.g = payload.group.gid;
    record.gn = payload.group.name;
    record.gm = payload.group.members;
    record.ga = payload.group.action;
    if (payload.group.subject !== null) {
      record.gs = payload.group.subject;
    }
  }
  return new TextEncoder().encode(JSON.stringify(record));
}

/** A group id: 128 random bits, hex. Opaque and never derived from the member
 * list, so it does not leak the roster to anyone who sees one. */
const GID_RE = /^[0-9a-f]{32}$/;

/** Group names are shown in aligned listings and in the prompt, and they arrive
 * from a peer, so they get the same treatment as an alias: a tight character
 * class and a hard length cap. The renderer strips control characters on top of
 * this; both are wanted, since this is the layer that decides whether a name is
 * storable at all. */
const GROUP_NAME_RE = /^[A-Za-z0-9 _-]{1,32}$/;

/** Ceiling on a roster arriving from a peer. Fan-out costs one send per member
 * against a per-UID rate limit, so an unbounded roster is a way to make someone
 * else's client hammer the server. */
export const MAX_GROUP_MEMBERS = 32;

export function isGroupId(value: string): boolean {
  return GID_RE.test(value);
}

export function isGroupName(value: string): boolean {
  return GROUP_NAME_RE.test(value);
}

/** Validate a roster off the wire: every entry a canonical UID, deduplicated,
 * capped, and sorted so two members who agree produce identical bytes (which is
 * what makes the digest comparable). Returns null if anything is off, because a
 * roster that is partly wrong is not one worth guessing at. */
export function sanitizeRoster(raw: unknown): string[] | null {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_GROUP_MEMBERS) {
    return null;
  }
  const seen = new Set<string>();
  for (const entry of raw as readonly unknown[]) {
    if (typeof entry !== "string") {
      return null;
    }
    const uid = normalizeUid(entry);
    if (uid === null) {
      return null;
    }
    seen.add(uid);
  }
  return [...seen].sort();
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
  const record = parsed as {
    m?: unknown;
    tmr?: unknown;
    id?: unknown;
    del?: unknown;
    ds?: unknown;
    g?: unknown;
    gn?: unknown;
    gm?: unknown;
    ga?: unknown;
    gs?: unknown;
  };
  const text = typeof record.m === "string" ? record.m : null;
  const tmr = typeof record.tmr === "number" && record.tmr > 0 ? record.tmr : null;
  const mid = typeof record.id === "string" ? record.id : null;
  const deletes =
    Array.isArray(record.del) && record.del.every((x) => typeof x === "string")
      ? record.del
      : null;
  return {
    text,
    timerSeconds: tmr,
    mid,
    deletes,
    deleteSilent: record.ds === true,
    group: decodeGroupEnvelope(record),
  };
}

/** Pull the group envelope out of a decoded record, or null when this is an
 * ordinary one-to-one message. Shared by the ratchet payload decoder above and
 * by the KX branch of processEnvelope in messaging.ts, so peer-supplied group
 * fields meet exactly one validator whichever path they arrive on.
 *
 * Everything here is peer-supplied and gets validated rather than trusted: a
 * malformed group envelope yields null and the message is handled as an
 * ordinary message, which is the safe direction to fail. In particular a bad
 * roster does NOT fall back to "no members" or "the members I already had",
 * since either would silently rewrite the recipient's view of who is in the
 * group, and that view is the only thing making a split-roster attack
 * detectable. */
export function decodeGroupEnvelope(record: {
  g?: unknown;
  gn?: unknown;
  gm?: unknown;
  ga?: unknown;
  gs?: unknown;
}): GroupEnvelope | null {
  if (typeof record.g !== "string" || !isGroupId(record.g)) {
    return null;
  }
  if (typeof record.gn !== "string" || !isGroupName(record.gn)) {
    return null;
  }
  const members = sanitizeRoster(record.gm);
  if (members === null) {
    return null;
  }
  if (typeof record.ga !== "string" || !GROUP_ACTIONS.includes(record.ga as GroupAction)) {
    return null;
  }
  const action = record.ga as GroupAction;
  let subject: string | null = null;
  if (record.gs !== undefined) {
    subject = typeof record.gs === "string" ? normalizeUid(record.gs) : null;
    if (subject === null) {
      return null; // a named action whose subject does not parse is not actionable
    }
  }
  // add/remove are only meaningful with a subject; msg/invite/leave only
  // without one. Rejecting the mismatch keeps every downstream handler from
  // having to re-check.
  const needsSubject = action === "add" || action === "remove";
  if (needsSubject !== (subject !== null)) {
    return null;
  }
  return { gid: record.g, name: record.gn, members, action, subject };
}
