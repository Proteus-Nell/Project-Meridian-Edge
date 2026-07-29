// Group conversations, built as pairwise fan-out.
//
// A group message is not a new kind of message. It is N ordinary messages, each
// encrypted to one member over the KEM double-ratchet already established with
// them, carrying a group envelope inside the encrypted payload. That choice is
// the whole design, so it is worth writing down why:
//
//   - No new cryptography. Forward secrecy and post-compromise security come
//     from the pairwise ratchets unchanged. There is no group key to leak, to
//     rotate on removal, or to get wrong.
//   - No new server surface. The server sees N opaque envelopes addressed to N
//     recipients, exactly as it would for N separate conversations. It stores
//     no group object and cannot enumerate one.
//   - Sender authentication is inherited. Each envelope is authenticated by its
//     own pairwise ratchet, so no member can forge a message as another member.
//
// The cost is O(n) bandwidth per message, which is the right trade at the scale
// a personal messenger operates at, and two limitations that cannot be waved
// away:
//
//   1. THERE IS NO CRYPTOGRAPHIC AGREEMENT ON MEMBERSHIP. A malicious member
//      can tell different people different rosters. This design does not
//      prevent that; it makes it *detectable*. Every message carries the
//      sender's full roster, and a recipient whose own roster disagrees raises
//      a [SECURITY] divergence warning naming exactly who was added or dropped.
//      Detection, not prevention, and it is labelled as such wherever it is
//      surfaced.
//   2. THERE IS NO TRANSCRIPT CONSISTENCY. A member can send different text to
//      different members. Fan-out cannot fix this, and neither can sender keys;
//      only a protocol with a shared, ordered transcript can. MLS is the
//      upgrade path if that guarantee is ever needed.
//
// Removal is likewise local: a removed member keeps every message they already
// received, and there is no group key whose rotation would change that.

import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { formatUid } from "../parser";
import type { ExecutorInternals } from "./context";
import { MAX_GROUP_MEMBERS, isGroupId, isGroupName } from "./payload";
import type { GroupEnvelope } from "./payload";

/** A group as this device knows it. Stored encrypted under `group/<gid>`, so
 * the roster and the name are as protected as the contact list is. */
export interface Group {
  readonly gid: string;
  readonly name: string;
  /** Canonical UIDs, sorted, including this device's own UID. */
  readonly members: readonly string[];
  readonly createdAt: number;
  /** False once this device has left, so history stays readable without the
   * group accepting new traffic. */
  readonly active: boolean;
}

export const GROUP_KEY_PREFIX = "group/";
export const GROUP_MSG_PREFIX = "gmsg/";

export function groupKey(gid: string): string {
  return `${GROUP_KEY_PREFIX}${gid}`;
}

/** A fresh group id: 128 random bits, hex. Deliberately not derived from the
 * roster, so the identifier alone discloses nothing about who is in it. */
export function newGroupId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

/** A short fingerprint of a roster, for out-of-band comparison.
 *
 * This is a convenience for humans, NOT a security control: it is a hash of a
 * list the sender chose, so it proves only that two people are looking at the
 * same list, not that the list is right. Two members reading the same digest
 * aloud is what turns a split-roster attack from invisible into obvious. */
export function rosterDigest(members: readonly string[]): string {
  const canonical = [...members].sort().join(",");
  return bytesToHex(sha512(new TextEncoder().encode(canonical)).slice(0, 4)).toUpperCase();
}

export function isValidGroup(group: Group): boolean {
  return (
    isGroupId(group.gid) &&
    isGroupName(group.name) &&
    group.members.length > 0 &&
    group.members.length <= MAX_GROUP_MEMBERS
  );
}

/** Read one group, or null when it is absent or fails validation. Groups are
 * re-validated on read for the same reason the display prefs are: the record
 * could have been written by an older build or tampered with at rest. */
export async function loadGroup(x: ExecutorInternals, gid: string): Promise<Group | null> {
  if (!isGroupId(gid)) {
    return null;
  }
  const stored = await x.store.getJson<Group>(groupKey(gid));
  if (stored === null) {
    return null;
  }
  const members = [...new Set(stored.members ?? [])].sort();
  const group: Group = {
    gid: stored.gid,
    name: stored.name,
    members,
    createdAt: typeof stored.createdAt === "number" ? stored.createdAt : 0,
    active: stored.active !== false,
  };
  return isValidGroup(group) ? group : null;
}

export async function saveGroup(x: ExecutorInternals, group: Group): Promise<void> {
  await x.store.putJson(groupKey(group.gid), group);
}

/** Every group this device knows, newest first. */
export async function loadGroups(x: ExecutorInternals): Promise<Group[]> {
  const out: Group[] = [];
  for (const key of await x.store.listKeys(GROUP_KEY_PREFIX)) {
    const group = await loadGroup(x, key.slice(GROUP_KEY_PREFIX.length));
    if (group !== null) {
      out.push(group);
    }
  }
  return out.sort((a, b) => b.createdAt - a.createdAt);
}

/** Find a group by its name, case-insensitively. Names are local labels and
 * are not required to be unique across groups, so this returns the first
 * match by recency and the caller reports ambiguity. */
export async function findGroupByName(
  x: ExecutorInternals,
  name: string,
): Promise<Group | null> {
  const wanted = name.toLowerCase();
  const matches = (await loadGroups(x)).filter((g) => g.name.toLowerCase() === wanted);
  return matches[0] ?? null;
}

/** The difference between two rosters, as the two directions a human cares
 * about. Used to describe a divergence rather than just flag one. */
export function rosterDelta(
  mine: readonly string[],
  theirs: readonly string[],
): { readonly onlyTheirs: string[]; readonly onlyMine: string[] } {
  const a = new Set(mine);
  const b = new Set(theirs);
  return {
    onlyTheirs: theirs.filter((uid) => !a.has(uid)).sort(),
    onlyMine: mine.filter((uid) => !b.has(uid)).sort(),
  };
}

/** Compare an incoming envelope's roster against the local one and, when they
 * disagree, say so loudly and specifically.
 *
 * This is the visible half of limitation (1) at the top of this file. It does
 * not block the message: the sender may simply be ahead of us, and refusing
 * traffic on a roster mismatch would make an ordinary add look like an attack.
 * What it does is refuse to let the divergence pass unseen. */
export function warnOnRosterDivergence(
  x: ExecutorInternals,
  group: Group,
  envelope: GroupEnvelope,
  senderLabel: string,
): void {
  const { onlyTheirs, onlyMine } = rosterDelta(group.members, envelope.members);
  if (onlyTheirs.length === 0 && onlyMine.length === 0) {
    return;
  }
  const parts: string[] = [];
  if (onlyTheirs.length > 0) {
    parts.push(`they also list ${onlyTheirs.map(formatUid).join(", ")}`);
  }
  if (onlyMine.length > 0) {
    parts.push(`they are missing ${onlyMine.map(formatUid).join(", ")}`);
  }
  x.renderer.event(
    "security",
    `${senderLabel} has a different member list for '${group.name}': ${parts.join(", ")}. Group membership is not cryptographically agreed, so this is a difference to check with them out-of-band rather than proof of anything. /group info ${group.name} shows your list and its fingerprint.`,
  );
}
