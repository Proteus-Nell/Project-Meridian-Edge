// Stored record shapes and their (de)serialization: everything the executor
// persists in the encrypted store, plus the wire-to-crypto bundle adapter.
// Key material is base64 in these records; the store encrypts the whole
// serialized value at rest.

import { initRatchet } from "../../crypto/ratchet";
import type { RatchetState } from "../../crypto/ratchet";
import type { Bundle, KxSession } from "../../crypto/kx";
import type * as api from "../../net/api";
import { fromBase64, toBase64 } from "../../util/base64";
import type { Weekday } from "../parser";

export interface StoredIdentity {
  readonly uid: string; // canonical 26-char form
  readonly pub: string; // base64
  readonly sec: string; // base64
}

export interface Identity {
  readonly uid: string;
  readonly pub: Uint8Array;
  sec: Uint8Array;
}

export interface StoredSpk {
  readonly pub: string;
  readonly sec: string;
  readonly sig: string;
  readonly createdAt: number;
}

export interface StoredOpk {
  readonly pub: string;
  readonly sec: string;
}

export interface RotationSettings {
  readonly enabled: boolean;
  readonly day: Weekday;
  readonly lastPrompt: number;
}

export const DEFAULT_ROTATION: RotationSettings = {
  enabled: true,
  day: "friday",
  lastPrompt: 0,
};

export const WEEKDAY_INDEX: Record<Weekday, number> = {
  sunday: 0,
  monday: 1,
  tuesday: 2,
  wednesday: 3,
  thursday: 4,
  friday: 5,
  saturday: 6,
};

export interface Contact {
  readonly uid: string;
  readonly alias: string;
  readonly ik: string | null; // base64, pinned TOFU-style on first contact
  /** Set by /verified after out-of-band safety-number comparison. Reset to
   * false whenever a key change is detected. */
  readonly verified: boolean;
  /** True from the moment a key change is detected until /ack. Sending is
   * refused while this is set. */
  readonly keyChangeBlocked: boolean;
  /** Mutual disappearing-message timer in seconds; null = off.
   * Shared with the peer over the encrypted ratchet payload, last-writer-wins. */
  readonly timerSeconds: number | null;
  /** Pinned to the top of the contact list (/favourite). Local and cosmetic:
   * like the alias, it never leaves the device and the peer is never told. */
  readonly favourite: boolean;
}

export interface PartialContact {
  uid: string;
  alias: string;
  ik?: string | null | undefined;
  verified?: boolean | undefined;
  keyChangeBlocked?: boolean | undefined;
  timerSeconds?: number | null | undefined;
  favourite?: boolean | undefined;
}

export function normalizeContact(c: PartialContact): Contact {
  return {
    uid: c.uid,
    alias: c.alias,
    ik: c.ik ?? null,
    verified: c.verified ?? false,
    keyChangeBlocked: c.keyChangeBlocked ?? false,
    timerSeconds: c.timerSeconds ?? null,
    favourite: c.favourite ?? false,
  };
}

/** Display order for every contact listing: favourites first, then alphabetical
 * within each group. Shared by /home and /contacts so the two never disagree
 * about where a contact sits. */
export function sortContacts(contacts: readonly Contact[]): Contact[] {
  return [...contacts].sort((a, b) => {
    if (a.favourite !== b.favourite) {
      return a.favourite ? -1 : 1;
    }
    return a.alias.localeCompare(b.alias);
  });
}

/** The two-column gutter every contact line starts with, marking favourites. */
export function favouriteMark(contact: Contact): string {
  return contact.favourite ? "*" : " ";
}

/** When a message happened, as the two instants a receiver has to keep apart.
 *
 * `ts` is what the transcript shows and sorts by: the sender's own clock, so a
 * message written on Thursday still reads as Thursday when it is finally
 * collected on Saturday. `receivedAt` is when this device actually got it, and
 * it is what every deadline counts from - a disappearing timer must not have
 * been running while the envelope sat in the server's queue, or a message with
 * an hour on it would arrive already expired and be purged before it is read.
 *
 * The two are equal for anything this device sent, and for anything received
 * from a peer old enough not to send a time at all. */
export interface MessageInstant {
  readonly ts: number;
  readonly receivedAt: number;
}

/** The queue TTL, past which an envelope cannot legitimately still have been
 * undelivered. Mirrors MESSAGE_TTL_SECONDS in server/app/constants.py. */
const MAX_QUEUE_AGE_MS = 14 * 86_400_000;

/** Allowance for an honestly-fast peer clock, so someone a minute ahead is not
 * dragged backwards on every message they send. */
const MAX_CLOCK_SKEW_MS = 5 * 60_000;

/** Decide what instant a received message is shown and sorted under.
 *
 * `sentAt` travels inside the ratchet AEAD, so it is authenticated as the
 * peer's - but authenticated is not honest, and it is still THEIR clock. Left
 * unclamped, a skewed or malicious sender can park a message at the top of the
 * transcript indefinitely, or backdate one far enough to slip past the local
 * retention cap. Clamping to the window the envelope could actually have
 * travelled in bounds the damage at "somewhat wrong" instead of "rewrites the
 * order of your history".
 *
 * `notBefore` is the per-session monotonicity floor: the time already accepted
 * for the newest message on this ratchet, passed only when THIS message extends
 * the receive frontier (see processRatchetMessage). It is what stops a peer
 * shuffling their own messages inside the window above - the global clamp bounds
 * how wrong one message can be, this bounds how wrong it can be *relative to the
 * ones before it*. The ratchet's own counters decide what "before" means, so a
 * legitimately late message is never dragged forward to sit after messages it
 * really did precede; it simply arrives with no floor.
 *
 * A null `sentAt` - a peer on a build from before the field existed - falls
 * back to arrival, which is exactly what every message did before it. */
export function stampIncoming(
  sentAt: number | null,
  receivedAt: number,
  notBefore: number | null = null,
): MessageInstant {
  if (sentAt === null || !Number.isFinite(sentAt)) {
    return { ts: receivedAt, receivedAt };
  }
  const ceiling = receivedAt + MAX_CLOCK_SKEW_MS;
  const floor = Math.max(receivedAt - MAX_QUEUE_AGE_MS, notBefore ?? -Infinity);
  // The ceiling is applied last and so wins outright. That only bites when the
  // floor has somehow overtaken it - a local clock that jumped backwards since
  // the previous message - and pinning to "about now" is the least surprising
  // answer there; it is the one case where the floor does not hold.
  return { ts: Math.min(Math.max(sentAt, floor), ceiling), receivedAt };
}

/** A locally stored message record. Written on send and on receive; the live
 * transcript renders as messages arrive, so this is at-rest history for view
 * rebuilds, subject to the disappearing timer and local purge (-5.3). */
export interface StoredMessage {
  readonly dir: "in" | "out";
  readonly text: string;
  readonly ts: number;
  /** When this device received the message, when that differs from `ts` - i.e.
   * an incoming message that spent time queued. Absent means "same as `ts`",
   * which covers everything sent from here and every record written before the
   * sender's clock was carried. Deadlines count from this, never from `ts`
   * (see MessageInstant). */
  readonly receivedAt?: number;
  /** Absolute epoch-ms deletion deadline from the mutual timer, if any. */
  readonly tmrExpiresAt?: number;
  /** Shared per-message id (random 128-bit hex), carried in the encrypted
   * payload so a cooperative /delete can name it on both sides (a).
   * Absent on records that predate /delete: those still delete locally but
   * cannot be signalled to the peer. */
  readonly mid?: string;
}

/** A stored group message, under `gmsg/<gid>/<ts>`. Unlike a one-to-one record
 * it keeps the sender's label, because a group transcript has to say who is
 * speaking. There is no `mid`: cooperative /delete is a pairwise directive and
 * a group has no shared transcript to reconcile, which is one of the honest
 * limitations of fan-out groups (see executor/groups.ts).
 *
 * There is also no `tmrExpiresAt`. Group history is still covered by the
 * local retention cap (`ts` + the cap, same as a one-to-one message) and by
 * /group purge, but NOT by a mutual disappearing timer: a mutual timer needs
 * every member to agree on one deadline, and fan-out gives them no shared
 * transcript to carry that agreement through, the same gap that rules out a
 * shared `mid` above. */
export interface StoredGroupMessage {
  readonly dir: "in" | "out";
  readonly sender: string;
  readonly text: string;
  readonly ts: number;
  /** As StoredMessage.receivedAt: present only when arrival differs from `ts`.
   * Group history has no mutual timer, but the retention cap counts from here
   * so a backdated fan-out leg cannot be swept the moment it lands. */
  readonly receivedAt?: number;
}

/** Local retention cap: personal, never transmitted, may be
 * stricter than the mutual timer. null = off. */
export interface PurgeSettings {
  readonly seconds: number | null;
}

/** Serialized KEM double-ratchet state. All key material base64;
 * the skipped-key cache is a list of [chainId:n, base64 mk] pairs. */
export interface StoredRatchet {
  readonly role: "initiator" | "responder";
  readonly rk: string;
  readonly cks: string;
  readonly ckr: string | null;
  readonly ns: number;
  readonly nr: number;
  readonly pn: number;
  readonly lastAction: "send" | "recv";
  readonly hks: string;
  readonly hkr: string;
  readonly nhkr: string | null;
  readonly sendKemSk: string | null;
  readonly sendKemPk: string | null;
  readonly peerKemPk: string | null;
  readonly sinceOffer: number;
  readonly recvChainId: number;
  readonly skipped: readonly (readonly [string, string])[];
}

export interface StoredSession {
  readonly ratchet: StoredRatchet;
  readonly peerIk: string;
  readonly reducedFs: boolean;
  readonly establishedAt: number;
  /** Display time accepted for the newest message received on this ratchet -
   * newest by the ratchet's own counters, not by arrival. The floor the next
   * frontier-extending message is clamped against (stampIncoming). Absent
   * until the first ratchet message lands, and on sessions stored before this
   * existed, where it simply means "no floor yet". */
  readonly lastTs?: number;
}

export interface PendingRequest {
  readonly text: string;
  readonly session: StoredSession;
  readonly senderIk: string;
  readonly receivedAt: number;
  /** The already-clamped display instant (stampIncoming) for the held message,
   * when the sender carried a clock. Absent on a held request from a peer that
   * did not, and on ones stored before the field existed: both fall back to
   * `receivedAt`, which is what they were shown under. */
  readonly sentAt?: number;
  /** Shared id of the held first message, if it carried one (a). */
  readonly mid?: string | null;
}

export function serializeRatchet(state: RatchetState): StoredRatchet {
  return {
    role: state.role,
    rk: toBase64(state.rk),
    cks: toBase64(state.cks),
    ckr: state.ckr === null ? null : toBase64(state.ckr),
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    lastAction: state.lastAction,
    hks: toBase64(state.hks),
    hkr: toBase64(state.hkr),
    nhkr: state.nhkr === null ? null : toBase64(state.nhkr),
    sendKemSk: state.sendKemSk === null ? null : toBase64(state.sendKemSk),
    sendKemPk: state.sendKemPk === null ? null : toBase64(state.sendKemPk),
    peerKemPk: state.peerKemPk === null ? null : toBase64(state.peerKemPk),
    sinceOffer: state.sinceOffer,
    recvChainId: state.recvChainId,
    skipped: [...state.skipped].map(([k, v]) => [k, toBase64(v)] as const),
  };
}

export function deserializeRatchet(stored: StoredRatchet): RatchetState {
  return {
    role: stored.role,
    rk: fromBase64(stored.rk),
    cks: fromBase64(stored.cks),
    ckr: stored.ckr === null ? null : fromBase64(stored.ckr),
    ns: stored.ns,
    nr: stored.nr,
    pn: stored.pn,
    lastAction: stored.lastAction,
    hks: fromBase64(stored.hks),
    hkr: fromBase64(stored.hkr),
    nhkr: stored.nhkr === null ? null : fromBase64(stored.nhkr),
    sendKemSk: stored.sendKemSk === null ? null : fromBase64(stored.sendKemSk),
    sendKemPk: stored.sendKemPk === null ? null : fromBase64(stored.sendKemPk),
    peerKemPk: stored.peerKemPk === null ? null : fromBase64(stored.peerKemPk),
    sinceOffer: stored.sinceOffer,
    recvChainId: stored.recvChainId,
    skipped: new Map(stored.skipped.map(([k, v]) => [k, fromBase64(v)])),
  };
}

/** Establish a stored session from a completed handshake: initialise the
 * ratchet from RK0 and wipe the handshake's transient root/transcript copy
 *. */
export function serializeSession(session: KxSession, establishedAt: number): StoredSession {
  const ratchet = serializeRatchet(initRatchet(session.rk, session.role));
  session.rk.fill(0);
  session.transcript.fill(0);
  return {
    ratchet,
    peerIk: toBase64(session.peerIk),
    reducedFs: session.reducedFs,
    establishedAt,
  };
}

export function wireToBundle(wire: api.WireBundle): Bundle {
  return {
    ikPub: fromBase64(wire.ik_pub),
    spkPub: fromBase64(wire.spk_pub),
    spkSig: fromBase64(wire.spk_sig),
    opk:
      wire.opk === null
        ? null
        : {
            pub: fromBase64(wire.opk.pub),
            index: wire.opk.index,
            leaves: wire.opk.leaf_hashes.map(fromBase64),
            rootSig: fromBase64(wire.opk.root_sig),
          },
  };
}
