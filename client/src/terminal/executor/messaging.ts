// Messaging: the PQ-KX first message, ratchet sends, and
// the receive pipeline (KX responses, ratchet trial decryption, inbox drain,
// contact requests). The send side write-aheads ratchet state before any
// network call so a failed send can never reuse a message key.

import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import * as api from "../../net/api";
import { ApiError } from "../../net/api";
import { initiateKx, respondKx, verifyBundle } from "../../crypto/kx";
import type { Bundle, PrekeyLookup, PrekeySecret } from "../../crypto/kx";
import { ratchetDecrypt, ratchetEncrypt } from "../../crypto/ratchet";
import {
  decodeMsgEnvelope,
  encodeMsgEnvelope,
  envelopeType,
  ENVELOPE_TYPE_MSG,
} from "../../crypto/envelope";
import { MAX_PAYLOAD_BYTES } from "../../crypto/constants";
import { fromBase64, toBase64 } from "../../util/base64";
import { formatUid, normalizeUid } from "../parser";
import {
  findContactByUid,
  isActiveConversation,
  pinKey,
  refreshEmblemState,
  saveContacts,
} from "./context";
import type { ExecutorInternals } from "./context";
import { decodeAppPayload, decodeGroupEnvelope, encodeAppPayload } from "./payload";
import type { GroupAction, GroupEnvelope } from "./payload";
import {
  GROUP_MSG_PREFIX,
  applyAnnouncedChange,
  loadGroup,
  saveGroup,
  uniqueGroupName,
  warnOnRosterDivergence,
} from "./groups";
import type { Group } from "./groups";
import {
  deserializeRatchet,
  serializeRatchet,
  serializeSession,
  wireToBundle,
} from "./records";
import type {
  Contact,
  PendingRequest,
  StoredGroupMessage,
  StoredMessage,
  StoredOpk,
  StoredSession,
  StoredSpk,
} from "./records";
import { handleKeyChange } from "./trust";
import { applyIncomingDeletion, applyIncomingTimer, purgeExpired } from "./lifecycle";
import { renderHome } from "./views";

/** Send one already-echoed outgoing message to `target`, then mark that row
 * delivered or failed via the chrome tick, with a status line on success.
 * Does NOT wrap its own run()/echo, so a caller can sequence it after other
 * work inside a single task: used both by a plain typed message (echoed in
 * main.ts) and by the `/chat <target> <message>` inline form (which echoes it
 * after the view switch). */
export async function sendActiveMessage(
  x: ExecutorInternals,
  target: Contact,
  text: string,
): Promise<void> {
  // Declared without a value: the catch below always rethrows, so control only
  // reaches the read when the try assigned it.
  let sent: boolean;
  try {
    sent = await sendFirstMessage(x, target, text);
  } catch (err) {
    // A thrown send (e.g. network) still marks the echoed line failed; the
    // run() error path logs the specific reason.
    x.chrome.rejectSent();
    throw err;
  }
  if (sent) {
    x.chrome.confirmSent();
    x.renderer.status("success", `sent to ${target.alias}`);
  } else {
    // A graceful non-send already explained itself on the transcript/status.
    x.chrome.rejectSent();
  }
}

/** Fan one group message out to every other member, as N independent pairwise
 * messages over the ratchets already established with them.
 *
 * There is no group key and no broadcast: each member gets their own envelope,
 * encrypted to them alone, carrying the same group envelope in its payload. The
 * server sees N ordinary sends. See groups.ts for why this design was chosen
 * over sender keys and what it does not guarantee.
 *
 * Delivery is reported honestly. A member with no contact entry, a blocked key
 * change, or a failed send is named in `failed` rather than folded into a
 * success: a group message that reached four of six people is not a message
 * that was sent, and the sender is the only person who can act on the
 * difference. */
/** How many fan-out legs are in flight at once.
 *
 * Kept small on purpose. The legs are independent (each advances its own
 * pairwise ratchet, and the store writes never touch the same key), so this is
 * safe to raise, but the server's per-account send budget is 60 messages a
 * minute and a burst is what a rate limiter is built to notice. Four keeps a
 * large group responsive without looking like a flood. */
const FAN_OUT_CONCURRENCY = 4;

/** Fan one group message out as N independent pairwise messages.
 *
 * `recipients` and `roster` are separate parameters and that separation is
 * load-bearing. Who receives a copy is not always who the group contains: the
 * invite that goes to a newly added member has one recipient but must advertise
 * the WHOLE roster, and a removal notice goes to the person being removed but
 * must advertise the roster without them. Deriving one from the other, as an
 * earlier version of this function did, silently told a new member their group
 * had two people in it. */
export async function fanOutToGroup(
  x: ExecutorInternals,
  group: Group,
  text: string | null,
  action: GroupAction,
  subject: string | null,
  recipients?: readonly string[],
): Promise<{ delivered: number; failed: string[] }> {
  const envelope: GroupEnvelope = {
    gid: group.gid,
    name: group.name,
    members: group.members,
    action,
    subject,
  };
  const targets = (recipients ?? group.members).filter((uid) => uid !== x.identity?.uid);

  const send = async (uid: string): Promise<string | null> => {
    const contact = findContactByUid(x, uid);
    if (contact === null) {
      // A member with no contact entry has no pinned key and no session, so
      // there is nothing to encrypt to. Named rather than skipped, and
      // /group sync is what resolves it.
      return formatUid(uid);
    }
    if (contact.keyChangeBlocked) {
      return `${contact.alias} (unacknowledged key change)`;
    }
    try {
      const stored = await x.store.getJson<StoredSession>(`session/${uid}`);
      const ok =
        stored === null
          ? await sendFirstMessage(x, contact, text ?? "", envelope)
          : await sendRatchetMessage(x, contact, stored, text, { group: envelope });
      return ok ? null : contact.alias;
    } catch {
      // One member's network failure must not abandon the rest of the fan-out.
      return contact.alias;
    }
  };

  const failed: string[] = [];
  let delivered = 0;
  for (let i = 0; i < targets.length; i += FAN_OUT_CONCURRENCY) {
    const batch = targets.slice(i, i + FAN_OUT_CONCURRENCY);
    for (const result of await Promise.all(batch.map(send))) {
      if (result === null) {
        delivered += 1;
      } else {
        failed.push(result);
      }
    }
  }
  return { delivered, failed };
}

/** Send to `target`, running the PQ-KX handshake first if no session exists
 * yet; an established session rides the ratchet instead. Returns
 * true only when an envelope was accepted by the server. */
export async function sendFirstMessage(
  x: ExecutorInternals,
  target: Contact,
  text: string,
  group: GroupEnvelope | null = null,
): Promise<boolean> {
  if (x.identity === null || x.token === null) {
    x.renderer.error("E201");
    return false;
  }
  if (target.keyChangeBlocked) {
    x.renderer.event(
      "security",
      `sending to ${target.alias} is blocked: an unacknowledged identity-key change was detected. /ack ${target.alias}, then /verify + /verified to resume.`,
    );
    return false;
  }
  const existing = await x.store.getJson<StoredSession>(`session/${target.uid}`);
  if (existing !== null) {
    return sendRatchetMessage(x, target, existing, text, group === null ? undefined : { group });
  }

  let wire: api.WireBundle;
  try {
    wire = await api.fetchBundle(x.token, target.uid);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      x.renderer.error("E304");
      return false;
    }
    throw err;
  }
  const bundle = wireToBundle(wire);

  // Spec 3.1: verify both prekey signatures against IK_B; abort loudly on
  // failure, never proceed, never retry silently.
  if (!verifyBundleOrWarn(x, target, bundle)) {
    return false;
  }
  const bundleIk = toBase64(bundle.ikPub);
  if (target.ik !== null && target.ik !== bundleIk) {
    // Manual trust blocks the send; auto-trust re-pins and lets it proceed on
    // the new (freshly fetched) key after the loud warning.
    if (!(await handleKeyChange(x, target, bundleIk))) {
      return false;
    }
    target = findContactByUid(x, target.uid) ?? target;
  }

  const mid = newMessageId();
  // The KX first message predates the AppPayload format and stays its own small
  // JSON record, but it carries the same group fields under the same key names,
  // so a group's very first message to a member does not need a second round
  // trip to establish a session first.
  const payload = new TextEncoder().encode(
    JSON.stringify(
      group === null
        ? { u: x.identity.uid, m: text, id: mid }
        : {
            u: x.identity.uid,
            m: text,
            id: mid,
            g: group.gid,
            gn: group.name,
            gm: group.members,
            ga: group.action,
            ...(group.subject === null ? {} : { gs: group.subject }),
          },
    ),
  );
  const { envelope, session } = initiateKx(x.identity.pub, x.identity.sec, bundle, payload);
  await api.sendMessage(x.token, target.uid, envelope);

  const timestamp = x.now();
  await x.store.putJson(`session/${target.uid}`, serializeSession(session, timestamp));
  // A group send stores its copy once, under the group, rather than once per
  // member: the fan-out is a transport detail, not six conversations.
  if (group === null) {
    await recordMessage(x, target.uid, "out", text, timestamp, mid);
  }
  if (target.ik === null) {
    x.contacts.set(target.alias, pinKey(x, target, bundleIk));
    await saveContacts(x);
  }
  // The delivery tick and "sent to" status are raised by the caller; the
  // once-per-conversation handshake milestone still gets a transcript line
  // since it is not per-message noise.
  x.renderer.event("info", `PQ-KX handshake established with ${target.alias}`);
  if (session.reducedFs) {
    x.renderer.event(
      "warning",
      "reduced forward secrecy: recipient had no one-time prekeys left; heals once the ratchet takes its first key-encapsulation step",
    );
  }
  return true;
}

function verifyBundleOrWarn(x: ExecutorInternals, target: Contact, bundle: Bundle): boolean {
  if (verifyBundle(bundle)) {
    return true;
  }
  x.renderer.event(
    "security",
    `Prekey bundle signature verification FAILED for ${target.alias}. The server may be tampering, so the send was aborted.`,
  );
  return false;
}

/** Send a subsequent message through the KEM double-ratchet. The
 * ratchet state is advanced, persisted write-ahead (so a failed send never
 * risks key reuse), and only then transmitted. The MSG envelope is opaque: it
 * carries no sender identity, so the recipient locates the session by trial
 * decryption. */
export async function sendRatchetMessage(
  x: ExecutorInternals,
  target: Contact,
  stored: StoredSession,
  text: string | null,
  control?: {
    readonly deletes?: readonly string[];
    readonly deleteSilent?: boolean;
    readonly group?: GroupEnvelope;
  },
): Promise<boolean> {
  if (x.token === null) {
    x.renderer.error("E201");
    return false;
  }
  const ratchet = deserializeRatchet(stored.ratchet);
  // A real message gets a fresh shared id so the peer stores it under the
  // same handle we do and a later /delete can name it on both sides.
  const mid = text !== null ? newMessageId() : null;
  // The payload carries the message text (if any) and our current mutual-
  // timer view, so a /timer change propagates over the encrypted body
  // it can also carry a cooperative deletion directive (control).
  const payload = encodeAppPayload({
    text,
    timerSeconds: target.timerSeconds,
    mid,
    deletes: control?.deletes ?? null,
    deleteSilent: control?.deleteSilent ?? false,
    group: control?.group ?? null,
  });
  const body = ratchetEncrypt(ratchet, payload);
  const envelope = encodeMsgEnvelope(body);
  if (envelope.length > MAX_PAYLOAD_BYTES) {
    x.renderer.error("E504");
    return false;
  }
  // Write-ahead the advanced ratchet before the send: the message
  // key is already consumed, so persisting first prevents any reuse if the
  // send fails.
  const timestamp = x.now();
  await x.store.putJson(`session/${target.uid}`, {
    ...stored,
    ratchet: serializeRatchet(ratchet),
  });
  await api.sendMessage(x.token, target.uid, envelope);
  // A real message is recorded at rest; the delivery tick and "sent" status
  // are raised by the caller. A pure timer/delete-control message carries no
  // user text, so it neither records nor confirms.
  // A group copy is stored once under the group by the caller, not once per
  // member, so the per-contact record is skipped for a fan-out leg.
  if (text !== null && control?.group === undefined) {
    await recordMessage(x, target.uid, "out", text, timestamp, mid);
  }
  await purgeExpired(x);
  return true;
}

/** Store a message at rest, stamping its disappearing-message
 * deadline from the contact's mutual timer if one is set. */
export async function recordMessage(
  x: ExecutorInternals,
  uid: string,
  dir: "in" | "out",
  text: string,
  ts: number,
  mid: string | null = null,
): Promise<void> {
  const timerSeconds = findContactByUid(x, uid)?.timerSeconds ?? null;
  const base: StoredMessage =
    timerSeconds === null
      ? { dir, text, ts }
      : { dir, text, ts, tmrExpiresAt: ts + timerSeconds * 1000 };
  const record: StoredMessage = mid === null ? base : { ...base, mid };
  // Same-millisecond sends would share a `msg/<uid>/<ts>` key and silently
  // overwrite each other, so collisions get an order-preserving sub-index.
  // record.ts is untouched: timer math and display order stay correct.
  let key = `msg/${uid}/${ts}`;
  if ((await x.store.getJson<StoredMessage>(key)) !== null) {
    let n = 1;
    while ((await x.store.getJson<StoredMessage>(`${key}.${n}`)) !== null) {
      n += 1;
    }
    key = `${key}.${n}`;
  }
  await x.store.putJson(key, record);
}

/** Store one group message under `gmsg/<gid>/<ts>`, a namespace of its own so
 * it can never collide with the per-contact `msg/<uid>/` history and so the
 * retention machinery can sweep both explicitly rather than by accident.
 * Incoming records keep the sender's label, since a group transcript has to say
 * who is speaking. */
export async function recordGroupMessage(
  x: ExecutorInternals,
  gid: string,
  dir: "in" | "out",
  sender: string,
  text: string,
  ts: number,
): Promise<void> {
  const record: StoredGroupMessage = { dir, sender, text, ts };
  let key = `${GROUP_MSG_PREFIX}${gid}/${ts}`;
  if ((await x.store.getJson<StoredGroupMessage>(key)) !== null) {
    let n = 1;
    while ((await x.store.getJson<StoredGroupMessage>(`${key}.${n}`)) !== null) {
      n += 1;
    }
    key = `${key}.${n}`;
  }
  await x.store.putJson(key, record);
}

/** Render an incoming group message according to the focused view, mirroring
 * deliverIncoming for one-to-one traffic. */
export function deliverIncomingGroup(
  x: ExecutorInternals,
  group: Group,
  senderLabel: string,
  text: string,
): void {
  if (x.activeGroup?.gid === group.gid) {
    x.renderer.peerMessage(`${group.name}/${senderLabel}`, text);
    return;
  }
  x.unread.set(group.gid, (x.unread.get(group.gid) ?? 0) + 1);
  x.renderer.status("info", `New message in '${group.name}'. Run /group open ${group.name} to read it.`);
  if (x.active === null && x.activeGroup === null) {
    x.enqueueRender(() => renderHome(x));
  }
}

/** A fresh shared message id: random 128-bit, hex. Stamped on outgoing
 * messages and echoed to the peer in the payload so /delete can reference the
 * same message on both devices. */
function newMessageId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Render an incoming message according to the focused view. When
 * the sender's conversation is on screen, append it live. Otherwise keep the
 * current view undisturbed: bump the sender's unread mark, post a status-
 * strip notice, and (only when sitting on the home dashboard) refresh it so
 * the new count shows. Either way the message is already stored. */
export function deliverIncoming(
  x: ExecutorInternals,
  uid: string,
  label: string,
  text: string,
): void {
  if (isActiveConversation(x, uid)) {
    x.renderer.peerMessage(label, text);
    return;
  }
  x.unread.set(uid, (x.unread.get(uid) ?? 0) + 1);
  x.renderer.status("info", `New message from ${label}. Run /chat ${label} to read it.`);
  if (x.active === null) {
    x.enqueueRender(() => renderHome(x));
  }
}

async function buildPrekeyLookup(x: ExecutorInternals): Promise<PrekeyLookup> {
  const spkMap = new Map<string, PrekeySecret>();
  for (const key of await x.store.listKeys("spk/")) {
    const record = await x.store.getJson<StoredSpk>(key);
    if (record !== null) {
      const pub = fromBase64(record.pub);
      spkMap.set(bytesToHex(sha512(pub)), { pub, sec: fromBase64(record.sec), storeKey: key });
    }
  }
  const opkMap = new Map<string, PrekeySecret>();
  for (const key of await x.store.listKeys("opk/")) {
    const record = await x.store.getJson<StoredOpk>(key);
    if (record !== null) {
      const pub = fromBase64(record.pub);
      opkMap.set(bytesToHex(sha512(pub)), { pub, sec: fromBase64(record.sec), storeKey: key });
    }
  }
  return {
    spkByHash: (hash) => spkMap.get(hash) ?? null,
    opkByHash: (hash) => opkMap.get(hash) ?? null,
  };
}

/** Returns "ack" when the message was fully handled (or safely discarded)
 * and may be deleted server-side; "skip" leaves it queued for later. */
export async function processEnvelope(
  x: ExecutorInternals,
  envelopeBytes: Uint8Array,
): Promise<"ack" | "skip"> {
  if (x.identity === null || x.token === null || !x.store.isUnlocked()) {
    return "skip";
  }
  // A ratchet message routes to the trial-decrypt path; only a KX
  // first message consumes a prekey.
  if (envelopeType(envelopeBytes) === ENVELOPE_TYPE_MSG) {
    return processRatchetMessage(x, envelopeBytes);
  }
  const epoch = x.epoch;
  const lookup = await buildPrekeyLookup(x);
  if (x.epoch !== epoch || x.identity === null) {
    return "skip"; // locked out / wiped while reading prekeys
  }
  const result = respondKx(x.identity.pub, lookup, envelopeBytes);
  if (!result.ok) {
    if (result.reason === "bad-signature") {
      x.renderer.event(
        "security",
        "A message arrived with an INVALID identity signature, so it was discarded.",
      );
    } else if (result.reason === "unknown-spk" || result.reason === "unknown-opk") {
      // A real contact attempt against prekeys this device no longer holds
      // (typically after /recover or /wipe replaced them). The sender must
      // re-fetch our current bundle; nothing here can fix it for them.
      x.renderer.discarded("E511");
    } else {
      // malformed / decrypt-failed: corrupted or tampered, not a contact attempt.
      x.renderer.discarded("E512");
    }
    return "ack";
  }

  // Spec 3.7: delete the consumed OPK secret immediately.
  if (result.consumedOpkStoreKey !== null) {
    await x.store.deleteKey(result.consumedOpkStoreKey);
  }

  let senderUid: string | null = null;
  let text: string | null = null;
  let mid: string | null = null;
  let group: GroupEnvelope | null = null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(result.plaintext));
    if (typeof parsed === "object" && parsed !== null) {
      const record = parsed as {
        u?: unknown;
        m?: unknown;
        id?: unknown;
        g?: unknown;
        gn?: unknown;
        gm?: unknown;
        ga?: unknown;
        gs?: unknown;
      };
      senderUid = typeof record.u === "string" ? normalizeUid(record.u) : null;
      text = typeof record.m === "string" ? record.m : null;
      mid = typeof record.id === "string" ? record.id : null;
      // The KX first message carries the same group fields under the same key
      // names as an ordinary ratchet payload does (see sendFirstMessage), so
      // this reuses the one shared validator rather than trusting a second,
      // ad hoc read of peer-supplied data.
      group = decodeGroupEnvelope(record);
    }
  } catch {
    // fall through to the discard below
  }
  if (senderUid === null || text === null) {
    x.renderer.discarded("E506");
    return "ack";
  }

  const senderIkB64 = toBase64(result.senderIk);
  const timestamp = x.now();
  if (x.epoch !== epoch) {
    return "skip"; // torn down while decrypting; leave queued server-side
  }
  const contact = findContactByUid(x, senderUid);

  if (contact !== null) {
    if (contact.ik !== null && contact.ik !== senderIkB64) {
      // Manual trust discards a message on a changed key and blocks; auto-
      // trust re-pins (loud warning) and accepts it under the new key.
      if (!(await handleKeyChange(x, contact, senderIkB64))) {
        x.renderer.event(
          "security",
          `A message claiming to be ${contact.alias} used the new, unconfirmed key, so it was DISCARDED.`,
        );
        return "ack";
      }
    } else if (contact.ik === null) {
      x.contacts.set(contact.alias, pinKey(x, contact, senderIkB64));
      await saveContacts(x);
    }
    await x.store.putJson(`session/${senderUid}`, serializeSession(result.session, timestamp));
    // A group's first message to a member skips the extra round trip a
    // session would otherwise need (see sendFirstMessage), so a group
    // envelope can arrive right here, on the handshake itself, and not only
    // over an already-established ratchet. Route it exactly like the ratchet
    // path does rather than flattening add/remove/invite into plain text.
    if (group !== null) {
      await applyIncomingGroup(x, senderUid, contact.alias, group, text, timestamp);
      return "ack";
    }
    await recordMessage(x, senderUid, "in", text, timestamp, mid);
    deliverIncoming(x, senderUid, contact.alias, text);
    if (result.session.reducedFs) {
      x.renderer.event(
        "warning",
        "This session has reduced forward secrecy, because no one-time prekey was used.",
      );
    }
    return "ack";
  }

  // Unknown sender: bind the claimed UID to the envelope's identity key via a
  // non-consuming bundle fetch before holding it as a request.
  try {
    const senderWire = await api.fetchBundle(x.token, senderUid, false);
    if (x.epoch !== epoch) {
      return "skip";
    }
    if (senderWire.ik_pub !== senderIkB64) {
      x.renderer.event(
        "security",
        "The sender's identity does not match its claimed UID, so the message was DISCARDED.",
      );
      return "ack";
    }
  } catch {
    if (x.epoch !== epoch) {
      return "skip";
    }
    x.renderer.discarded("E508");
    return "ack";
  }
  const pending: PendingRequest = {
    text,
    session: serializeSession(result.session, timestamp),
    senderIk: senderIkB64,
    receivedAt: timestamp,
    mid,
  };
  await x.store.putJson(`pending/${senderUid}`, pending);
  await refreshEmblemState(x); // an unread request now awaits /add
  x.renderer.event(
    "warning",
    `New contact request from ${formatUid(senderUid)}. Run /add ${senderUid} [alias] to accept.`,
  );
  return "ack";
}

/** Decrypt a ratchet MSG. Since the envelope carries no sender
 * identity, try each established session; the header AEAD authenticates the
 * match and a non-matching session fails without mutating its state.
 * Delivery is idempotent: a replay of an already-consumed message decrypts to
 * nothing, so we drop it. */
export async function processRatchetMessage(
  x: ExecutorInternals,
  envelopeBytes: Uint8Array,
): Promise<"ack" | "skip"> {
  const body = decodeMsgEnvelope(envelopeBytes);
  if (body === null) {
    x.renderer.discarded("E507");
    return "ack";
  }
  const epoch = x.epoch;
  for (const key of await x.store.listKeys("session/")) {
    if (x.epoch !== epoch || x.identity === null) {
      return "skip"; // locked out / wiped mid-scan
    }
    const stored = await x.store.getJson<StoredSession>(key);
    if (stored === null) {
      continue;
    }
    const ratchet = deserializeRatchet(stored.ratchet);
    const result = ratchetDecrypt(ratchet, body);
    if (!result.ok) {
      continue; // not this session (or out-of-order/duplicate): leave it untouched
    }
    const uid = key.slice("session/".length);
    const timestamp = x.now();
    if (x.epoch !== epoch) {
      return "skip"; // torn down while decrypting; leave queued server-side
    }
    await x.store.putJson(key, { ...stored, ratchet: serializeRatchet(ratchet) });
    const payload = decodeAppPayload(result.plaintext);
    if (payload === null) {
      x.renderer.discarded("E506");
      return "ack";
    }
    const contact = findContactByUid(x, uid);
    const label = contact?.alias ?? formatUid(uid);
    // Adopt a mutual-timer change carried by the peer and announce it.
    await applyIncomingTimer(x, uid, label, payload.timerSeconds);
    // Honor a cooperative deletion the peer requested for messages they sent
    // us.
    if (payload.deletes !== null) {
      await applyIncomingDeletion(x, uid, label, payload.deletes, payload.deleteSilent);
    }
    if (payload.group !== null) {
      // A group message is still an ordinary pairwise message; only its
      // handling differs, and only after the pairwise ratchet has already
      // authenticated who sent it.
      await applyIncomingGroup(x, uid, label, payload.group, payload.text, timestamp);
      await purgeExpired(x);
      return "ack";
    }
    if (payload.text !== null) {
      await recordMessage(x, uid, "in", payload.text, timestamp, payload.mid);
      deliverIncoming(x, uid, label, payload.text);
    }
    await purgeExpired(x);
    return "ack";
  }
  x.renderer.discarded("E505");
  return "ack";
}

/** Handle a group-bearing payload that has already been authenticated by the
 * pairwise ratchet it arrived on.
 *
 * `senderUid` is the crucial input and it does NOT come from the message: it is
 * the session the envelope decrypted under, so a member cannot claim to be
 * someone else. Every membership decision below is attributed to that UID.
 *
 * Three rules keep an unwanted group from materialising on this device:
 *   - A group from someone who is not a contact is ignored entirely. The
 *     first-contact gate already governs whether a stranger can reach you;
 *     groups do not get to bypass it.
 *   - A sender who is not in the roster they are sending is ignored. That is
 *     either a bug or a forgery, and neither deserves state.
 *   - An unknown group is only created when the sender says so explicitly with
 *     an invite, and only when it lists us. Ordinary traffic for a group we do
 *     not have is reported, never silently joined. */
export async function applyIncomingGroup(
  x: ExecutorInternals,
  senderUid: string,
  senderLabel: string,
  envelope: GroupEnvelope,
  text: string | null,
  timestamp: number,
): Promise<void> {
  const self = x.identity?.uid ?? null;
  if (self === null) {
    return;
  }
  if (findContactByUid(x, senderUid) === null) {
    // Not a contact: no group state, no notice beyond the discard panel. The
    // contact-request gate is the only way a stranger reaches this device.
    x.renderer.discarded("E513");
    return;
  }
  // Being told you were removed is the one message that legitimately arrives
  // with you absent from its roster: the roster it carries is the one that
  // exists AFTER the removal, which is exactly the point of sending it. Without
  // this exception the notice is discarded by the only person who needs it, and
  // they go on believing they are still in the group.
  const removesMe = envelope.action === "remove" && envelope.subject === self;
  if (
    !envelope.members.includes(senderUid) ||
    (!envelope.members.includes(self) && !removesMe)
  ) {
    x.renderer.discarded("E513");
    return;
  }

  const existing = await loadGroup(x, envelope.gid);
  if (existing !== null && !existing.members.includes(senderUid)) {
    // The check above only verified the sender's OWN self-reported roster,
    // which is worthless as a gate: someone this device already removed is
    // still a 1:1 contact and still knows the gid, so without checking OUR
    // OWN roster they could keep forging add/remove envelopes forever and
    // have every one of them applied. `existing.members` is what this device
    // actually holds, not what the envelope claims.
    x.renderer.discarded("E513");
    return;
  }
  if (existing === null) {
    if (envelope.action !== "invite") {
      // Traffic for a group this device does not know. Reported rather than
      // joined: adopting a roster from an unsolicited message is exactly how a
      // silent add would work.
      x.renderer.event(
        "warning",
        `${senderLabel} sent a message for a group this device does not know ('${envelope.name}'). Ask them to invite you again if you should be in it.`,
      );
      return;
    }
    // The name comes from the sender, and every /group subcommand addresses a
    // group by name, so a collision with a group already here would decide
    // where a later message goes. Disambiguate and say so.
    const name = await uniqueGroupName(x, envelope.name);
    const group: Group = {
      gid: envelope.gid,
      name,
      members: envelope.members,
      createdAt: timestamp,
      active: true,
    };
    await saveGroup(x, group);
    x.renderer.event(
      "success",
      `${senderLabel} added you to the group '${group.name}' with ${group.members.length} members. /group info ${group.name} shows who is in it.`,
    );
    if (name !== envelope.name) {
      x.renderer.event(
        "warning",
        `They called it '${envelope.name}', which is the name of a group you already have, so this one is '${name}' here. Check with them that you are in the group you think you are.`,
      );
    }
    await noteUnknownMembers(x, group);
    if (text !== null) {
      await recordGroupMessage(x, group.gid, "in", senderLabel, text, timestamp);
      deliverIncomingGroup(x, group, senderLabel, text);
    }
    return;
  }

  // The group is known. Work out the roster this device will hold once the
  // ANNOUNCED change is applied, and only then compare against what the sender
  // claims. Comparing before applying meant every legitimate add and removal
  // raised a divergence warning, which is the fastest way to teach someone to
  // ignore a security warning.
  //
  // Note what is NOT done here: the sender's roster is never adopted wholesale.
  // This device applies only the delta the sender announced, to its own roster.
  // A member who lies about the roster therefore cannot rewrite it with one
  // message; the most they can do is disagree, and disagreement is what the
  // warning below reports.
  const applied = applyAnnouncedChange(existing.members, envelope, senderUid);
  warnOnRosterDivergence(x, { ...existing, members: applied }, envelope, senderLabel);

  switch (envelope.action) {
    case "add":
    case "remove": {
      const subject = envelope.subject;
      if (subject === null) {
        return;
      }
      const subjectLabel = findContactByUid(x, subject)?.alias ?? formatUid(subject);
      const leftBehind = envelope.action === "remove" && subject === self;
      const updated: Group = {
        ...existing,
        members: applied,
        active: leftBehind ? false : existing.active,
      };
      await saveGroup(x, updated);
      if (leftBehind && x.activeGroup?.gid === existing.gid) {
        // This device is the one just removed, and the group it lost access
        // to is the one on screen. Leaving it focused would let the next
        // typed line keep routing into a group nothing more will ever arrive
        // in, exactly like a stale activeGroup let /return misroute earlier.
        x.activeGroup = null;
        x.shell.setPrompt("> ");
        x.chrome.setChatContext(null);
        x.enqueueRender(() => renderHome(x));
      }
      x.renderer.event(
        "security",
        envelope.action === "add"
          ? `${senderLabel} added ${subjectLabel} to '${existing.name}'. Anyone already in a group can add someone, and membership is not cryptographically agreed, so check an unexpected addition with the others.`
          : leftBehind
            ? `${senderLabel} removed you from '${existing.name}'. Nothing more will arrive; the history stays on this device until you /group purge it.`
            : `${senderLabel} removed ${subjectLabel} from '${existing.name}'. They keep every message they already received; there is no group key to rotate.`,
      );
      if (envelope.action === "add") {
        await noteUnknownMembers(x, updated);
      }
      return;
    }
    case "leave": {
      await saveGroup(x, { ...existing, members: applied });
      x.renderer.event("info", `${senderLabel} left '${existing.name}'.`);
      return;
    }
    case "invite":
    case "msg": {
      if (text === null) {
        return;
      }
      await recordGroupMessage(x, existing.gid, "in", senderLabel, text, timestamp);
      deliverIncomingGroup(x, existing, senderLabel, text);
      return;
    }
  }
}


/** Point out members this device has no contact entry for. They are in the
 * group and will receive everything sent to it, but nothing here has verified
 * their key, so naming them is more useful than a silent roster entry. */
async function noteUnknownMembers(x: ExecutorInternals, group: Group): Promise<void> {
  const self = x.identity?.uid ?? null;
  const unknown = group.members.filter(
    (uid) => uid !== self && findContactByUid(x, uid) === null,
  );
  if (unknown.length === 0) {
    return;
  }
  x.renderer.event(
    "warning",
    `${unknown.length} member(s) of '${group.name}' are not in your contacts, so their keys are unverified and you cannot send to them: ${unknown.map(formatUid).join(", ")}. /add each UID to include them.`,
  );
  await Promise.resolve();
}

export async function drainInbox(x: ExecutorInternals): Promise<void> {
  if (x.token === null) {
    return;
  }
  const inbox = await api.fetchMessages(x.token);
  const acks: number[] = [];
  for (const message of inbox.messages) {
    let envelope: Uint8Array;
    try {
      envelope = fromBase64(message.envelope);
    } catch {
      acks.push(message.id); // not even base64: drop
      continue;
    }
    if ((await processEnvelope(x, envelope)) === "ack") {
      acks.push(message.id);
    }
  }
  if (acks.length > 0 && x.token !== null) {
    await api.ackMessages(x.token, acks);
  }
}
