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
import { decodeAppPayload, encodeAppPayload } from "./payload";
import {
  deserializeRatchet,
  serializeRatchet,
  serializeSession,
  wireToBundle,
} from "./records";
import type {
  Contact,
  PendingRequest,
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
  let sent = false;
  try {
    sent = await sendFirstMessage(x, target, text);
  } catch (err) {
    // A thrown send (e.g. network) still marks the echoed line failed; the
    // specific reason is logged by the run() error path.
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

/** Send to `target`, running the PQ-KX handshake first if no session exists
 * yet; an established session rides the ratchet instead. Returns
 * true only when an envelope was accepted by the server. */
export async function sendFirstMessage(
  x: ExecutorInternals,
  target: Contact,
  text: string,
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
    return sendRatchetMessage(x, target, existing, text);
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
  const payload = new TextEncoder().encode(
    JSON.stringify({ u: x.identity.uid, m: text, id: mid }),
  );
  const { envelope, session } = initiateKx(x.identity.pub, x.identity.sec, bundle, payload);
  await api.sendMessage(x.token, target.uid, envelope);

  const timestamp = x.now();
  await x.store.putJson(`session/${target.uid}`, serializeSession(session, timestamp));
  await recordMessage(x, target.uid, "out", text, timestamp, mid);
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
    `prekey bundle signature verification FAILED for ${target.alias} - the server may be tampering. send aborted.`,
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
  control?: { readonly deletes?: readonly string[]; readonly deleteSilent?: boolean },
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
  if (text !== null) {
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
  x.renderer.status("info", `new message from ${label} - /chat ${label} to read`);
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
        "received a message with an INVALID identity signature - discarded",
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

  // Spec 3.7: the consumed OPK secret is deleted immediately.
  if (result.consumedOpkStoreKey !== null) {
    await x.store.deleteKey(result.consumedOpkStoreKey);
  }

  let senderUid: string | null = null;
  let text: string | null = null;
  let mid: string | null = null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(result.plaintext));
    if (typeof parsed === "object" && parsed !== null) {
      const record = parsed as { u?: unknown; m?: unknown; id?: unknown };
      senderUid = typeof record.u === "string" ? normalizeUid(record.u) : null;
      text = typeof record.m === "string" ? record.m : null;
      mid = typeof record.id === "string" ? record.id : null;
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
          `message claiming to be ${contact.alias} used the new (unconfirmed) key - DISCARDED`,
        );
        return "ack";
      }
    } else if (contact.ik === null) {
      x.contacts.set(contact.alias, pinKey(x, contact, senderIkB64));
      await saveContacts(x);
    }
    await x.store.putJson(`session/${senderUid}`, serializeSession(result.session, timestamp));
    await recordMessage(x, senderUid, "in", text, timestamp, mid);
    deliverIncoming(x, senderUid, contact.alias, text);
    if (result.session.reducedFs) {
      x.renderer.event("warning", "session has reduced forward secrecy (no one-time prekey)");
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
        "sender identity does not match its claimed UID - message DISCARDED",
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
    `new contact request from ${formatUid(senderUid)} - /add ${senderUid} [alias] to accept`,
  );
  return "ack";
}

/** Decrypt a ratchet MSG. Since the envelope carries no sender
 * identity, try each established session; the header AEAD authenticates the
 * match and a non-matching session fails without mutating its state.
 * Delivery is idempotent: a replay of an already-consumed message decrypts to
 * nothing and is dropped. */
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
