// Contact management: /add (which doubles as accepting a held contact
// request, spec 7.4) and the /contacts listing. Aliases are local-only; the
// server never learns them.

import { formatUid } from "../parser";
import {
  findContactByUid,
  pinKey,
  refreshEmblemState,
  saveContacts,
} from "./context";
import type { ExecutorInternals } from "./context";
import { formatDuration } from "./format";
import { normalizeContact } from "./records";
import type { PendingRequest } from "./records";
import { recordMessage } from "./messaging";

export async function doAdd(
  x: ExecutorInternals,
  uid: string,
  alias: string | undefined,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.event("failure", "contacts live in the encrypted store - /login first");
    return;
  }
  const name = alias ?? uid;
  const existing = findContactByUid(x, uid);
  const contact = normalizeContact({
    uid,
    alias: name,
    ik: existing?.ik ?? null,
    verified: existing?.verified,
    keyChangeBlocked: existing?.keyChangeBlocked,
  });
  if (existing !== null) {
    x.contacts.delete(existing.alias);
  }
  x.contacts.set(name, contact);

  const pending = await x.store.getJson<PendingRequest>(`pending/${uid}`);
  if (pending !== null) {
    // Accepting a held first-contact message (spec 7.4): promote its session
    // and show the message that was queued behind the request line.
    await x.store.putJson(`session/${uid}`, pending.session);
    await recordMessage(x, uid, "in", pending.text, pending.receivedAt, pending.mid ?? null);
    await x.store.deleteKey(`pending/${uid}`);
    x.contacts.set(name, pinKey(x, contact, pending.senderIk));
    await saveContacts(x);
    await refreshEmblemState(x); // the held request is resolved
    x.renderer.event("success", `added contact ${name} (${formatUid(uid)})`);
    x.renderer.peerMessage(name, pending.text);
    if (pending.session.reducedFs) {
      x.renderer.event(
        "warning",
        "session has reduced forward secrecy (no one-time prekey was used)",
      );
    }
    return;
  }
  await saveContacts(x);
  x.renderer.event(
    "success",
    `added contact ${name} (${formatUid(uid)}) - alias is local-only`,
  );
}

/** `/contacts`: list every saved contact with its alias, full UID, and trust
 * state, plus any saved contact-request UIDs still awaiting /add. A plain
 * informational listing (like /keys status); it does not switch views. */
export async function doContacts(x: ExecutorInternals): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.event("warning", "contacts live in the encrypted store - /login first");
    return;
  }
  const contacts = [...x.contacts.values()].sort((a, b) => a.alias.localeCompare(b.alias));
  if (contacts.length === 0) {
    x.renderer.event("info", "no contacts yet - /add <uid> [alias] to add one");
  } else {
    x.renderer.event("info", `contacts (${contacts.length}):`);
    const width = Math.max(...contacts.map((c) => c.alias.length));
    for (const contact of contacts) {
      const flags = [
        contact.verified ? "verified" : "UNVERIFIED",
        contact.keyChangeBlocked ? "KEY CHANGED — /ack" : "",
        contact.timerSeconds === null ? "" : `timer ${formatDuration(contact.timerSeconds)}`,
      ]
        .filter((s) => s.length > 0)
        .join(" · ");
      x.renderer.plain(`  ${contact.alias.padEnd(width)}  ${formatUid(contact.uid)}  ${flags}`);
    }
  }
  const pending = await x.store.listKeys("pending/");
  if (pending.length > 0) {
    x.renderer.event("info", `contact requests (${pending.length}) - /add to accept:`);
    for (const key of pending) {
      const uid = key.slice("pending/".length);
      x.renderer.plain(`  ${formatUid(uid)}`);
    }
  }
}
