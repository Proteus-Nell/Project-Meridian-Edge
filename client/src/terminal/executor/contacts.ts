// Contact management: /add (which doubles as accepting a held contact
// request, §7.4) and the /contacts listing. Aliases are local-only; the
// server never learns them.

import { formatUid } from "../parser";
import type { RemoveTarget } from "../parser";
import {
  findContactByUid,
  pinKey,
  refreshChatContext,
  refreshEmblemState,
  resolveContact,
  saveContacts,
} from "./context";
import type { ExecutorInternals } from "./context";
import { formatDuration } from "./format";
import { normalizeContact } from "./records";
import type { Contact, PendingRequest } from "./records";
import { recordMessage } from "./messaging";
import { renderHome } from "./views";

export async function doAdd(
  x: ExecutorInternals,
  uid: string,
  alias: string | undefined,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
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
    // Accepting a held first-contact message (§7.4): promote its session
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
        contact.keyChangeBlocked ? "KEY CHANGED - /ack" : "",
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

/** `/remove <alias|uid|all> [purge]`: remove a contact locally. Ends the
 * relationship - deletes the contact entry and tears down the ratchet
 * session, so a later message from them arrives as a fresh contact request -
 * and drops any held request and unread mark. Message history is KEPT unless
 * `purge` is given, which also deletes msg/<uid> (irreversible; browser
 * deletion is not forensic erasure, §5.4). `all` clears every contact and
 * confirms first. Nothing is signalled to the peer; removal is purely local. */
export async function doRemove(
  x: ExecutorInternals,
  target: RemoveTarget,
  purge: boolean,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  if (target.kind === "all") {
    await removeAllContacts(x, purge);
    return;
  }
  const contact = resolveContact(x, target.value);
  if (contact === null) {
    x.renderer.error("E501", target.value);
    return;
  }
  x.contacts.delete(contact.alias);
  await forgetContact(x, contact, purge);
  await saveContacts(x);
  if (x.active?.uid === contact.uid) {
    goHomeAfterRemoval(x);
  } else if (x.previousView?.kind === "chat" && x.previousView.uid === contact.uid) {
    x.previousView = null; // the remembered screen is gone
  }
  await refreshEmblemState(x);
  x.renderer.event(
    "success",
    purge
      ? `removed ${contact.alias} (${formatUid(contact.uid)}) and its message history`
      : `removed ${contact.alias} (${formatUid(contact.uid)}) - message history kept (add 'purge' to delete it too)`,
  );
}

async function removeAllContacts(x: ExecutorInternals, purge: boolean): Promise<void> {
  const count = x.contacts.size;
  if (count === 0) {
    x.renderer.event("info", "no contacts to remove");
    return;
  }
  const suffix = purge ? " and their message history" : "";
  const answer = await x.shell.readLine(`remove ALL ${count} contact(s)${suffix}? (yes/NO): `);
  if (answer === null || answer.trim().toLowerCase() !== "yes") {
    x.renderer.event("info", "removal cancelled - nothing was changed");
    return;
  }
  for (const contact of [...x.contacts.values()]) {
    await forgetContact(x, contact, purge);
  }
  x.contacts.clear();
  x.unread.clear();
  await saveContacts(x);
  goHomeAfterRemoval(x);
  await refreshEmblemState(x);
  x.renderer.event("success", `removed all ${count} contact(s)${suffix}`);
}

/** Tear down a single contact's stored side artifacts: the ratchet session,
 * any held request, its unread mark, and (only when `purge`) its at-rest
 * message history. Does not touch the contacts map - the caller owns that. */
async function forgetContact(
  x: ExecutorInternals,
  contact: Contact,
  purge: boolean,
): Promise<void> {
  await x.store.deleteKey(`session/${contact.uid}`);
  await x.store.deleteKey(`pending/${contact.uid}`);
  x.unread.delete(contact.uid);
  if (purge) {
    for (const key of await x.store.listKeys(`msg/${contact.uid}/`)) {
      await x.store.deleteKey(key);
    }
  }
}

/** Return to the home dashboard after the focused (or every) contact was
 * removed: the conversation it showed no longer exists. */
function goHomeAfterRemoval(x: ExecutorInternals): void {
  x.active = null;
  x.previousView = null;
  x.shell.setPrompt("> ");
  refreshChatContext(x);
  x.enqueueRender(() => renderHome(x));
}

/** `/rename <alias|uid> <new-alias>`: give a contact a new local alias.
 * Aliases never leave the device. Rekeys the contacts map; message history is
 * stored by UID, so it is unaffected. Rejects a name already used by another
 * contact. */
export async function doRename(
  x: ExecutorInternals,
  target: string,
  newAlias: string,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const contact = resolveContact(x, target);
  if (contact === null) {
    x.renderer.error("E501", target);
    return;
  }
  if (contact.alias === newAlias) {
    x.renderer.event("info", `${contact.alias} already goes by that name`);
    return;
  }
  const clash = x.contacts.get(newAlias);
  if (clash !== undefined && clash.uid !== contact.uid) {
    x.renderer.error("E510", newAlias);
    return;
  }
  const oldAlias = contact.alias;
  const renamed: Contact = { ...contact, alias: newAlias };
  x.contacts.delete(oldAlias);
  x.contacts.set(newAlias, renamed);
  await saveContacts(x);
  if (x.active?.uid === contact.uid) {
    x.active = renamed;
    x.shell.setPrompt(`[${newAlias}] > `);
  }
  refreshChatContext(x);
  x.renderer.event("success", `renamed ${oldAlias} to ${newAlias}`);
}
