// Transcript views (§1.5): the focused conversation view /chat switches
// into, the home dashboard /home returns to, the /return toggle between
// them, and the /contacts listing. xterm is append-only, so "removing" a
// line from a view always means clearing the screen and reprinting what
// remains; every rebuild here runs on the executor's render lane.

import { formatUid } from "../parser";
import {
  currentViewRef,
  findContactByUid,
  refreshChatContext,
} from "./context";
import type { ExecutorInternals } from "./context";
import { formatDuration } from "./format";
import type { StoredMessage } from "./records";

/** Rebuild the transcript as the focused conversation view: clear the screen
 * and reprint only the active conversation's stored history, oldest first.
 * This is what /chat switches into and what a /delete redraws, so a deleted
 * line actually disappears rather than lingering in an interleaved log.
 * No-op when nothing is active or the store is locked. */
export async function renderActiveConversation(x: ExecutorInternals): Promise<void> {
  if (x.active === null || !x.store.isUnlocked()) {
    return;
  }
  const contact = findContactByUid(x, x.active.uid) ?? x.active;
  const records: StoredMessage[] = [];
  for (const key of await x.store.listKeys(`msg/${contact.uid}/`)) {
    const record = await x.store.getJson<StoredMessage>(key);
    if (record !== null) {
      records.push(record);
    }
  }
  records.sort((a, b) => a.ts - b.ts);
  x.chrome.clearScreen(false); // silent wipe before reprinting
  const trust = contact.verified ? "verified" : "UNVERIFIED";
  const timer =
    contact.timerSeconds === null ? "" : ` · timer ${formatDuration(contact.timerSeconds)}`;
  x.renderer.divider(`-- conversation with ${contact.alias} (${trust})${timer} --`);
  if (records.length === 0) {
    x.renderer.plain("  (no messages yet - type to send the first one · /home to go back)");
  }
  for (const record of records) {
    if (record.dir === "in") {
      x.renderer.peerMessage(contact.alias, record.text);
    } else {
      x.renderer.ownMessage(record.text);
    }
  }
  if (contact.keyChangeBlocked) {
    x.renderer.event(
      "security",
      `sending to ${contact.alias} is blocked by an unacknowledged key change - /ack ${contact.alias}, then /verify + /verified to resume`,
    );
  }
}

/** Rebuild the transcript as the home view: the dashboard of every
 * conversation (the "everything else" that /chat hides and /home brings
 * back). Lists contacts with their trust, unread count, timer and any
 * key-change block, plus held contact requests. Falls back to a minimal
 * screen while locked/logged out. No untrusted markup: plain sanitized text
 * only. */
export async function renderHome(x: ExecutorInternals): Promise<void> {
  x.chrome.clearScreen(false);
  x.renderer.divider("-- home --");
  if (x.identity === null || !x.store.isUnlocked()) {
    x.renderer.plain("  locked - /login to unlock, or /register to create an identity");
    return;
  }
  const contacts = [...x.contacts.values()].sort((a, b) => a.alias.localeCompare(b.alias));
  if (contacts.length === 0) {
    x.renderer.plain("  no contacts yet - /add <uid> [alias] to add one");
  } else {
    x.renderer.plain("  contacts:");
    const width = Math.max(...contacts.map((c) => c.alias.length));
    for (const contact of contacts) {
      const unread = x.unread.get(contact.uid) ?? 0;
      const flags = [
        contact.verified ? "verified" : "UNVERIFIED",
        unread > 0 ? `${unread} unread` : "",
        contact.keyChangeBlocked ? "KEY CHANGED - /ack" : "",
        contact.timerSeconds === null ? "" : `timer ${formatDuration(contact.timerSeconds)}`,
      ]
        .filter((s) => s.length > 0)
        .join(" · ");
      x.renderer.plain(`    ${contact.alias.padEnd(width)}  ${flags}`);
    }
  }
  const pending = await x.store.listKeys("pending/");
  if (pending.length > 0) {
    x.renderer.plain("");
    x.renderer.plain("  contact requests:");
    for (const key of pending) {
      const uid = key.slice("pending/".length);
      x.renderer.plain(`    ${formatUid(uid)}  - /add ${uid} [alias] to accept`);
    }
  }
  x.renderer.plain("");
  x.renderer.divider(
    "  /chat <alias> to open a conversation · /contacts for UIDs · /help for commands",
  );
}

/** `/return`: toggle back to the screen shown before the current one, naming
 * where it went. The two screens swap each call, so /return alternates like
 * a back/forward button. Falls back to home if the remembered conversation's
 * contact is gone (removed or wiped). */
export function returnToPreviousView(x: ExecutorInternals): void {
  if (x.previousView === null) {
    x.renderer.event("info", "no previous screen to return to");
    return;
  }
  const current = currentViewRef(x);
  const target = x.previousView;
  x.previousView = current; // swap so a second /return comes back here
  if (target.kind === "home") {
    x.active = null;
    x.shell.setPrompt("> ");
    refreshChatContext(x);
    x.renderer.event("info", "returned to home");
    x.enqueueRender(() => renderHome(x));
    return;
  }
  const contact = findContactByUid(x, target.uid);
  if (contact === null) {
    x.active = null;
    x.previousView = null;
    x.shell.setPrompt("> ");
    refreshChatContext(x);
    x.renderer.event("warning", "that conversation is no longer available - returned to home");
    x.enqueueRender(() => renderHome(x));
    return;
  }
  x.active = contact;
  x.unread.delete(contact.uid);
  x.shell.setPrompt(`[${contact.alias}] > `);
  refreshChatContext(x);
  x.renderer.event("info", `returned to the conversation with ${contact.alias}`);
  x.enqueueRender(() => renderActiveConversation(x));
}
