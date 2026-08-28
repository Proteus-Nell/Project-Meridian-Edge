// Transcript views: the focused conversation view /chat switches
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
import { favouriteMark, sortContacts } from "./records";
import type { StoredMessage } from "./records";
import { loadGroup, loadGroups, rosterDigest } from "./groups";
import type { Group } from "./groups";
import { loadGroupHistory } from "./group-commands";

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
  x.renderer.resetMessageDay(); // the dividers went with it; date the first line again
  const trust = contact.verified ? "verified" : "UNVERIFIED";
  const timer =
    contact.timerSeconds === null ? "" : ` · timer ${formatDuration(contact.timerSeconds)}`;
  x.renderer.divider(`-- conversation with ${contact.alias} (${trust})${timer} --`);
  if (records.length === 0) {
    x.renderer.plain("  (No messages yet. Type to send the first one, or /home to go back.)");
  }
  for (const record of records) {
    // The record's own `ts`, not the moment of the rebuild: a /delete redraw
    // must not restamp the whole conversation with the time it was redrawn.
    if (record.dir === "in") {
      x.renderer.peerMessage(contact.alias, record.text, record.ts);
    } else {
      x.renderer.ownMessage(record.text, record.ts);
    }
  }
  if (contact.keyChangeBlocked) {
    x.renderer.event(
      "security",
      `Sending to ${contact.alias} is blocked by an unacknowledged key change. Run /ack ${contact.alias}, then /verify and /verified to resume.`,
    );
  }
}

/** Rebuild the transcript as a group conversation: the roster header, then the
 * stored history with each line attributed to its sender. Attribution matters
 * more here than in a one-to-one view, because a group transcript is assembled
 * from N independently authenticated pairwise streams and the sender label is
 * the only thing carrying who said what. */
export async function renderGroupConversation(
  x: ExecutorInternals,
  group: Group,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    return;
  }
  const records = await loadGroupHistory(x, group.gid);
  x.chrome.clearScreen(false);
  x.renderer.resetMessageDay();
  x.renderer.divider(
    `-- ${group.name} · ${group.members.length} members · fingerprint ${rosterDigest(group.members)} --`,
  );
  if (records.length === 0) {
    x.renderer.plain("  (No messages yet. Type to send the first one, or /home to go back.)");
  }
  for (const record of records) {
    if (record.dir === "in") {
      x.renderer.peerMessage(`${group.name}/${record.sender}`, record.text, record.ts);
    } else {
      x.renderer.ownMessage(record.text, record.ts);
    }
  }
}

/** Redraw whichever conversation is on screen, one-to-one or group. Used where
 * a display setting changes how a message line is drawn: the transcript is
 * append-only, so the only way such a change reaches lines already printed is
 * to clear and reprint them. The home dashboard carries no message lines, so
 * sitting there is a no-op. */
export async function redrawConversation(x: ExecutorInternals): Promise<void> {
  if (x.activeGroup !== null) {
    await renderGroupConversation(x, x.activeGroup);
    return;
  }
  if (x.active !== null) {
    await renderActiveConversation(x);
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
  x.renderer.resetMessageDay();
  x.renderer.divider("-- home --");
  if (x.identity === null || !x.store.isUnlocked()) {
    x.renderer.plain("  Locked. Run /login to unlock, or /register to create an identity.");
    return;
  }
  // Favourites first (/favourite), then alphabetical - the same order /contacts
  // prints, with a leading '*' marking the pinned ones.
  const contacts = sortContacts([...x.contacts.values()]);
  if (contacts.length === 0) {
    x.renderer.plain("  No contacts yet. Run /add <uid> [alias] to add one.");
  } else {
    x.renderer.plain("  contacts:");
    const width = Math.max(...contacts.map((c) => c.alias.length));
    for (const contact of contacts) {
      const unread = x.unread.get(contact.uid) ?? 0;
      const flags = [
        contact.verified ? "verified" : "UNVERIFIED",
        unread > 0 ? `${unread} unread` : "",
        contact.keyChangeBlocked ? "KEY CHANGED (/ack)" : "",
        contact.timerSeconds === null ? "" : `timer ${formatDuration(contact.timerSeconds)}`,
      ]
        .filter((s) => s.length > 0)
        .join(" · ");
      x.renderer.plain(`  ${favouriteMark(contact)} ${contact.alias.padEnd(width)}  ${flags}`);
    }
  }
  const groups = await loadGroups(x);
  if (groups.length > 0) {
    x.renderer.plain("");
    x.renderer.plain("  groups:");
    const gwidth = Math.max(...groups.map((g) => g.name.length));
    for (const group of groups) {
      const unread = x.unread.get(group.gid) ?? 0;
      const flags = [
        `${group.members.length} members`,
        group.active ? "" : "left",
        unread > 0 ? `${unread} unread` : "",
      ]
        .filter((s) => s.length > 0)
        .join(" · ");
      x.renderer.plain(`    ${group.name.padEnd(gwidth)}  ${flags}`);
    }
  }
  const pending = await x.store.listKeys("pending/");
  if (pending.length > 0) {
    x.renderer.plain("");
    x.renderer.plain("  contact requests:");
    for (const key of pending) {
      const uid = key.slice("pending/".length);
      x.renderer.plain(`    ${formatUid(uid)}   /add ${uid} [alias] to accept`);
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
 * contact, or group, is gone (removed, left, purged, or wiped). */
export async function returnToPreviousView(x: ExecutorInternals): Promise<void> {
  if (x.previousView === null) {
    x.renderer.event("info", "There is no previous screen to return to.");
    return;
  }
  const current = currentViewRef(x);
  const target = x.previousView;
  x.previousView = current; // swap so a second /return comes back here
  if (target.kind === "home") {
    x.active = null;
    x.activeGroup = null;
    x.shell.setPrompt("> ");
    refreshChatContext(x);
    x.renderer.event("info", "Returned to home.");
    x.enqueueRender(() => renderHome(x));
    return;
  }
  if (target.kind === "group") {
    const group = await loadGroup(x, target.gid);
    if (group === null) {
      x.active = null;
      x.activeGroup = null;
      x.previousView = null;
      x.shell.setPrompt("> ");
      refreshChatContext(x);
      x.renderer.event("warning", "That group is no longer available, so you are back at home.");
      x.enqueueRender(() => renderHome(x));
      return;
    }
    x.active = null;
    x.activeGroup = group;
    x.unread.delete(group.gid);
    x.shell.setPrompt(`[${group.name}] > `);
    x.chrome.setChatContext(`[group: ${group.name} (${group.members.length} members)]`);
    x.renderer.event("info", `Returned to '${group.name}'.`);
    x.enqueueRender(() => renderGroupConversation(x, group));
    return;
  }
  const contact = findContactByUid(x, target.uid);
  if (contact === null) {
    x.active = null;
    x.activeGroup = null;
    x.previousView = null;
    x.shell.setPrompt("> ");
    refreshChatContext(x);
    x.renderer.event("warning", "That conversation is no longer available, so you are back at home.");
    x.enqueueRender(() => renderHome(x));
    return;
  }
  x.active = contact;
  x.activeGroup = null;
  x.unread.delete(contact.uid);
  x.shell.setPrompt(`[${contact.alias}] > `);
  refreshChatContext(x);
  x.renderer.event("info", `Returned to the conversation with ${contact.alias}.`);
  x.enqueueRender(() => renderActiveConversation(x));
}
