// Message lifecycle (-5.3a): the mutual disappearing timer, the
// local retention cap, immediate local purge, and cooperative two-sided
// deletion of your own messages. Deletion is cooperative, not forensic: it
// relies on the peer's client honoring the request, and browser deletion is
// not forensic erasure.

import { findContactByUid, isActiveConversation, refreshChatContext, resolveContact } from "./context";
import type { ExecutorInternals } from "./context";
import { durationToSeconds, formatDuration } from "./format";
import type { DeleteScope, Duration } from "../parser";
import type { GlyphLevel } from "../renderer";
import type { PurgeSettings, StoredGroupMessage, StoredMessage, StoredSession } from "./records";
import { GROUP_MSG_PREFIX } from "./groups";
import { saveContacts } from "./context";
import { sendRatchetMessage } from "./messaging";
import { renderActiveConversation } from "./views";

/** Adopt a mutual-timer value the peer carried in its payload (last-writer-
 * wins) and announce the change inline, mirroring the sender's own line
 *. */
export async function applyIncomingTimer(
  x: ExecutorInternals,
  uid: string,
  label: string,
  timerSeconds: number | null,
): Promise<void> {
  const contact = findContactByUid(x, uid);
  if (contact === null || contact.timerSeconds === timerSeconds) {
    return;
  }
  x.contacts.set(contact.alias, { ...contact, timerSeconds });
  await saveContacts(x);
  refreshChatContext(x);
  x.renderer.event(
    "info",
    timerSeconds === null
      ? `${label} turned off disappearing messages.`
      : `${label} set disappearing messages to ${formatDuration(timerSeconds)}.`,
  );
}

/** Delete at-rest messages past their mutual-timer deadline or the local
 * retention cap, whichever bites first (-5.3). Best-effort, on
 * activity. */
export async function purgeExpired(x: ExecutorInternals): Promise<void> {
  if (!x.store.isUnlocked()) {
    return;
  }
  const cap = (await x.store.getJson<PurgeSettings>("settings/purge"))?.seconds ?? null;
  const now = x.now();
  const expired = (record: { ts: number; tmrExpiresAt?: number }): boolean => {
    const timerExpired = record.tmrExpiresAt !== undefined && now >= record.tmrExpiresAt;
    return timerExpired || (cap !== null && now >= record.ts + cap * 1000);
  };
  for (const msgKey of await x.store.listKeys("msg/")) {
    const record = await x.store.getJson<StoredMessage>(msgKey);
    if (record !== null && expired(record)) {
      await x.store.deleteKey(msgKey);
    }
  }
  // Group history lives in its own namespace and would otherwise escape the
  // retention cap entirely, which would make the cap quietly untrue rather
  // than merely incomplete. StoredGroupMessage carries no tmrExpiresAt (see
  // its doc comment in records.ts), so `expired` always falls through to the
  // cap check for these: a mutual timer needs every member to agree on one
  // deadline, which fan-out has no shared transcript to carry.
  for (const msgKey of await x.store.listKeys(GROUP_MSG_PREFIX)) {
    const record = await x.store.getJson<StoredGroupMessage>(msgKey);
    if (record !== null && expired(record)) {
      await x.store.deleteKey(msgKey);
    }
  }
}

async function deleteMessages(x: ExecutorInternals, prefix: string): Promise<number> {
  const keys = await x.store.listKeys(prefix);
  for (const key of keys) {
    await x.store.deleteKey(key);
  }
  return keys.length;
}

/** `/timer <alias> <duration|off>`: set the mutual disappearing timer,
 * announce it locally, and push it to the peer over the ratchet so both
 * sides agree. */
export async function doTimer(
  x: ExecutorInternals,
  alias: string,
  duration: Duration,
): Promise<void> {
  if (x.identity === null || x.token === null) {
    x.renderer.error("E201");
    return;
  }
  const contact = resolveContact(x, alias);
  if (contact === null) {
    x.renderer.error("E501", alias);
    return;
  }
  const seconds = durationToSeconds(duration);
  const updated = { ...contact, timerSeconds: seconds };
  x.contacts.set(contact.alias, updated);
  await saveContacts(x);
  refreshChatContext(x);
  x.renderer.event(
    "info",
    seconds === null
      ? `Disappearing messages turned off for ${contact.alias}. This applies to both sides.`
      : `Disappearing messages set to ${formatDuration(seconds)} for ${contact.alias}. It applies to both sides, and the countdown starts on read.`,
  );
  if (updated.keyChangeBlocked) {
    x.renderer.event(
      "warning",
      `Sending to ${contact.alias} is blocked by an unacknowledged key change. They will get this timer once you /ack and resume.`,
    );
    return;
  }
  const stored = await x.store.getJson<StoredSession>(`session/${contact.uid}`);
  if (stored === null) {
    x.renderer.event(
      "info",
      "the peer will receive this setting once your conversation is established",
    );
    return;
  }
  await sendRatchetMessage(x, updated, stored, null);
}

/** `/purge set <duration|off>`: local retention cap, never transmitted. */
export async function doPurgeSet(x: ExecutorInternals, duration: Duration): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.event("warning", "Locked or not registered. Please run /login or /register.");
    return;
  }
  const seconds = durationToSeconds(duration);
  await x.store.putJson("settings/purge", { seconds } satisfies PurgeSettings);
  await purgeExpired(x);
  x.renderer.event(
    "success",
    seconds === null
      ? "Local retention cap cleared. Stored messages are kept until the mutual timer or /purge now."
      : `Local retention cap set to ${formatDuration(seconds)}. It is local only, never sent, and applies to every conversation.`,
  );
}

/** `/purge now [alias]`: immediate local deletion of stored messages. */
export async function doPurgeNow(x: ExecutorInternals, alias: string | undefined): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.event("warning", "Locked or not registered. Please run /login or /register.");
    return;
  }
  if (alias === undefined) {
    // "across all conversations" has to include groups, or the report is a
    // lie: group history lives under its own gmsg/ prefix (see
    // recordGroupMessage) precisely so it never collides with msg/, which
    // also means a sweep of msg/ alone silently leaves it all behind.
    const count = (await deleteMessages(x, "msg/")) + (await deleteMessages(x, GROUP_MSG_PREFIX));
    x.renderer.event("success", `Purged ${count} stored message(s) across all conversations.`);
    return;
  }
  const contact = resolveContact(x, alias);
  if (contact === null) {
    x.renderer.error("E501", alias);
    return;
  }
  const count = await deleteMessages(x, `msg/${contact.uid}/`);
  x.renderer.event("success", `Purged ${count} stored message(s) with ${contact.alias}.`);
}

/** `/delete <last|N|all|purge> [/s]`: delete your own (outgoing) messages on
 * BOTH sides (a). `last`/`N`/`all` scope to the active one-to-one
 * conversation; `purge` spans every one-to-one conversation. Groups are out
 * of scope entirely: this is a two-sided directive naming a shared message
 * id, and a group message has no such id to name (/group purge is the group
 * equivalent). Each deleted message is removed from local history and, where
 * a live session exists, a delete directive naming its shared id is pushed
 * to the peer over the encrypted ratchet. `/s` makes it silent: no
 * confirmation here and no notice on the peer's end. Messages with no live
 * session (or a key-change block) are removed locally but cannot be
 * signalled; that is reported honestly. */
export async function doDelete(
  x: ExecutorInternals,
  scope: DeleteScope,
  silent: boolean,
): Promise<void> {
  const report = (level: GlyphLevel, text: string): void => {
    if (!silent) {
      x.renderer.event(level, text);
    }
  };
  if (!x.store.isUnlocked()) {
    report("warning", "Locked or not registered. Please run /login or /register.");
    return;
  }

  let victims: { key: string; uid: string; ts: number; mid: string | null }[];
  let scopeLabel: string;
  if (scope.kind === "purge") {
    victims = await collectOwnOutgoing(x, "msg/");
    // Not "across all conversations": group messages have no `mid` (see the
    // comment on StoredGroupMessage in records.ts), so there is nothing to
    // signal a peer with and this sweep never touches gmsg/. Claiming group
    // coverage here would be a lie the next /group open disproves.
    scopeLabel = "across every one-to-one conversation";
  } else {
    if (x.active === null) {
      if (x.activeGroup !== null) {
        report(
          "warning",
          `/delete is a two-sided directive between exactly two people, and a group has no such channel. To remove '${x.activeGroup.name}' from this device, run /group purge ${x.activeGroup.name}.`,
        );
        return;
      }
      report("warning", "No active conversation. Use /chat <alias|uid> first.");
      return;
    }
    const contact = findContactByUid(x, x.active.uid) ?? x.active;
    const inChat = (await collectOwnOutgoing(x, `msg/${contact.uid}/`)).sort(
      (a, b) => a.ts - b.ts,
    );
    const limit = scope.kind === "all" ? inChat.length : scope.kind === "last" ? 1 : scope.count;
    victims = inChat.slice(Math.max(0, inChat.length - limit));
    scopeLabel = `with ${contact.alias}`;
  }

  if (victims.length === 0) {
    report("info", `There are no messages of yours to delete ${scopeLabel}.`);
    return;
  }

  // Remove the local copies first, then ask each peer to remove theirs.
  for (const victim of victims) {
    await x.store.deleteKey(victim.key);
  }
  const midsByUid = new Map<string, string[]>();
  for (const victim of victims) {
    if (victim.mid !== null) {
      const list = midsByUid.get(victim.uid) ?? [];
      list.push(victim.mid);
      midsByUid.set(victim.uid, list);
    }
  }
  let signalled = 0;
  let unreachable = victims.length;
  for (const [uid, mids] of midsByUid) {
    if (await requestPeerDeletion(x, uid, mids, silent)) {
      signalled += mids.length;
    }
  }
  unreachable -= signalled;

  // Rebuild the on-screen conversation so the deleted lines vanish from view,
  // not just from storage. This runs even for a silent delete: /s suppresses
  // the notices, never the screen's agreement with the store. The append-only
  // transcript can only drop a line by clearing and reprinting.
  if (x.active !== null) {
    await renderActiveConversation(x);
  }

  const tail =
    unreachable === 0
      ? "Deletion is cooperative, not forensic erasure."
      : `${unreachable} could not be signalled to the peer, because there is no live session, so those were removed locally only. Deletion is cooperative, not forensic erasure.`;
  report("success", `Deleted ${victims.length} of your message(s) ${scopeLabel}. ${tail}`);
}

/** Gather your outgoing (`dir: "out"`) messages under `prefix`, tagged with
 * the conversation uid (parsed from the `msg/<uid>/<ts>` key) and shared id.
 * Only your own messages are eligible: a peer's incoming lines are never
 * touched. */
async function collectOwnOutgoing(
  x: ExecutorInternals,
  prefix: string,
): Promise<{ key: string; uid: string; ts: number; mid: string | null }[]> {
  const out: { key: string; uid: string; ts: number; mid: string | null }[] = [];
  for (const key of await x.store.listKeys(prefix)) {
    const record = await x.store.getJson<StoredMessage>(key);
    if (record === null || record.dir !== "out") {
      continue;
    }
    const uid = key.split("/")[1] ?? "";
    out.push({ key, uid, ts: record.ts, mid: record.mid ?? null });
  }
  return out;
}

/** Push a cooperative delete directive to `uid` over the ratchet: the peer
 * removes the named messages they received from us. Returns false (caller
 * treats the ids as unreachable) when there is no live session or the
 * conversation is key-change-blocked. */
async function requestPeerDeletion(
  x: ExecutorInternals,
  uid: string,
  mids: readonly string[],
  silent: boolean,
): Promise<boolean> {
  const contact = findContactByUid(x, uid);
  if (contact === null || contact.keyChangeBlocked) {
    return false;
  }
  const stored = await x.store.getJson<StoredSession>(`session/${uid}`);
  if (stored === null) {
    return false;
  }
  return sendRatchetMessage(x, contact, stored, null, { deletes: mids, deleteSilent: silent });
}

/** A peer asked us to delete messages they had sent us (a). Remove
 * the matching incoming records by shared id and, unless the request was
 * silent, announce it inline so the deletion is visible rather than a silent
 * gap. */
export async function applyIncomingDeletion(
  x: ExecutorInternals,
  uid: string,
  label: string,
  mids: readonly string[],
  silent: boolean,
): Promise<void> {
  const wanted = new Set(mids);
  let removed = 0;
  for (const key of await x.store.listKeys(`msg/${uid}/`)) {
    const record = await x.store.getJson<StoredMessage>(key);
    if (record !== null && record.dir === "in" && record.mid !== undefined && wanted.has(record.mid)) {
      await x.store.deleteKey(key);
      removed += 1;
    }
  }
  // Redraw so the removed lines disappear from view. This runs even for a
  // SILENT request: /s suppresses the inline notice below, never the screen's
  // agreement with storage.
  if (removed > 0 && isActiveConversation(x, uid)) {
    await renderActiveConversation(x);
  }
  if (!silent && removed > 0) {
    x.renderer.event(
      "info",
      `${label} deleted ${removed} message(s) they had sent, so those are gone from your history too.`,
    );
  }
}
