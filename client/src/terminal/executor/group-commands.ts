// The /group command surface: create, list, inspect, add, remove, leave, open,
// and sending into a focused group.
//
// Split from groups.ts (which holds the record shape and the validation) so the
// data layer stays importable from messaging.ts without a cycle: messaging
// imports groups, and this module imports both.
//
// Every membership change here is announced to the whole roster in-band. That
// is deliberate and is the only thing standing between this design and a silent
// add: there is no cryptographic agreement on who is in a group, so the roster
// changing without anyone being told is precisely the attack. See the header of
// groups.ts for the full statement of what fan-out does and does not give you.

import { formatUid, normalizeUid } from "../parser";
import { doAdd } from "./contacts";
import { currentViewRef, findContactByUid, resolveContact } from "./context";
import type { ExecutorInternals } from "./context";
import {
  GROUP_MSG_PREFIX,
  findGroupByName,
  loadGroup,
  loadGroups,
  newGroupId,
  rosterDigest,
  saveGroup,
} from "./groups";
import type { Group } from "./groups";
import { fanOutToGroup, recordGroupMessage } from "./messaging";
import { MAX_GROUP_MEMBERS, isGroupName } from "./payload";
import type { StoredGroupMessage } from "./records";
import { renderGroupConversation, renderHome } from "./views";

/** Resolve a group by name, reporting the failure. */
async function requireGroup(x: ExecutorInternals, name: string): Promise<Group | null> {
  const group = await findGroupByName(x, name);
  if (group === null) {
    x.renderer.error("E514", name);
    return null;
  }
  return group;
}

/** Report how a fan-out actually went. A partial delivery is reported as a
 * partial delivery: the sender is the only one who can chase the rest. */
function reportFanOut(
  x: ExecutorInternals,
  group: Group,
  result: { delivered: number; failed: string[] },
  what: string,
): void {
  if (result.failed.length === 0) {
    x.renderer.status("success", `${what} sent to ${result.delivered} member(s) of '${group.name}'`);
    return;
  }
  x.renderer.event(
    "warning",
    `${what} reached ${result.delivered} of ${result.delivered + result.failed.length} members of '${group.name}'. Not delivered to: ${result.failed.join(", ")}.`,
  );
}

/** `/group new <name> <alias|uid>...`: create a group and invite everyone. */
export async function doGroupNew(
  x: ExecutorInternals,
  name: string,
  targets: readonly string[],
): Promise<void> {
  if (!x.store.isUnlocked() || x.identity === null) {
    x.renderer.error("E403");
    return;
  }
  if (!isGroupName(name)) {
    x.renderer.error("E515", name);
    return;
  }
  if ((await findGroupByName(x, name)) !== null) {
    x.renderer.error("E516", name);
    return;
  }
  const members = new Set<string>([x.identity.uid]);
  for (const target of targets) {
    const contact = resolveContact(x, target);
    if (contact === null) {
      x.renderer.error("E501", target);
      return;
    }
    members.add(contact.uid);
  }
  if (members.size < 2) {
    x.renderer.error("E517");
    return;
  }
  if (members.size > MAX_GROUP_MEMBERS) {
    x.renderer.error("E518", MAX_GROUP_MEMBERS);
    return;
  }

  const group: Group = {
    gid: newGroupId(),
    name,
    members: [...members].sort(),
    createdAt: x.now(),
    active: true,
  };
  await saveGroup(x, group);
  x.renderer.event(
    "success",
    `Created '${group.name}' with ${group.members.length} members. Every message is encrypted separately to each of them, so there is no group key and the server sees only ordinary one-to-one traffic.`,
  );
  x.renderer.event(
    "info",
    `Membership is not cryptographically agreed. Compare the fingerprint ${rosterDigest(group.members)} with the others out-of-band if it matters.`,
  );
  const result = await fanOutToGroup(x, group, null, "invite", null);
  reportFanOut(x, group, result, "Invitation");
}

/** `/group list`: every group on this device. */
export async function doGroupList(x: ExecutorInternals): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const groups = await loadGroups(x);
  if (groups.length === 0) {
    x.renderer.event("info", "No groups yet. Run /group new <name> <contact>... to make one.");
    return;
  }
  x.renderer.event("info", `groups (${groups.length}):`);
  const width = Math.max(...groups.map((g) => g.name.length));
  for (const group of groups) {
    const unread = x.unread.get(group.gid) ?? 0;
    const flags = [
      `${group.members.length} members`,
      group.active ? "" : "left",
      unread > 0 ? `${unread} unread` : "",
    ]
      .filter((s) => s.length > 0)
      .join(" · ");
    x.renderer.plain(`  ${group.name.padEnd(width)}  ${flags}`);
  }
}

/** `/group info <name>`: the roster, in full, with its fingerprint.
 *
 * This is the out-of-band comparison surface. The fingerprint is a convenience
 * for reading a roster aloud, not a security control: it hashes a list this
 * device holds, so two people matching it have confirmed they agree, nothing
 * more. That is said on screen rather than left to be assumed. */
export async function doGroupInfo(x: ExecutorInternals, name: string): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  x.renderer.event("info", `'${group.name}': ${group.members.length} members`);
  for (const uid of group.members) {
    const you = uid === x.identity?.uid ? "  (you)" : "";
    const contact = findContactByUid(x, uid);
    const who =
      contact === null ? "not in your contacts" : contact.verified ? "verified" : "UNVERIFIED";
    x.renderer.plain(`  ${formatUid(uid)}  ${contact?.alias ?? ""}  ${who}${you}`);
  }
  x.renderer.plain("");
  x.renderer.plain(`  member-list fingerprint: ${rosterDigest(group.members)}`);
  x.renderer.event(
    "info",
    "Read that fingerprint out to the others. Matching means you agree on the member list; it cannot prove the list is right, because nothing here signs it.",
  );
}

/** `/group add <name> <alias|uid>`: add a member and tell everyone. */
export async function doGroupAdd(
  x: ExecutorInternals,
  name: string,
  target: string,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  const contact = resolveContact(x, target);
  if (contact === null) {
    x.renderer.error("E501", target);
    return;
  }
  if (group.members.includes(contact.uid)) {
    x.renderer.event("info", `${contact.alias} is already in '${group.name}'.`);
    return;
  }
  if (group.members.length >= MAX_GROUP_MEMBERS) {
    x.renderer.error("E518", MAX_GROUP_MEMBERS);
    return;
  }
  const updated: Group = {
    ...group,
    members: [...group.members, contact.uid].sort(),
  };
  await saveGroup(x, updated);
  x.renderer.event(
    "security",
    `Added ${contact.alias} to '${group.name}'. Everyone in the group is being told, and they can see it was you. ${contact.alias} cannot read anything sent before now.`,
  );
  // Both fan-outs advertise the FULL new roster; only the recipient list
  // differs. The new member gets an invite (which is what creates the group on
  // their device), everyone else gets the add notice.
  const invite = await fanOutToGroup(x, updated, null, "invite", null, [contact.uid]);
  const notice = await fanOutToGroup(
    x,
    updated,
    null,
    "add",
    contact.uid,
    updated.members.filter((uid) => uid !== contact.uid),
  );
  reportFanOut(x, updated, {
    delivered: invite.delivered + notice.delivered,
    failed: [...invite.failed, ...notice.failed],
  }, "The membership change");
}

/** `/group remove <name> <alias|uid>`: remove a member and tell everyone. */
export async function doGroupRemove(
  x: ExecutorInternals,
  name: string,
  target: string,
): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  const uid = normalizeUid(target) ?? resolveContact(x, target)?.uid ?? null;
  if (uid === null || !group.members.includes(uid)) {
    x.renderer.error("E519", target, group.name);
    return;
  }
  const label = findContactByUid(x, uid)?.alias ?? formatUid(uid);
  const updated: Group = { ...group, members: group.members.filter((m) => m !== uid) };
  await saveGroup(x, updated);
  x.renderer.event(
    "security",
    `Removed ${label} from '${group.name}'. They keep every message they already received, and there is no group key to rotate, so removal stops future messages and nothing else.`,
  );
  // The notice advertises the roster WITHOUT the removed member, which is what
  // every recipient will end up holding, but it is sent to the old roster so
  // the person removed learns it from the group rather than from silence.
  const result = await fanOutToGroup(x, updated, null, "remove", uid, group.members);
  reportFanOut(x, updated, result, "The removal notice");
}

/** `/group leave <name>`: leave, telling the others. */
export async function doGroupLeave(x: ExecutorInternals, name: string): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  const self = x.identity?.uid ?? "";
  const updated: Group = {
    ...group,
    members: group.members.filter((uid) => uid !== self),
    active: false,
  };
  // Advertise the roster as it stands AFTER the departure, the same as a
  // removal does. Every notice carrying the after-state is what lets a
  // recipient apply the announced change and get a roster that matches, so a
  // routine departure raises no divergence warning. Sending the pre-leave
  // roster meant every remaining member was told the person who just left was
  // an extra member the sender could see and they could not.
  const result = await fanOutToGroup(x, updated, null, "leave", null, group.members);
  await saveGroup(x, updated);
  x.unread.delete(group.gid);
  if (x.activeGroup?.gid === group.gid) {
    x.activeGroup = null;
    x.shell.setPrompt("> ");
    x.chrome.setChatContext(null);
    x.enqueueRender(() => renderHome(x));
  }
  x.renderer.event(
    "success",
    `Left '${group.name}'. Its history stays on this device until you /group purge it.`,
  );
  reportFanOut(x, group, result, "The leave notice");
}

/** `/group open <name>`: focus a group conversation. */
export async function doGroupOpen(x: ExecutorInternals, name: string): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  const previousBeforeOpen = currentViewRef(x);
  if (previousBeforeOpen.kind !== "group" || previousBeforeOpen.gid !== group.gid) {
    x.previousView = previousBeforeOpen; // remember for /return
  }
  x.active = null;
  x.activeGroup = group;
  x.unread.delete(group.gid);
  x.shell.setPrompt(`[${group.name}] > `);
  x.chrome.setChatContext(`[group: ${group.name} (${group.members.length} members)]`);
  if (!group.active) {
    x.renderer.event("warning", `You have left '${group.name}'. This is history only.`);
  }
  x.enqueueRender(() => renderGroupConversation(x, group));
}

/** `/group sync <name>`: add the group's members you have no contact entry for.
 *
 * This is the answer to a gap that is inherent to fan-out: you can only encrypt
 * to someone you have a session with, and a session needs a pinned key, so a
 * member you have never added is unreachable. Without this, a five-person group
 * would need every member to add every other member by hand before anyone could
 * talk to more than the person who invited them.
 *
 * It is a command rather than an automatic step, and that is the security
 * decision. Adding a contact means accepting a UID's key on trust, and doing it
 * silently would mean anyone who can invite you to a group can also write into
 * your contact list. Here the roster is printed, the user runs the command, and
 * the additions are theirs. Keys are still pinned through the ordinary path, so
 * /verify and safety numbers apply to a synced contact exactly as to any
 * other. */
export async function doGroupSync(x: ExecutorInternals, name: string): Promise<void> {
  if (!x.store.isUnlocked() || x.identity === null) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  const self = x.identity.uid;
  const missing = group.members.filter(
    (uid) => uid !== self && findContactByUid(x, uid) === null,
  );
  if (missing.length === 0) {
    x.renderer.event("info", `Every member of '${group.name}' is already in your contacts.`);
    return;
  }
  x.renderer.event(
    "security",
    `'${group.name}' has ${missing.length} member(s) you have never added. Adding them saves their UID as a contact so you can send to them; their identity keys are pinned on first contact and are UNVERIFIED until you /verify each one.`,
  );
  for (const uid of missing) {
    x.renderer.plain(`  ${formatUid(uid)}`);
  }
  const answer = await x.shell.readLine(`add ${missing.length} contact(s)? (yes/NO): `);
  if (answer === null || answer.trim().toLowerCase() !== "yes") {
    x.renderer.event("info", "Nothing was added.");
    return;
  }
  for (const uid of missing) {
    await doAdd(x, uid, undefined);
  }
  x.renderer.event(
    "success",
    `Added ${missing.length} member(s) of '${group.name}'. Run /verify on each before treating them as confirmed.`,
  );
}

/** `/group purge <name>`: delete a group's stored history, and the group with
 * it. Local and irreversible, exactly like /remove ... purge for a contact. */
export async function doGroupPurge(x: ExecutorInternals, name: string): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E403");
    return;
  }
  const group = await requireGroup(x, name);
  if (group === null) {
    return;
  }
  const keys = await x.store.listKeys(`${GROUP_MSG_PREFIX}${group.gid}/`);
  for (const key of keys) {
    await x.store.deleteKey(key);
  }
  await x.store.deleteKey(`group/${group.gid}`);
  x.unread.delete(group.gid);
  if (x.activeGroup?.gid === group.gid) {
    x.activeGroup = null;
    x.shell.setPrompt("> ");
    x.chrome.setChatContext(null);
    x.enqueueRender(() => renderHome(x));
  }
  x.renderer.event(
    "success",
    `Deleted '${group.name}' and its ${keys.length} stored message(s) from this device. The others still have their copies.`,
  );
}

/** Send typed text into the focused group. */
export async function sendGroupText(
  x: ExecutorInternals,
  group: Group,
  text: string,
): Promise<void> {
  // Checked on a freshly reloaded copy, not the possibly-stale cached one:
  // an incoming /group leave or removal notice can flip `active` to false
  // between focusing the group and typing into it, and checking the cache
  // would still report a message as sent when every recipient discards it.
  const fresh = (await loadGroup(x, group.gid)) ?? group;
  if (!fresh.active) {
    x.renderer.event("warning", `You have left '${fresh.name}', so nothing is sent.`);
    x.chrome.rejectSent();
    return;
  }
  const result = await fanOutToGroup(x, fresh, text, "msg", null);
  if (result.delivered > 0) {
    await recordGroupMessage(x, fresh.gid, "out", "you", text, x.now());
    x.chrome.confirmSent();
  } else {
    x.chrome.rejectSent();
  }
  reportFanOut(x, fresh, result, "Message");
}

/** Rebuild the transcript for a group, oldest first. */
export async function loadGroupHistory(
  x: ExecutorInternals,
  gid: string,
): Promise<StoredGroupMessage[]> {
  const records: StoredGroupMessage[] = [];
  for (const key of await x.store.listKeys(`${GROUP_MSG_PREFIX}${gid}/`)) {
    const record = await x.store.getJson<StoredGroupMessage>(key);
    if (record !== null) {
      records.push(record);
    }
  }
  return records.sort((a, b) => a.ts - b.ts);
}
