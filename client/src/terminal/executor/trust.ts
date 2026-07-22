// Trust: safety numbers, manual verification, and the identity-key-change
// teardown (spec 4.5, 4.6). handleKeyChange is the single path for every
// key-change detection site (send, receive, /verify), so the teardown
// semantics cannot drift between them.

import { toBase64 } from "../../util/base64";
import * as api from "../../net/api";
import { ApiError } from "../../net/api";
import { computeSafetyNumber, formatSafetyNumber } from "../../crypto/safetynumber";
import { verifyBundle } from "../../crypto/kx";
import {
  pinKey,
  refreshChatContext,
  refreshEmblemState,
  resolveContact,
  saveContacts,
} from "./context";
import type { ExecutorInternals } from "./context";
import { wireToBundle } from "./records";
import type { Contact } from "./records";

export async function doVerify(x: ExecutorInternals, alias: string): Promise<void> {
  if (x.identity === null || x.token === null) {
    x.renderer.event("failure", "not logged in - /login first");
    return;
  }
  const contact = resolveContact(x, alias);
  if (contact === null) {
    x.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
    return;
  }

  // Always fetch fresh (non-consuming) so /verify itself can catch a key
  // change that has not shown up in a message yet.
  let wire: api.WireBundle;
  try {
    wire = await api.fetchBundle(x.token, contact.uid, false);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      x.renderer.event("failure", "recipient keys unavailable - unknown UID");
      return;
    }
    throw err;
  }
  const bundle = wireToBundle(wire);
  if (!verifyBundle(bundle)) {
    x.renderer.event(
      "security",
      `prekey bundle signature verification FAILED for ${contact.alias} - the server may be tampering.`,
    );
    return;
  }
  const bundleIk = toBase64(bundle.ikPub);
  if (contact.ik !== null && contact.ik !== bundleIk) {
    // Auto-trust re-pins and lets /verify continue to the new safety number;
    // manual trust blocks here until /ack.
    if (!(await handleKeyChange(x, contact, bundleIk))) {
      return;
    }
  } else if (contact.ik === null) {
    x.contacts.set(contact.alias, pinKey(x, contact, bundleIk));
    await saveContacts(x);
  }

  const sn = computeSafetyNumber(x.identity.pub, x.identity.uid, bundle.ikPub, contact.uid);
  x.renderer.event("info", `safety number with ${contact.alias} (compare out-of-band):`);
  for (const row of formatSafetyNumber(sn)) {
    x.renderer.plain(`  ${row}`);
  }
  x.renderer.event(
    "info",
    `if it matches, run /verified ${contact.alias} to mark this contact trusted`,
  );
}

export async function doVerified(x: ExecutorInternals, alias: string): Promise<void> {
  const contact = resolveContact(x, alias);
  if (contact === null) {
    x.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
    return;
  }
  if (contact.ik === null) {
    x.renderer.event("failure", `no known identity key for ${contact.alias} yet - /verify first`);
    return;
  }
  if (contact.keyChangeBlocked) {
    x.renderer.event(
      "failure",
      `${contact.alias} has an unacknowledged key change - /ack ${contact.alias} first, then /verify again`,
    );
    return;
  }
  x.contacts.set(contact.alias, { ...contact, verified: true });
  await saveContacts(x);
  refreshChatContext(x);
  x.renderer.event(
    "success",
    `${contact.alias} marked verified - safety number confirmed out-of-band`,
  );
}

export async function doAck(x: ExecutorInternals, alias: string): Promise<void> {
  const contact = resolveContact(x, alias);
  if (contact === null) {
    x.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
    return;
  }
  if (!contact.keyChangeBlocked) {
    x.renderer.event("info", `nothing to acknowledge for ${contact.alias}`);
    return;
  }
  x.contacts.set(contact.alias, { ...contact, keyChangeBlocked: false });
  await saveContacts(x);
  refreshChatContext(x);
  await refreshEmblemState(x);
  x.renderer.event(
    "success",
    `acknowledged - ${contact.alias} remains UNVERIFIED; /verify then /verified to confirm the new key before sending`,
  );
}

/** Identity-key change detected for `contact` (spec 4.6): adopt the new key
 * so the safety number and future traffic reflect reality, and tear down any
 * established session so old chain keys cannot carry over. Manual trust marks
 * the contact UNVERIFIED and BLOCKED (returns false: the caller must abort
 * until /ack). Trust-on-first-use auto-re-pins, drops to UNVERIFIED but does
 * NOT block (returns true: the caller may proceed), and warns loudly so a
 * possible MITM is still visible. Either way a high-visibility event fires. */
export async function handleKeyChange(
  x: ExecutorInternals,
  contact: Contact,
  newIkB64: string,
): Promise<boolean> {
  const blocked = !x.autoTrust;
  const updated: Contact = {
    ...contact,
    ik: newIkB64,
    verified: false,
    keyChangeBlocked: blocked,
  };
  x.contacts.set(contact.alias, updated);
  await saveContacts(x);
  await x.store.deleteKey(`session/${contact.uid}`);
  refreshChatContext(x);
  await refreshEmblemState(x);
  x.renderer.event(
    "security",
    blocked
      ? `IDENTITY KEY CHANGED for ${contact.alias} - this conversation is now blocked and marked UNVERIFIED. /ack ${contact.alias} to acknowledge, then /verify + /verified to confirm the new key before sending.`
      : `IDENTITY KEY CHANGED for ${contact.alias} - the new key was auto-accepted (trust-on-first-use) and the session reset; ${contact.alias} is now UNVERIFIED. If you did not expect this, treat it as a possible server MITM: /verify ${contact.alias} to compare the new safety number, or /settings trust manual to block on future changes.`,
  );
  return !blocked;
}
