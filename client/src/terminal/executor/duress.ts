// The duress passphrase: a second passphrase that, typed at the /login prompt,
// destroys this device's store and deletes the account from the server instead
// of unlocking anything. Opt-in, off until /duress set arms it.
//
// Three properties define the feature, and each one is a deliberate cost:
//
//   1. It is silent. No confirmation, no warning, no progress. The screen shows
//      the same "[E203] Unlock failed." a typo produces, because anything else
//      would tell whoever is standing over the user what just happened. The
//      warning shown by /duress set is the only place this is ever announced.
//   2. The armed state is invisible at rest. The sealed envelope lives in the
//      store's meta record and is written with random contents from the moment
//      the store is created, so an imaged database looks identical whether the
//      feature is armed or not (crypto/store.ts::decoyDuress). The human-
//      readable flag /duress status reads lives ENCRYPTED, so only the real
//      passphrase reveals it.
//   3. It seals a copy of the identity key. Deleting the account requires
//      authenticating to the server as its owner, and that key is the only
//      credential there is - so the duress passphrase gets the same strength
//      rules as the real one, and is refused if it IS the real one.
//
// What it does not do: clear the transcript already on screen. A screen that
// wipes itself is exactly the tell this feature exists to avoid, and anyone
// watching has already read what is on it. Durable data is what gets destroyed.

import * as api from "../../net/api";
import { fromBase64, toBase64 } from "../../util/base64";
import { secretStringsEqual } from "../../util/secret";
import { refreshChatContext } from "./context";
import type { ExecutorInternals } from "./context";
import { authenticate, passphraseProblem, MIN_PASSPHRASE_LENGTH } from "./identity";

/** Whether the duress passphrase is armed, kept in the ENCRYPTED store so only
 * the real passphrase can answer the question. The sealed envelope itself is
 * the mechanism; this is just what /duress status reports. */
interface DuressSettings {
  readonly armed: boolean;
}

const DURESS_SETTINGS_KEY = "settings/duress";

/** The minimum needed to delete the account: its UID and the identity secret
 * that signs the login challenge. Sealed under the duress passphrase, so it is
 * deliberately not the DEK - guessing this envelope buys the ability to destroy
 * the account, not to read its message history. */
interface DuressCredential {
  readonly uid: string;
  readonly sec: Uint8Array;
}

function encodeCredential(uid: string, sec: Uint8Array): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ uid, sec: toBase64(sec) }));
}

/** Total: a payload that authenticated but does not parse yields null, and the
 * purge still destroys everything local. */
function decodeCredential(payload: Uint8Array): DuressCredential | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(payload)) as {
      uid?: unknown;
      sec?: unknown;
    };
    if (typeof parsed.uid !== "string" || typeof parsed.sec !== "string") {
      return null;
    }
    return { uid: parsed.uid, sec: fromBase64(parsed.sec) };
  } catch {
    return null;
  }
}

/** `/duress set`: arm the passphrase. Needs an unlocked store and a live
 * identity, since the credential it seals comes from both. */
export async function doDuressSet(x: ExecutorInternals): Promise<void> {
  if (!x.store.isUnlocked() || x.identity === null) {
    x.renderer.error("E406");
    return;
  }
  x.renderer.event(
    "security",
    "a duress passphrase gives NO warning and NO confirmation. Typing it at the /login prompt immediately destroys this device's store and deletes your account from the server, and the screen shows only 'unlock failed', exactly as a typo would. There is no undo and no recovery code that brings it back. It also seals a copy of your identity key, so choose one as strong as your real passphrase, and one you could never type by accident.",
  );
  const answer = await x.shell.readLine("arm a duress passphrase? (yes/NO): ");
  if (answer === null || answer.trim().toLowerCase() !== "yes") {
    x.renderer.event("info", "Duress passphrase not armed. Nothing was changed.");
    return;
  }
  const first = await x.shell.readSecret(
    `choose a DURESS passphrase (${MIN_PASSPHRASE_LENGTH}+ characters, with a number and a symbol): `,
  );
  if (first === null) {
    x.renderer.event("info", "Duress passphrase not armed. Nothing was changed.");
    return;
  }
  const problem = passphraseProblem(first);
  if (problem === "short") {
    x.renderer.error("E206", MIN_PASSPHRASE_LENGTH);
    return;
  }
  if (problem === "composition") {
    x.renderer.error("E209");
    return;
  }
  const second = await x.shell.readSecret("confirm duress passphrase: ");
  if (second === null) {
    x.renderer.event("info", "Duress passphrase not armed. Nothing was changed.");
    return;
  }
  if (!secretStringsEqual(first, second)) {
    x.renderer.error("E207");
    return;
  }
  // The unlock passphrase must never double as the duress one: every login
  // would then be an unannounced wipe. Checked against the store itself rather
  // than asking the user to retype it.
  if (await x.store.isPrimaryPassphrase(first)) {
    x.renderer.error("E211");
    return;
  }
  // armDuress zeroizes its own padded copy and the KEK once it has sealed
  // them, but the buffer handed to it here is ours: it holds the base64 of
  // the raw ML-DSA-65 secret key in plaintext, armDuress does not own it, and
  // nothing else zeroizes it for us.
  const credential = encodeCredential(x.identity.uid, x.identity.sec);
  await x.store.armDuress(first, credential);
  credential.fill(0);
  await x.store.putJson(DURESS_SETTINGS_KEY, { armed: true } satisfies DuressSettings);
  x.renderer.event(
    "success",
    "Duress passphrase armed. Typing it at the /login prompt destroys this device and the account, silently and with no confirmation. /duress off disarms it.",
  );
}

/** `/duress off`: overwrite the envelope with a fresh decoy. Always safe to
 * run, whether or not anything was armed. */
export async function doDuressOff(x: ExecutorInternals): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E406");
    return;
  }
  await x.store.disarmDuress();
  await x.store.putJson(DURESS_SETTINGS_KEY, { armed: false } satisfies DuressSettings);
  x.renderer.event(
    "success",
    "Duress passphrase disarmed. The /login prompt now only ever unlocks or fails.",
  );
}

/** `/duress status`: report the armed flag from the encrypted store. Reading it
 * needs the real passphrase, which is the point: the raw database says nothing. */
export async function doDuressStatus(x: ExecutorInternals): Promise<void> {
  if (!x.store.isUnlocked()) {
    x.renderer.error("E406");
    return;
  }
  const settings = await x.store.getJson<DuressSettings>(DURESS_SETTINGS_KEY);
  if (settings?.armed === true) {
    x.renderer.event(
      "security",
      "Duress passphrase ARMED. Typing it at /login destroys this device and the account with no confirmation. /duress off disarms it, /duress set replaces it.",
    );
    return;
  }
  x.renderer.event(
    "info",
    "Duress passphrase not armed. Run /duress set to arm one, after reading its warning.",
  );
}

/** Called with a passphrase that did NOT unlock the store, from /login's
 * failure path. Purges when it is the duress passphrase, returns quietly when
 * it is an ordinary typo. Either way the caller reports the same E203.
 *
 * Wired in as a hook rather than called from identity.ts so the executor's
 * module graph stays acyclic: index.ts composes the two. */
export async function maybeTriggerDuress(x: ExecutorInternals, passphrase: string): Promise<void> {
  let payload: Uint8Array | null;
  try {
    payload = await x.store.tryDuress(passphrase);
  } catch {
    return; // no store, or a meta record too old/damaged to hold an envelope
  }
  if (payload === null) {
    return;
  }
  const credential = decodeCredential(payload);
  payload.fill(0);
  await purgeUnderDuress(x, credential);
}

/** Destroy everything, local first.
 *
 * The order matters. Local destruction runs first, unconditionally, and never
 * waits on the network: it is the irreversible part, the part holding the
 * message history, and the part that must still happen when the machine is
 * offline or the server is unreachable. The account deletion follows from key
 * material held in memory, and every failure it can produce is swallowed -
 * there is no one to report it to who should be told. */
async function purgeUnderDuress(
  x: ExecutorInternals,
  credential: DuressCredential | null,
): Promise<void> {
  x.token = null;
  x.lockLocal();
  try {
    await x.store.wipe();
  } catch {
    // A failed wipe must not skip the rest of the teardown, and reporting it
    // would defeat the silence. Locking already zeroized what was in memory.
  }
  x.contacts.clear();
  x.unread.clear();
  x.active = null;
  x.previousView = null;
  x.wipeRequestedAt = 0;
  refreshChatContext(x);
  x.shell.setPrompt("> ");

  if (credential === null) {
    return;
  }
  try {
    await api.deleteAccount(await authenticate(credential.uid, credential.sec));
  } catch {
    // Offline, rate-limited, or already deleted. The local store is gone
    // regardless, and the account keeps whatever the server still holds.
  } finally {
    credential.sec.fill(0);
  }
}
