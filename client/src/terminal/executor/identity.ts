// Identity and session flows: registration, recovery, the ML-DSA
// login challenge-response, logout/lock, passphrase rotation, prekey
// maintenance, and /wipe. Everything here follows the same rule: server
// state first, then local persistence, so a failed network call never
// leaves the device claiming an identity the server does not honor.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import * as api from "../../net/api";
import { ApiError } from "../../net/api";
import { buildLoginMessage } from "../../crypto/login";
import { generateOpkBatch, generateSpk } from "../../crypto/prekeys";
import {
  OPK_BATCH_MAX,
  OPK_LOW_WATERMARK,
  SPK_RETENTION_DAYS,
  SPK_ROTATION_DAYS,
} from "../../crypto/constants";
import { fromBase64, toBase64 } from "../../util/base64";
import { secretStringsEqual } from "../../util/secret";
import { formatUid, normalizeRecoveryCode, normalizeUid } from "../parser";
import {
  loadContacts,
  loadTrustMode,
  refreshChatContext,
  refreshEmblemState,
} from "./context";
import type { ExecutorInternals } from "./context";
import { drainInbox } from "./messaging";
import { purgeExpired } from "./lifecycle";
import { formatDuration } from "./format";
import { DEFAULT_ROTATION, WEEKDAY_INDEX } from "./records";
import type { RotationSettings, StoredIdentity, StoredSpk } from "./records";

const MIN_PASSPHRASE_LENGTH = 12;
const WIPE_CONFIRM_WINDOW_MS = 30_000;
const DAY_MS = 24 * 60 * 60 * 1000;

export type PassphraseProblem = "short" | "composition";

/** Strength rules for a new passphrase, shared by /register, /recover and
 * /rotate passphrase.
 *
 * This passphrase never leaves the device: it derives the KEK that wraps the
 * store's DEK through Argon2id, so it is the only thing standing between a
 * copied IndexedDB directory and its contents. That makes offline guessing the
 * threat being priced, which is why the length floor carries most of the
 * weight and the composition rules are a floor rather than the point.
 *
 * "Symbol" is anything that is not an ASCII letter or digit, so punctuation,
 * spaces and non-Latin marks all count - an allowlist would only reject
 * legitimate characters and push users toward predictable substitutions. */
export function passphraseProblem(passphrase: string): PassphraseProblem | null {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    return "short";
  }
  if (!/[0-9]/.test(passphrase) || !/[^A-Za-z0-9]/.test(passphrase)) {
    return "composition";
  }
  return null;
}

export async function promptNewPassphrase(x: ExecutorInternals): Promise<string | null> {
  const first = await x.shell.readSecret(
    `choose a passphrase (${MIN_PASSPHRASE_LENGTH}+ characters, with a number and a symbol): `,
  );
  if (first === null) {
    return null;
  }
  const problem = passphraseProblem(first);
  if (problem === "short") {
    x.renderer.error("E206", MIN_PASSPHRASE_LENGTH);
    return null;
  }
  if (problem === "composition") {
    x.renderer.error("E209");
    return null;
  }
  const second = await x.shell.readSecret("confirm passphrase: ");
  if (second === null) {
    return null;
  }
  if (!secretStringsEqual(first, second)) {
    x.renderer.error("E207");
    return null;
  }
  return first;
}

export async function doRegister(x: ExecutorInternals): Promise<void> {
  if (await x.store.exists()) {
    x.renderer.event(
      "warning",
      "an identity store already exists on this device - /login (or /wipe to destroy it first)",
    );
    return;
  }
  const passphrase = await promptNewPassphrase(x);
  if (passphrase === null) {
    x.renderer.event("info", "registration cancelled");
    return;
  }

  x.renderer.event("info", "generating ML-DSA-65 identity keypair...");
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const keys = ml_dsa65.keygen(seed);
  seed.fill(0);
  const response = await api.register(keys.publicKey);
  const uid = normalizeUid(response.uid);
  if (uid === null) {
    throw new Error("server returned malformed uid");
  }

  await x.store.create(passphrase);
  const stored: StoredIdentity = {
    uid,
    pub: toBase64(keys.publicKey),
    sec: toBase64(keys.secretKey),
  };
  await x.store.putJson("identity", stored);
  await x.store.putJson("settings/rotation", DEFAULT_ROTATION);
  x.identity = { uid, pub: keys.publicKey, sec: keys.secretKey };

  x.renderer.event("success", `registered - your UID is ${response.uid}`);
  x.renderer.event("info", "share your UID out-of-band; there is no directory to search");
  x.renderer.event(
    "security",
    "recovery codes - shown ONCE, never recoverable. write them down now:",
  );
  response.recovery_codes.forEach((code, i) => {
    x.renderer.plain(`    ${(i + 1).toString().padStart(2)}. ${code}`);
  });

  await loginWithIdentity(x);
  await uploadInitialBundle(x);
  x.connectWs();
  await refreshEmblemState(x);
  x.touchAutoLock();
}

/** `/recover`: redeem a recovery code to take the UID back with a brand-new
 * identity key. The server destroys every artifact of the old
 * identity (prekeys, sessions, queued ciphertext) and reissues the full code
 * set; locally the store is rebuilt from scratch under a new passphrase.
 * Peers still pin the old key, so their next contact with us raises the
 * identity-key-change warning: that is the designed signal that a
 * recovery (or a MITM) happened. */
export async function doRecover(x: ExecutorInternals): Promise<void> {
  const hadStore = await x.store.exists();
  if (hadStore) {
    x.renderer.event(
      "security",
      "recovery will REPLACE the identity store on this device - the identity, keys, contacts and message history held here are destroyed and rebuilt from the recovered account. This is a confirmation, not a refusal: answer yes below to go ahead",
    );
    const answer = await x.shell.readLine("destroy the local store and recover? (yes/NO): ");
    if (answer === null || answer.trim().toLowerCase() !== "yes") {
      x.renderer.event("info", "recovery cancelled - nothing was changed");
      return;
    }
  }
  const uidRaw = await x.shell.readLine("account UID: ");
  if (uidRaw === null) {
    x.renderer.event("info", "recovery cancelled");
    return;
  }
  const uid = normalizeUid(uidRaw.trim());
  if (uid === null) {
    x.renderer.error("E103");
    return;
  }
  const codeRaw = await x.shell.readSecret("recovery code: ");
  if (codeRaw === null) {
    x.renderer.event("info", "recovery cancelled");
    return;
  }
  const code = normalizeRecoveryCode(codeRaw);
  if (code === null) {
    x.renderer.error("E104");
    return;
  }
  const passphrase = await promptNewPassphrase(x);
  if (passphrase === null) {
    x.renderer.event("info", "recovery cancelled");
    return;
  }

  x.renderer.event("info", "generating replacement ML-DSA-65 identity keypair...");
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const keys = ml_dsa65.keygen(seed);
  seed.fill(0);
  let response: api.RecoverResponse;
  try {
    response = await api.recover(uid, code, keys.publicKey);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      // Uniform by design: the server does not distinguish an
      // unknown UID from a wrong or already-spent code, and neither do we.
      x.renderer.error("E205");
      return;
    }
    throw err; // 429 and network failures take the standard error path
  }
  const confirmedUid = normalizeUid(response.uid);
  if (confirmedUid === null) {
    throw new Error("server returned malformed uid");
  }

  // The server has already switched the account to the new key; whatever
  // local state existed belongs to a dead identity. Tear down, then rebuild.
  x.token = null;
  x.lockLocal();
  x.contacts.clear();
  x.active = null;
  x.shell.setPrompt("> ");
  if (hadStore) {
    await x.store.wipe();
  }
  await x.store.create(passphrase);
  const stored: StoredIdentity = {
    uid: confirmedUid,
    pub: toBase64(keys.publicKey),
    sec: toBase64(keys.secretKey),
  };
  await x.store.putJson("identity", stored);
  await x.store.putJson("settings/rotation", DEFAULT_ROTATION);
  x.identity = { uid: confirmedUid, pub: keys.publicKey, sec: keys.secretKey };

  x.renderer.event("success", `account recovered - your UID is ${response.uid}`);
  x.renderer.event(
    "security",
    "NEW recovery codes - the old set is now void. shown ONCE, never recoverable. write them down now:",
  );
  response.recovery_codes.forEach((freshCode, i) => {
    x.renderer.plain(`    ${(i + 1).toString().padStart(2)}. ${freshCode}`);
  });
  x.renderer.event(
    "warning",
    "message history, contacts, and sessions did not survive - they lived only in the old encrypted store",
  );
  x.renderer.event(
    "warning",
    "your contacts still pin the OLD identity key: your next message triggers their identity-key-change warning, and they should re-verify your safety number",
  );

  await loginWithIdentity(x);
  await uploadInitialBundle(x);
  x.connectWs();
  await refreshEmblemState(x);
  x.touchAutoLock();
}

export async function loginWithIdentity(x: ExecutorInternals): Promise<void> {
  if (x.identity === null) {
    throw new Error("no identity");
  }
  const challenge = await api.loginChallenge(x.identity.uid);
  const message = buildLoginMessage(
    hexToBytes(challenge.nonce),
    challenge.origin,
    challenge.timestamp,
  );
  const signature = ml_dsa65.sign(message, x.identity.sec);
  const verified = await api.loginVerify(x.identity.uid, challenge.nonce, signature);
  x.token = verified.token;
  x.renderer.event("success", "logged in - session token held in memory only (15 min idle)");
}

async function uploadInitialBundle(x: ExecutorInternals): Promise<void> {
  if (x.identity === null || x.token === null) {
    throw new Error("not logged in");
  }
  await rotateSpkInternal(x);
  await refillOpksInternal(x, OPK_BATCH_MAX);
  x.renderer.event("success", `prekey bundle uploaded (SPK + ${OPK_BATCH_MAX} one-time prekeys)`);
}

async function rotateSpkInternal(x: ExecutorInternals): Promise<void> {
  if (x.identity === null || x.token === null) {
    throw new Error("not logged in");
  }
  const spk = generateSpk(x.identity.sec);
  const createdAt = x.now();
  const record: StoredSpk = {
    pub: toBase64(spk.pub),
    sec: toBase64(spk.sec),
    sig: toBase64(spk.sig),
    createdAt,
  };
  await x.store.putJson(`spk/${createdAt}`, record);
  await api.uploadSpk(x.token, spk.pub, spk.sig);
  spk.sec.fill(0);
  // Keep old SPK secrets for SPK_ROTATION+RETENTION days so late handshakes
  // still resolve, then delete them.
  const cutoff = x.now() - (SPK_ROTATION_DAYS + SPK_RETENTION_DAYS) * DAY_MS;
  for (const key of await x.store.listKeys("spk/")) {
    const ts = Number(key.slice("spk/".length));
    if (Number.isFinite(ts) && ts < cutoff) {
      await x.store.deleteKey(key);
    }
  }
}

async function refillOpksInternal(x: ExecutorInternals, count: number): Promise<void> {
  if (x.identity === null || x.token === null) {
    throw new Error("not logged in");
  }
  const batchId = x.now();
  const batch = generateOpkBatch(x.identity.sec, count);
  for (let i = 0; i < batch.pubs.length; i += 1) {
    const pub = batch.pubs[i];
    const sec = batch.secs[i];
    if (pub === undefined || sec === undefined) {
      continue;
    }
    await x.store.putJson(`opk/${batchId}/${i}`, {
      pub: toBase64(pub),
      sec: toBase64(sec),
    });
    sec.fill(0);
  }
  await api.uploadOpks(x.token, batch.pubs, batch.rootSig);
}

export async function doLogin(x: ExecutorInternals): Promise<void> {
  if (!(await x.store.exists())) {
    x.renderer.error("E204");
    return;
  }
  if (!x.store.isUnlocked()) {
    const passphrase = await x.shell.readSecret("passphrase: ");
    if (passphrase === null) {
      x.renderer.event("info", "login cancelled");
      return;
    }
    if (!(await x.store.unlock(passphrase))) {
      x.renderer.error("E203");
      return;
    }
  }
  const stored = await x.store.getJson<StoredIdentity>("identity");
  if (stored === null) {
    x.renderer.error("E402");
    return;
  }
  x.identity = {
    uid: stored.uid,
    pub: fromBase64(stored.pub),
    sec: fromBase64(stored.sec),
  };
  await loadContacts(x);
  await loadTrustMode(x);
  try {
    await loginWithIdentity(x);
  } catch (err) {
    // A 401 here is not a lapsed session (there is none yet) - the server
    // refused this device's identity key. The usual cause is a /recover run on
    // another device, which enrolls a new key and orphans this one, so say that
    // rather than inheriting the generic session-expired message.
    if (err instanceof ApiError && err.status === 401) {
      x.renderer.error("E210");
      return;
    }
    throw err; // 429 and network failures take the standard error path
  }
  await postLoginMaintenance(x);
  await drainInbox(x);
  await purgeExpired(x); // evict anything past its timer/cap while offline
  x.connectWs();
  await maybeRotationPrompt(x);
  refreshChatContext(x); // restore the context line if a chat was active
  await refreshEmblemState(x);
  x.touchAutoLock();
}

async function postLoginMaintenance(x: ExecutorInternals): Promise<void> {
  if (x.token === null) {
    return;
  }
  const status = await api.keysStatus(x.token);
  const spkKeys = await x.store.listKeys("spk/");
  const newest = spkKeys
    .map((k) => Number(k.slice("spk/".length)))
    .filter((n) => Number.isFinite(n))
    .sort((a, b) => b - a)[0];
  const spkAgeMs = newest === undefined ? Number.POSITIVE_INFINITY : x.now() - newest;
  if (status.spk_uploaded_at === null || spkAgeMs > SPK_ROTATION_DAYS * DAY_MS) {
    await rotateSpkInternal(x);
    x.renderer.event("info", "signed prekey rotated (weekly schedule)");
  }
  if (status.opk_count < OPK_LOW_WATERMARK) {
    const needed = OPK_BATCH_MAX - status.opk_count;
    await refillOpksInternal(x, needed);
    x.renderer.event("info", `one-time prekeys refilled (+${needed})`);
  }
}

async function maybeRotationPrompt(x: ExecutorInternals): Promise<void> {
  const settings =
    (await x.store.getJson<RotationSettings>("settings/rotation")) ?? DEFAULT_ROTATION;
  if (!settings.enabled) {
    return;
  }
  const nowDate = new Date(x.now());
  const delta = (nowDate.getDay() - WEEKDAY_INDEX[settings.day] + 7) % 7;
  const occurrence = new Date(
    nowDate.getFullYear(),
    nowDate.getMonth(),
    nowDate.getDate() - delta,
  ).getTime();
  if (settings.lastPrompt < occurrence) {
    x.renderer.event(
      "warning",
      "weekly passphrase rotation is due - /rotate passphrase (configure: /settings rotation)",
    );
    await x.store.putJson("settings/rotation", { ...settings, lastPrompt: x.now() });
  }
}

export async function doLogout(x: ExecutorInternals): Promise<void> {
  if (x.token !== null) {
    try {
      await api.logout(x.token);
    } finally {
      x.token = null;
    }
  }
  x.lockLocal();
  x.renderer.event("success", "logged out - session revoked server-side, store locked");
}

/** Elapsed time as a short phrase, coarse for readability. */
function agoPhrase(seconds: number): string {
  return seconds < 60 ? "moments ago" : `${formatDuration(seconds)} ago`;
}

/** /sessions: list this account's live sessions on this server. Sessions stay
 * anonymous, since the server stores no device label, so each line shows only
 * when it started and how recently it was active, marking the current one. */
export async function doSessions(x: ExecutorInternals): Promise<void> {
  if (x.token === null) {
    x.renderer.error("E201");
    return;
  }
  const { sessions } = await api.sessions(x.token);
  const count = sessions.length;
  x.renderer.event("info", `${count} active session${count === 1 ? "" : "s"} on this account:`);
  for (const s of sessions) {
    const label = s.current ? "this device" : "another device";
    const activity = s.current
      ? "active now"
      : s.idle_seconds < 60
        ? "active moments ago"
        : `idle ${formatDuration(s.idle_seconds)}`;
    x.renderer.event("info", `  - ${label}: started ${agoPhrase(s.age_seconds)}, ${activity}`);
  }
  if (count > 1) {
    x.renderer.event("info", "sign out the others with /logout all (this device stays logged in)");
  }
}

/** /logout all: sign out every OTHER session, keeping this one. Signing out
 * this device is what /logout does. */
export async function doLogoutOthers(x: ExecutorInternals): Promise<void> {
  if (x.token === null) {
    x.renderer.error("E201");
    return;
  }
  const { revoked } = await api.logoutAll(x.token);
  if (revoked === 0) {
    x.renderer.event("info", "no other sessions to sign out - this is your only active device");
    return;
  }
  x.renderer.event(
    "success",
    `signed out ${revoked} other session${revoked === 1 ? "" : "s"} - this device stays logged in`,
  );
}

export function doLock(x: ExecutorInternals): void {
  x.lockLocal();
  x.renderer.event("success", "store locked (session token, if any, expires after 15 min idle)");
}

export async function doRotatePassphrase(x: ExecutorInternals): Promise<void> {
  if (!(await x.store.exists())) {
    x.renderer.error("E204");
    return;
  }
  const current = await x.shell.readSecret("current passphrase: ");
  if (current === null) {
    return;
  }
  const next = await promptNewPassphrase(x);
  if (next === null) {
    return;
  }
  if (secretStringsEqual(current, next)) {
    // Checked locally before anything touches the store: neither value
    // leaves this scope, and the answer reveals nothing the typist does not
    // already know.
    x.renderer.event(
      "warning",
      "the new passphrase is identical to the current one - rotating it changes nothing an attacker would have to guess",
    );
    const answer = await x.shell.readLine("rotate anyway? (y/N): ");
    if (answer === null || !/^y(es)?$/i.test(answer.trim())) {
      x.renderer.event("info", "rotation cancelled - run /rotate passphrase again with a different passphrase");
      return;
    }
  }
  if (!(await x.store.rotatePassphrase(current, next))) {
    x.renderer.error("E208");
    return;
  }
  const settings =
    (await x.store.getJson<RotationSettings>("settings/rotation").catch(() => null)) ??
    DEFAULT_ROTATION;
  if (x.store.isUnlocked()) {
    await x.store.putJson("settings/rotation", { ...settings, lastPrompt: x.now() });
  }
  x.renderer.event("success", "passphrase rotated - DEK re-wrapped locally, nothing sent anywhere");
}

export async function doKeysStatus(x: ExecutorInternals): Promise<void> {
  if (x.token === null) {
    x.renderer.error("E201");
    return;
  }
  const status = await api.keysStatus(x.token);
  if (status.spk_uploaded_at === null) {
    x.renderer.event("warning", "no signed prekey uploaded yet");
  } else {
    const days = Math.floor((x.now() / 1000 - status.spk_uploaded_at) / 86400);
    x.renderer.event("info", `signed prekey age: ${days} day(s) (rotates weekly)`);
  }
  x.renderer.event(
    "info",
    `one-time prekeys available: ${status.opk_count} (auto-refill below ${OPK_LOW_WATERMARK})`,
  );
}

export async function doKeysRefill(x: ExecutorInternals): Promise<void> {
  if (x.token === null || x.identity === null) {
    x.renderer.error("E201");
    return;
  }
  const status = await api.keysStatus(x.token);
  const needed = Math.max(0, OPK_BATCH_MAX - status.opk_count);
  if (needed === 0) {
    x.renderer.event("info", `one-time prekeys already at capacity (${status.opk_count})`);
    return;
  }
  await refillOpksInternal(x, needed);
  x.renderer.event("success", `uploaded ${needed} one-time prekey(s)`);
}

export async function doWipe(x: ExecutorInternals): Promise<void> {
  const nowMs = x.now();
  if (x.wipeRequestedAt === 0 || nowMs - x.wipeRequestedAt > WIPE_CONFIRM_WINDOW_MS) {
    x.wipeRequestedAt = nowMs;
    x.renderer.event(
      "security",
      "/wipe destroys the local store: identity, keys, history. IRREVERSIBLE without recovery codes. repeat /wipe within 30s to confirm.",
    );
    return;
  }
  x.wipeRequestedAt = 0;
  x.token = null;
  x.lockLocal();
  await x.store.wipe();
  x.contacts.clear();
  x.active = null;
  refreshChatContext(x);
  x.shell.setPrompt("> ");
  x.renderer.event("success", "local store destroyed (browser deletion is not forensic erasure)");
}

/** `/whoami`: own UID and identity-key fingerprint. */
export function doWhoami(x: ExecutorInternals): void {
  if (x.identity === null) {
    x.renderer.event("warning", "locked or not registered - /login or /register");
    return;
  }
  const fingerprint = bytesToHex(sha512(x.identity.pub).slice(0, 16));
  x.renderer.event("info", `UID: ${formatUid(x.identity.uid)}`);
  x.renderer.event("info", `identity-key fingerprint (SHA-512/128): ${fingerprint}`);
}
