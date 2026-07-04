// Command executor: consumes the parser's typed union in one switch
// (CLAUDE.md §1.2). W2 implements the full identity/key-store command set;
// messaging commands respond with their scheduled segment so the surface is
// honest about what exists.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import * as api from "../net/api";
import { ApiError } from "../net/api";
import { buildLoginMessage } from "../crypto/login";
import { generateOpkBatch, generateSpk } from "../crypto/prekeys";
import { KeyStore, StoreLockedError } from "../crypto/store";
import {
  AUTO_LOCK_MS,
  OPK_BATCH_MAX,
  OPK_LOW_WATERMARK,
  SPK_RETENTION_DAYS,
  SPK_ROTATION_DAYS,
} from "../crypto/constants";
import { fromBase64, toBase64 } from "../util/base64";
import type { Command, ParseResult, Weekday } from "./parser";
import { COMMAND_USAGE, formatUid, normalizeUid } from "./parser";
import type { Renderer } from "./renderer";
import type { Shell } from "./shell";

interface StoredIdentity {
  readonly uid: string; // canonical 26-char form
  readonly pub: string; // base64
  readonly sec: string; // base64
}

interface Identity {
  readonly uid: string;
  readonly pub: Uint8Array;
  sec: Uint8Array;
}

interface StoredSpk {
  readonly pub: string;
  readonly sec: string;
  readonly sig: string;
  readonly createdAt: number;
}

interface RotationSettings {
  readonly enabled: boolean;
  readonly day: Weekday;
  readonly lastPrompt: number;
}

interface Contact {
  readonly uid: string;
  readonly alias: string;
}

const DEFAULT_ROTATION: RotationSettings = { enabled: true, day: "friday", lastPrompt: 0 };

const WEEKDAY_INDEX: Record<Weekday, number> = {
  sunday: 0,
  monday: 1,
  tuesday: 2,
  wednesday: 3,
  thursday: 4,
  friday: 5,
  saturday: 6,
};

const MIN_PASSPHRASE_LENGTH = 8;
const WIPE_CONFIRM_WINDOW_MS = 30_000;
const DAY_MS = 24 * 60 * 60 * 1000;

const SEGMENT_OF: Partial<Record<Command["name"], string>> = {
  verify: "W4 (ratchet & trust)",
  verified: "W4 (ratchet & trust)",
  timer: "W5 (lifecycle & hardening)",
  "purge-set": "W5 (lifecycle & hardening)",
  "purge-now": "W5 (lifecycle & hardening)",
  bench: "W6 (benchmarks)",
  "settings-notify": "W6 (could-have)",
};

export class Executor {
  private readonly store: KeyStore;
  private identity: Identity | null = null;
  private token: string | null = null;
  private contacts = new Map<string, Contact>();
  private active: Contact | null = null;
  private busy = false;
  private wipeRequestedAt = 0;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly renderer: Renderer,
    private readonly shell: Shell,
    store?: KeyStore,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.store = store ?? new KeyStore();
  }

  handle(result: ParseResult): void {
    this.touchAutoLock();
    switch (result.kind) {
      case "empty":
        return;
      case "invalid": {
        this.renderer.event("failure", result.error);
        if (result.usage !== undefined) {
          this.renderer.plain(`    usage: ${result.usage}`);
        }
        return;
      }
      case "message": {
        this.handleMessage(result.text);
        return;
      }
      case "command": {
        this.handleCommand(result.command);
        return;
      }
    }
  }

  private handleMessage(text: string): void {
    if (this.active === null) {
      this.renderer.event("warning", "no active conversation - use /chat <alias|uid> first");
      return;
    }
    void text;
    this.renderer.event(
      "warning",
      `not sent to ${this.active.alias}: messaging arrives in W3 (handshake + delivery queue)`,
    );
  }

  private handleCommand(cmd: Command): void {
    if (cmd.name !== "wipe") {
      this.wipeRequestedAt = 0;
    }
    switch (cmd.name) {
      case "help":
        this.printHelp(cmd.topic);
        return;
      case "register":
        this.run(() => this.doRegister());
        return;
      case "login":
        this.run(() => this.doLogin());
        return;
      case "logout":
        this.run(() => this.doLogout());
        return;
      case "lock":
        this.doLock();
        return;
      case "rotate-passphrase":
        this.run(() => this.doRotatePassphrase());
        return;
      case "keys-status":
        this.run(() => this.doKeysStatus());
        return;
      case "keys-refill":
        this.run(() => this.doKeysRefill());
        return;
      case "settings-rotation":
        this.run(() => this.doSettingsRotation(cmd.setting));
        return;
      case "wipe":
        this.run(() => this.doWipe());
        return;
      case "whoami": {
        if (this.identity === null) {
          this.renderer.event("warning", "locked or not registered - /login or /register");
          return;
        }
        const fingerprint = bytesToHex(sha512(this.identity.pub).slice(0, 16));
        this.renderer.event("info", `UID: ${formatUid(this.identity.uid)}`);
        this.renderer.event("info", `identity-key fingerprint (SHA-512/128): ${fingerprint}`);
        return;
      }
      case "add": {
        const alias = cmd.alias ?? cmd.uid;
        this.contacts.set(alias, { uid: cmd.uid, alias });
        this.renderer.event(
          "success",
          `added contact ${alias} (${formatUid(cmd.uid)}) - alias is local-only`,
        );
        return;
      }
      case "chat": {
        const contact = this.resolveContact(cmd.target);
        if (contact === null) {
          this.renderer.event("failure", `unknown contact: ${cmd.target} - use /add <uid> [alias]`);
          return;
        }
        this.active = contact;
        this.renderer.event("info", `chatting with: ${contact.alias} (UNVERIFIED)`);
        this.shell.setPrompt(`[${contact.alias}] > `);
        return;
      }
      case "ack": {
        this.renderer.event("info", `nothing to acknowledge for ${cmd.alias}`);
        return;
      }
      default: {
        const segment = SEGMENT_OF[cmd.name] ?? "a later segment";
        this.renderer.event("info", `/${cmd.name} is not implemented yet - scheduled for ${segment}`);
        return;
      }
    }
  }

  // ----- async command plumbing -------------------------------------------

  private run(task: () => Promise<void>): void {
    if (this.busy) {
      this.renderer.event("warning", "another operation is in progress");
      return;
    }
    this.busy = true;
    void task()
      .catch((err: unknown) => this.reportError(err))
      .finally(() => {
        this.busy = false;
      });
  }

  private reportError(err: unknown): void {
    if (err instanceof ApiError) {
      if (err.status === 429) {
        this.renderer.event("failure", "rate limit reached - try again later");
        return;
      }
      if (err.status === 401) {
        this.token = null;
        this.renderer.event("failure", "session expired or invalid - /login again");
        return;
      }
      this.renderer.event("failure", "request failed - is the server running?");
      return;
    }
    if (err instanceof StoreLockedError) {
      this.renderer.event("failure", "store is locked - /login to unlock");
      return;
    }
    this.renderer.event("failure", "operation failed");
  }

  private touchAutoLock(): void {
    if (this.autoLockTimer !== null) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
    if (this.store.isUnlocked()) {
      this.autoLockTimer = setTimeout(() => {
        this.lockLocal();
        this.renderer.event("warning", "auto-locked after 10 minutes idle - /login to unlock");
      }, AUTO_LOCK_MS);
    }
  }

  private lockLocal(): void {
    if (this.identity !== null) {
      this.identity.sec.fill(0);
      this.identity = null;
    }
    this.store.lock();
    if (this.autoLockTimer !== null) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
  }

  // ----- flows --------------------------------------------------------------

  private async promptNewPassphrase(): Promise<string | null> {
    const first = await this.shell.readSecret("choose a passphrase: ");
    if (first === null) {
      return null;
    }
    if (first.length < MIN_PASSPHRASE_LENGTH) {
      this.renderer.event("failure", `passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
      return null;
    }
    const second = await this.shell.readSecret("confirm passphrase: ");
    if (second === null) {
      return null;
    }
    if (first !== second) {
      this.renderer.event("failure", "passphrases do not match");
      return null;
    }
    return first;
  }

  private async doRegister(): Promise<void> {
    if (await this.store.exists()) {
      this.renderer.event(
        "warning",
        "an identity store already exists on this device - /login (or /wipe to destroy it first)",
      );
      return;
    }
    const passphrase = await this.promptNewPassphrase();
    if (passphrase === null) {
      this.renderer.event("info", "registration cancelled");
      return;
    }

    this.renderer.event("info", "generating ML-DSA-65 identity keypair...");
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const keys = ml_dsa65.keygen(seed);
    seed.fill(0);
    const response = await api.register(keys.publicKey);
    const uid = normalizeUid(response.uid);
    if (uid === null) {
      throw new Error("server returned malformed uid");
    }

    await this.store.create(passphrase);
    const stored: StoredIdentity = {
      uid,
      pub: toBase64(keys.publicKey),
      sec: toBase64(keys.secretKey),
    };
    await this.store.putJson("identity", stored);
    await this.store.putJson("settings/rotation", DEFAULT_ROTATION);
    this.identity = { uid, pub: keys.publicKey, sec: keys.secretKey };

    this.renderer.event("success", `registered - your UID is ${response.uid}`);
    this.renderer.event("info", "share your UID out-of-band; there is no directory to search");
    this.renderer.event(
      "security",
      "recovery codes - shown ONCE, never recoverable. write them down now:",
    );
    response.recovery_codes.forEach((code, i) => {
      this.renderer.plain(`    ${(i + 1).toString().padStart(2)}. ${code}`);
    });

    await this.loginWithIdentity();
    await this.uploadInitialBundle();
    this.touchAutoLock();
  }

  private async loginWithIdentity(): Promise<void> {
    if (this.identity === null) {
      throw new Error("no identity");
    }
    const challenge = await api.loginChallenge(this.identity.uid);
    const message = buildLoginMessage(
      hexToBytes(challenge.nonce),
      challenge.origin,
      challenge.timestamp,
    );
    const signature = ml_dsa65.sign(message, this.identity.sec);
    const verified = await api.loginVerify(this.identity.uid, challenge.nonce, signature);
    this.token = verified.token;
    this.renderer.event("success", "logged in - session token held in memory only (15 min idle)");
  }

  private async uploadInitialBundle(): Promise<void> {
    if (this.identity === null || this.token === null) {
      throw new Error("not logged in");
    }
    await this.rotateSpkInternal();
    await this.refillOpksInternal(OPK_BATCH_MAX);
    this.renderer.event("success", `prekey bundle uploaded (SPK + ${OPK_BATCH_MAX} one-time prekeys)`);
  }

  private async rotateSpkInternal(): Promise<void> {
    if (this.identity === null || this.token === null) {
      throw new Error("not logged in");
    }
    const spk = generateSpk(this.identity.sec);
    const createdAt = this.now();
    const record: StoredSpk = {
      pub: toBase64(spk.pub),
      sec: toBase64(spk.sec),
      sig: toBase64(spk.sig),
      createdAt,
    };
    await this.store.putJson(`spk/${createdAt}`, record);
    await api.uploadSpk(this.token, spk.pub, spk.sig);
    spk.sec.fill(0);
    // Old SPK secrets are kept SPK_ROTATION+RETENTION days for late
    // handshakes, then deleted (§2.6).
    const cutoff = this.now() - (SPK_ROTATION_DAYS + SPK_RETENTION_DAYS) * DAY_MS;
    for (const key of await this.store.listKeys("spk/")) {
      const ts = Number(key.slice("spk/".length));
      if (Number.isFinite(ts) && ts < cutoff) {
        await this.store.deleteKey(key);
      }
    }
  }

  private async refillOpksInternal(count: number): Promise<void> {
    if (this.identity === null || this.token === null) {
      throw new Error("not logged in");
    }
    const batchId = this.now();
    const batch = generateOpkBatch(this.identity.sec, count);
    for (let i = 0; i < batch.pubs.length; i += 1) {
      const pub = batch.pubs[i];
      const sec = batch.secs[i];
      if (pub === undefined || sec === undefined) {
        continue;
      }
      await this.store.putJson(`opk/${batchId}/${i}`, {
        pub: toBase64(pub),
        sec: toBase64(sec),
      });
      sec.fill(0);
    }
    await api.uploadOpks(this.token, batch.pubs, batch.rootSig);
  }

  private async doLogin(): Promise<void> {
    if (!(await this.store.exists())) {
      this.renderer.event("failure", "no identity on this device - /register first");
      return;
    }
    if (!this.store.isUnlocked()) {
      const passphrase = await this.shell.readSecret("passphrase: ");
      if (passphrase === null) {
        this.renderer.event("info", "login cancelled");
        return;
      }
      if (!(await this.store.unlock(passphrase))) {
        this.renderer.event("failure", "unlock failed");
        return;
      }
    }
    const stored = await this.store.getJson<StoredIdentity>("identity");
    if (stored === null) {
      this.renderer.event("failure", "store is corrupt: no identity record");
      return;
    }
    this.identity = {
      uid: stored.uid,
      pub: fromBase64(stored.pub),
      sec: fromBase64(stored.sec),
    };
    await this.loginWithIdentity();
    await this.postLoginMaintenance();
    await this.maybeRotationPrompt();
    this.touchAutoLock();
  }

  private async postLoginMaintenance(): Promise<void> {
    if (this.token === null) {
      return;
    }
    const status = await api.keysStatus(this.token);
    const spkKeys = await this.store.listKeys("spk/");
    const newest = spkKeys
      .map((k) => Number(k.slice("spk/".length)))
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => b - a)[0];
    const spkAgeMs = newest === undefined ? Number.POSITIVE_INFINITY : this.now() - newest;
    if (status.spk_uploaded_at === null || spkAgeMs > SPK_ROTATION_DAYS * DAY_MS) {
      await this.rotateSpkInternal();
      this.renderer.event("info", "signed prekey rotated (weekly schedule)");
    }
    if (status.opk_count < OPK_LOW_WATERMARK) {
      const needed = OPK_BATCH_MAX - status.opk_count;
      await this.refillOpksInternal(needed);
      this.renderer.event("info", `one-time prekeys refilled (+${needed})`);
    }
  }

  private async maybeRotationPrompt(): Promise<void> {
    const settings =
      (await this.store.getJson<RotationSettings>("settings/rotation")) ?? DEFAULT_ROTATION;
    if (!settings.enabled) {
      return;
    }
    const nowDate = new Date(this.now());
    const delta = (nowDate.getDay() - WEEKDAY_INDEX[settings.day] + 7) % 7;
    const occurrence = new Date(
      nowDate.getFullYear(),
      nowDate.getMonth(),
      nowDate.getDate() - delta,
    ).getTime();
    if (settings.lastPrompt < occurrence) {
      this.renderer.event(
        "warning",
        "weekly passphrase rotation is due - /rotate passphrase (configure: /settings rotation)",
      );
      await this.store.putJson("settings/rotation", { ...settings, lastPrompt: this.now() });
    }
  }

  private async doLogout(): Promise<void> {
    if (this.token !== null) {
      try {
        await api.logout(this.token);
      } finally {
        this.token = null;
      }
    }
    this.lockLocal();
    this.renderer.event("success", "logged out - session revoked server-side, store locked");
  }

  private doLock(): void {
    this.lockLocal();
    this.renderer.event("success", "store locked (session token, if any, expires after 15 min idle)");
  }

  private async doRotatePassphrase(): Promise<void> {
    if (!(await this.store.exists())) {
      this.renderer.event("failure", "no identity on this device - /register first");
      return;
    }
    const current = await this.shell.readSecret("current passphrase: ");
    if (current === null) {
      return;
    }
    const next = await this.promptNewPassphrase();
    if (next === null) {
      return;
    }
    if (!(await this.store.rotatePassphrase(current, next))) {
      this.renderer.event("failure", "rotation failed");
      return;
    }
    const settings =
      (await this.store.getJson<RotationSettings>("settings/rotation").catch(() => null)) ??
      DEFAULT_ROTATION;
    if (this.store.isUnlocked()) {
      await this.store.putJson("settings/rotation", { ...settings, lastPrompt: this.now() });
    }
    this.renderer.event("success", "passphrase rotated - DEK re-wrapped locally, nothing sent anywhere");
  }

  private async doKeysStatus(): Promise<void> {
    if (this.token === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return;
    }
    const status = await api.keysStatus(this.token);
    if (status.spk_uploaded_at === null) {
      this.renderer.event("warning", "no signed prekey uploaded yet");
    } else {
      const days = Math.floor((this.now() / 1000 - status.spk_uploaded_at) / 86400);
      this.renderer.event("info", `signed prekey age: ${days} day(s) (rotates weekly)`);
    }
    this.renderer.event(
      "info",
      `one-time prekeys available: ${status.opk_count} (auto-refill below ${OPK_LOW_WATERMARK})`,
    );
  }

  private async doKeysRefill(): Promise<void> {
    if (this.token === null || this.identity === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return;
    }
    const status = await api.keysStatus(this.token);
    const needed = Math.max(0, OPK_BATCH_MAX - status.opk_count);
    if (needed === 0) {
      this.renderer.event("info", `one-time prekeys already at capacity (${status.opk_count})`);
      return;
    }
    await this.refillOpksInternal(needed);
    this.renderer.event("success", `uploaded ${needed} one-time prekey(s)`);
  }

  private async doSettingsRotation(
    setting: { kind: "on" } | { kind: "off" } | { kind: "day"; day: Weekday },
  ): Promise<void> {
    if (!this.store.isUnlocked()) {
      this.renderer.event("failure", "store is locked - /login first (settings live encrypted)");
      return;
    }
    const current =
      (await this.store.getJson<RotationSettings>("settings/rotation")) ?? DEFAULT_ROTATION;
    let next: RotationSettings;
    switch (setting.kind) {
      case "on":
        next = { ...current, enabled: true };
        break;
      case "off":
        next = { ...current, enabled: false };
        break;
      case "day":
        next = { ...current, enabled: true, day: setting.day };
        break;
    }
    await this.store.putJson("settings/rotation", next);
    this.renderer.event(
      "success",
      next.enabled
        ? `weekly rotation prompt on (${next.day})`
        : "weekly rotation prompt off",
    );
  }

  private async doWipe(): Promise<void> {
    const nowMs = this.now();
    if (this.wipeRequestedAt === 0 || nowMs - this.wipeRequestedAt > WIPE_CONFIRM_WINDOW_MS) {
      this.wipeRequestedAt = nowMs;
      this.renderer.event(
        "security",
        "/wipe destroys the local store: identity, keys, history. IRREVERSIBLE without recovery codes. repeat /wipe within 30s to confirm.",
      );
      return;
    }
    this.wipeRequestedAt = 0;
    this.token = null;
    this.lockLocal();
    await this.store.wipe();
    this.contacts.clear();
    this.active = null;
    this.shell.setPrompt("> ");
    this.renderer.event("success", "local store destroyed (browser deletion is not forensic erasure)");
  }

  private resolveContact(target: string): Contact | null {
    const byAlias = this.contacts.get(target);
    if (byAlias !== undefined) {
      return byAlias;
    }
    const uid = normalizeUid(target);
    if (uid === null) {
      return null;
    }
    for (const contact of this.contacts.values()) {
      if (contact.uid === uid) {
        return contact;
      }
    }
    return null;
  }

  private printHelp(topic: keyof typeof COMMAND_USAGE | undefined): void {
    if (topic !== undefined) {
      this.renderer.plain(`  ${COMMAND_USAGE[topic]}`);
      return;
    }
    this.renderer.plain("commands (anything else is message text for the active conversation):");
    for (const usage of Object.values(COMMAND_USAGE)) {
      this.renderer.plain(`  ${usage}`);
    }
    this.renderer.plain("  (escape a leading / in a message with a space)");
  }
}
