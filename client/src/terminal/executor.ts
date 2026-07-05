// Command executor: consumes the parser's typed union in one switch
// (CLAUDE.md §1.2). W1-W3 command surface: identity/key store (W2) plus the
// PQ-KX first message, delivery queue and WS push (W3). Later-segment
// commands respond with their scheduled milestone so the surface stays
// honest about what exists.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import * as api from "../net/api";
import { ApiError } from "../net/api";
import { WsClient } from "../net/ws";
import { buildLoginMessage } from "../crypto/login";
import { generateOpkBatch, generateSpk } from "../crypto/prekeys";
import { initiateKx, respondKx, verifyBundle } from "../crypto/kx";
import type { Bundle, KxSession, PrekeyLookup, PrekeySecret } from "../crypto/kx";
import { computeSafetyNumber, formatSafetyNumber } from "../crypto/safetynumber";
import { KeyStore, StoreLockedError } from "../crypto/store";
import {
  AUTO_LOCK_MS,
  OPK_BATCH_MAX,
  OPK_LOW_WATERMARK,
  SPK_RETENTION_DAYS,
  SPK_ROTATION_DAYS,
} from "../crypto/constants";
import { fromBase64, toBase64 } from "../util/base64";
import { secretStringsEqual } from "../util/secret";
import type { Command, ParseResult, Weekday } from "./parser";
import { COMMAND_USAGE, formatUid, normalizeUid } from "./parser";
import type { Renderer } from "./renderer";
import type { ShellIO } from "./shell";

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

interface StoredOpk {
  readonly pub: string;
  readonly sec: string;
}

interface RotationSettings {
  readonly enabled: boolean;
  readonly day: Weekday;
  readonly lastPrompt: number;
}

interface Contact {
  readonly uid: string;
  readonly alias: string;
  readonly ik: string | null; // base64, pinned TOFU-style on first contact
  /** Set by /verified after out-of-band safety-number comparison. Reset to
   * false whenever a key change is detected (§4.6). */
  readonly verified: boolean;
  /** True from the moment a key change is detected until /ack. Sending is
   * refused while this is set (§4.6, CLAUDE.md §1.4). */
  readonly keyChangeBlocked: boolean;
}

interface PartialContact {
  uid: string;
  alias: string;
  ik?: string | null | undefined;
  verified?: boolean | undefined;
  keyChangeBlocked?: boolean | undefined;
}

function normalizeContact(c: PartialContact): Contact {
  return {
    uid: c.uid,
    alias: c.alias,
    ik: c.ik ?? null,
    verified: c.verified ?? false,
    keyChangeBlocked: c.keyChangeBlocked ?? false,
  };
}

interface StoredSession {
  readonly rk: string;
  readonly transcript: string;
  readonly peerIk: string;
  readonly role: "initiator" | "responder";
  readonly reducedFs: boolean;
  readonly establishedAt: number;
}

interface PendingRequest {
  readonly text: string;
  readonly session: StoredSession;
  readonly senderIk: string;
  readonly receivedAt: number;
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
  private contacts = new Map<string, Contact>(); // key: alias
  private active: Contact | null = null;
  private busy = false;
  private wipeRequestedAt = 0;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private ws: WsClient | null = null;
  private rxTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly renderer: Renderer,
    private readonly shell: ShellIO,
    store?: KeyStore,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.store = store ?? new KeyStore();
  }

  /** Apply persisted display preferences before the first prompt. Safe to
   * call with no store yet (returns defaults). Best-effort: a read failure
   * just leaves the default asterisk masking in place. */
  async init(): Promise<void> {
    try {
      const prefs = await this.store.getDisplayPrefs();
      this.shell.setSecretMask(prefs.secretMask);
    } catch {
      // ignore: default masking remains
    }
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
    // Re-resolve from the map rather than trusting the snapshot captured at
    // /chat time: a key-change teardown (or /verified) mutates the stored
    // Contact, and sending must see that update, not a stale readonly copy.
    const target = this.findContactByUid(this.active.uid) ?? this.active;
    this.run(() => this.sendFirstMessage(target, text));
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
      case "settings-mask":
        this.run(() => this.doSettingsMask(cmd.mask));
        return;
      case "wipe":
        this.run(() => this.doWipe());
        return;
      case "add":
        this.run(() => this.doAdd(cmd.uid, cmd.alias));
        return;
      case "verify":
        this.run(() => this.doVerify(cmd.alias));
        return;
      case "verified":
        this.run(() => this.doVerified(cmd.alias));
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
      case "chat": {
        const contact = this.resolveContact(cmd.target);
        if (contact === null) {
          this.renderer.event(
            "failure",
            `unknown contact: ${cmd.target} - /add <uid> [alias] first (contacts load on /login)`,
          );
          return;
        }
        this.active = contact;
        const trust = contact.verified ? "verified" : "UNVERIFIED";
        this.renderer.event("info", `chatting with: ${contact.alias} (${trust})`);
        if (contact.keyChangeBlocked) {
          this.renderer.event(
            "security",
            `identity key for ${contact.alias} changed and is UNACKNOWLEDGED - sending is blocked. /ack ${contact.alias}, then /verify + /verified to resume.`,
          );
        }
        this.shell.setPrompt(`[${contact.alias}] > `);
        return;
      }
      case "ack":
        this.run(() => this.doAck(cmd.alias));
        return;
      default: {
        const segment = SEGMENT_OF[cmd.name] ?? "a later segment";
        this.renderer.event("info", `/${cmd.name} is not implemented yet - scheduled for ${segment}`);
        return;
      }
    }
  }

  // ----- async command plumbing -------------------------------------------

  private tail: Promise<void> = Promise.resolve();

  private run(task: () => Promise<void>): void {
    if (this.busy) {
      this.renderer.event("warning", "another operation is in progress");
      return;
    }
    this.busy = true;
    // Suspend auto-lock while a flow is in flight: it may be waiting at a
    // passphrase or recovery-code prompt, and firing mid-registration could
    // orphan a server-side identity that was never persisted locally.
    if (this.autoLockTimer !== null) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
    this.tail = task()
      .catch((err: unknown) => this.reportError(err))
      .finally(() => {
        this.busy = false;
        this.touchAutoLock();
      });
  }

  /** Resolves when the in-flight async command (if any) has finished. */
  idle(): Promise<void> {
    return this.tail;
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

  /** Bumped on every lock/logout/wipe; in-flight receive continuations
   * check it and bail instead of writing to torn-down state. */
  private epoch = 0;

  private lockLocal(): void {
    this.epoch += 1;
    this.ws?.close();
    this.ws = null;
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

  // ----- contacts -----------------------------------------------------------

  private async loadContacts(): Promise<void> {
    const stored = (await this.store.getJson<Contact[]>("contacts")) ?? [];
    this.contacts = new Map(stored.map((c) => [c.alias, normalizeContact(c)]));
  }

  private async saveContacts(): Promise<void> {
    await this.store.putJson("contacts", [...this.contacts.values()]);
  }

  private findContactByUid(uid: string): Contact | null {
    for (const contact of this.contacts.values()) {
      if (contact.uid === uid) {
        return contact;
      }
    }
    return null;
  }

  private resolveContact(target: string): Contact | null {
    return this.contacts.get(target) ?? this.findContactByUid(normalizeUid(target) ?? "");
  }

  private async doAdd(uid: string, alias: string | undefined): Promise<void> {
    if (!this.store.isUnlocked()) {
      this.renderer.event("failure", "contacts live in the encrypted store - /login first");
      return;
    }
    const name = alias ?? uid;
    const existing = this.findContactByUid(uid);
    const contact = normalizeContact({
      uid,
      alias: name,
      ik: existing?.ik ?? null,
      verified: existing?.verified,
      keyChangeBlocked: existing?.keyChangeBlocked,
    });
    if (existing !== null) {
      this.contacts.delete(existing.alias);
    }
    this.contacts.set(name, contact);

    const pending = await this.store.getJson<PendingRequest>(`pending/${uid}`);
    if (pending !== null) {
      // Accepting a held first-contact message (§7.4): promote its session
      // and show the message that was queued behind the request line.
      await this.store.putJson(`session/${uid}`, pending.session);
      await this.store.putJson(`msg/${uid}/${pending.receivedAt}`, {
        dir: "in",
        text: pending.text,
        ts: pending.receivedAt,
      });
      await this.store.deleteKey(`pending/${uid}`);
      this.contacts.set(name, { ...contact, ik: pending.senderIk });
      await this.saveContacts();
      this.renderer.event("success", `added contact ${name} (${formatUid(uid)})`);
      this.renderer.plain(`  [${name}] ${pending.text}`);
      if (pending.session.reducedFs) {
        this.renderer.event(
          "warning",
          "session has reduced forward secrecy (no one-time prekey was used)",
        );
      }
      return;
    }
    await this.saveContacts();
    this.renderer.event(
      "success",
      `added contact ${name} (${formatUid(uid)}) - alias is local-only`,
    );
  }

  // ----- trust: safety numbers & key-change teardown (§4.5, §4.6) ----------

  private async doVerify(alias: string): Promise<void> {
    if (this.identity === null || this.token === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return;
    }
    const contact = this.resolveContact(alias);
    if (contact === null) {
      this.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
      return;
    }

    // Always fetch fresh (non-consuming) so /verify itself can catch a key
    // change that hasn't shown up in a message yet.
    let wire: api.WireBundle;
    try {
      wire = await api.fetchBundle(this.token, contact.uid, false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        this.renderer.event("failure", "recipient keys unavailable - unknown UID");
        return;
      }
      throw err;
    }
    const bundle = wireToBundle(wire);
    if (!verifyBundle(bundle)) {
      this.renderer.event(
        "security",
        `prekey bundle signature verification FAILED for ${contact.alias} - the server may be tampering.`,
      );
      return;
    }
    const bundleIk = toBase64(bundle.ikPub);
    if (contact.ik !== null && contact.ik !== bundleIk) {
      await this.handleKeyChange(contact, bundleIk);
      return;
    }
    if (contact.ik === null) {
      this.contacts.set(contact.alias, { ...contact, ik: bundleIk });
      await this.saveContacts();
    }

    const sn = computeSafetyNumber(this.identity.pub, this.identity.uid, bundle.ikPub, contact.uid);
    this.renderer.event("info", `safety number with ${contact.alias} (compare out-of-band):`);
    for (const row of formatSafetyNumber(sn)) {
      this.renderer.plain(`  ${row}`);
    }
    this.renderer.event(
      "info",
      `if it matches, run /verified ${contact.alias} to mark this contact trusted`,
    );
  }

  private async doVerified(alias: string): Promise<void> {
    const contact = this.resolveContact(alias);
    if (contact === null) {
      this.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
      return;
    }
    if (contact.ik === null) {
      this.renderer.event("failure", `no known identity key for ${contact.alias} yet - /verify first`);
      return;
    }
    if (contact.keyChangeBlocked) {
      this.renderer.event(
        "failure",
        `${contact.alias} has an unacknowledged key change - /ack ${contact.alias} first, then /verify again`,
      );
      return;
    }
    this.contacts.set(contact.alias, { ...contact, verified: true });
    await this.saveContacts();
    this.renderer.event(
      "success",
      `${contact.alias} marked verified - safety number confirmed out-of-band`,
    );
  }

  private async doAck(alias: string): Promise<void> {
    const contact = this.resolveContact(alias);
    if (contact === null) {
      this.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
      return;
    }
    if (!contact.keyChangeBlocked) {
      this.renderer.event("info", `nothing to acknowledge for ${contact.alias}`);
      return;
    }
    this.contacts.set(contact.alias, { ...contact, keyChangeBlocked: false });
    await this.saveContacts();
    this.renderer.event(
      "success",
      `acknowledged - ${contact.alias} remains UNVERIFIED; /verify then /verified to confirm the new key before sending`,
    );
  }

  /** Identity-key change detected for `contact` (§4.6): adopt the new key so
   * the safety number and future traffic reflect reality, tear down any
   * established session, mark unverified and blocked, and raise a
   * high-visibility warning. The caller must still abort the action in
   * progress - this only updates state, it does not resume anything. */
  private async handleKeyChange(contact: Contact, newIkB64: string): Promise<void> {
    const updated: Contact = {
      ...contact,
      ik: newIkB64,
      verified: false,
      keyChangeBlocked: true,
    };
    this.contacts.set(contact.alias, updated);
    await this.saveContacts();
    await this.store.deleteKey(`session/${contact.uid}`);
    this.renderer.event(
      "security",
      `IDENTITY KEY CHANGED for ${contact.alias} - this conversation is now blocked and marked UNVERIFIED. /ack ${contact.alias} to acknowledge, then /verify + /verified to confirm the new key before sending.`,
    );
  }

  // ----- send (PQ-KX first message, §3) -------------------------------------

  private async sendFirstMessage(target: Contact, text: string): Promise<void> {
    if (this.identity === null || this.token === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return;
    }
    if (target.keyChangeBlocked) {
      this.renderer.event(
        "security",
        `sending to ${target.alias} is blocked: an unacknowledged identity-key change was detected. /ack ${target.alias}, then /verify + /verified to resume.`,
      );
      return;
    }
    const existing = await this.store.getJson<StoredSession>(`session/${target.uid}`);
    if (existing !== null) {
      this.renderer.event(
        "warning",
        `a PQ-KX session with ${target.alias} is already established - continued messaging arrives with the W4 ratchet`,
      );
      return;
    }

    let wire: api.WireBundle;
    try {
      wire = await api.fetchBundle(this.token, target.uid);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        this.renderer.event(
          "failure",
          "recipient keys unavailable - unknown UID or no prekeys published",
        );
        return;
      }
      throw err;
    }
    const bundle = wireToBundle(wire);

    // §3.1: verify both prekey signatures against IK_B; abort loudly on
    // failure, never proceed, never retry silently.
    if (!verifyBundle(bundle)) {
      this.renderer.event(
        "security",
        `prekey bundle signature verification FAILED for ${target.alias} - the server may be tampering. send aborted.`,
      );
      return;
    }
    const bundleIk = toBase64(bundle.ikPub);
    if (target.ik !== null && target.ik !== bundleIk) {
      await this.handleKeyChange(target, bundleIk);
      return;
    }

    const payload = new TextEncoder().encode(
      JSON.stringify({ u: this.identity.uid, m: text }),
    );
    const { envelope, session } = initiateKx(this.identity.pub, this.identity.sec, bundle, payload);
    await api.sendMessage(this.token, target.uid, envelope);

    const timestamp = this.now();
    await this.store.putJson(`session/${target.uid}`, serializeSession(session, timestamp));
    await this.store.putJson(`msg/${target.uid}/${timestamp}`, {
      dir: "out",
      text,
      ts: timestamp,
    });
    if (target.ik === null) {
      this.contacts.set(target.alias, { ...target, ik: bundleIk });
      await this.saveContacts();
    }
    this.renderer.event("success", `sent to ${target.alias} - PQ-KX handshake established`);
    if (session.reducedFs) {
      this.renderer.event(
        "warning",
        "reduced forward secrecy: recipient had no one-time prekeys left (§7.4) - heals with the W4 ratchet",
      );
    }
  }

  // ----- receive ------------------------------------------------------------

  private async buildPrekeyLookup(): Promise<PrekeyLookup> {
    const spkMap = new Map<string, PrekeySecret>();
    for (const key of await this.store.listKeys("spk/")) {
      const record = await this.store.getJson<StoredSpk>(key);
      if (record !== null) {
        const pub = fromBase64(record.pub);
        spkMap.set(bytesToHex(sha512(pub)), { pub, sec: fromBase64(record.sec), storeKey: key });
      }
    }
    const opkMap = new Map<string, PrekeySecret>();
    for (const key of await this.store.listKeys("opk/")) {
      const record = await this.store.getJson<StoredOpk>(key);
      if (record !== null) {
        const pub = fromBase64(record.pub);
        opkMap.set(bytesToHex(sha512(pub)), { pub, sec: fromBase64(record.sec), storeKey: key });
      }
    }
    return {
      spkByHash: (hash) => spkMap.get(hash) ?? null,
      opkByHash: (hash) => opkMap.get(hash) ?? null,
    };
  }

  /** Returns "ack" when the message was fully handled (or safely discarded)
   * and may be deleted server-side; "skip" leaves it queued for later. */
  private async processEnvelope(envelopeBytes: Uint8Array): Promise<"ack" | "skip"> {
    if (this.identity === null || this.token === null || !this.store.isUnlocked()) {
      return "skip";
    }
    const epoch = this.epoch;
    const lookup = await this.buildPrekeyLookup();
    if (this.epoch !== epoch || this.identity === null) {
      return "skip"; // locked out / wiped while reading prekeys
    }
    const result = respondKx(this.identity.pub, lookup, envelopeBytes);
    if (!result.ok) {
      if (result.reason === "bad-signature") {
        this.renderer.event(
          "security",
          "received a message with an INVALID identity signature - discarded",
        );
      } else {
        this.renderer.event("failure", `discarded undecryptable message (${result.reason})`);
      }
      return "ack";
    }

    // §3.7: the consumed OPK secret is deleted immediately.
    if (result.consumedOpkStoreKey !== null) {
      await this.store.deleteKey(result.consumedOpkStoreKey);
    }

    let senderUid: string | null = null;
    let text: string | null = null;
    try {
      const parsed: unknown = JSON.parse(new TextDecoder().decode(result.plaintext));
      if (typeof parsed === "object" && parsed !== null) {
        const record = parsed as { u?: unknown; m?: unknown };
        senderUid = typeof record.u === "string" ? normalizeUid(record.u) : null;
        text = typeof record.m === "string" ? record.m : null;
      }
    } catch {
      // fall through to the discard below
    }
    if (senderUid === null || text === null) {
      this.renderer.event("failure", "discarded message with malformed payload");
      return "ack";
    }

    const senderIkB64 = toBase64(result.senderIk);
    const timestamp = this.now();
    if (this.epoch !== epoch) {
      return "skip"; // torn down while decrypting; leave queued server-side
    }
    const contact = this.findContactByUid(senderUid);

    if (contact !== null) {
      if (contact.ik !== null && contact.ik !== senderIkB64) {
        await this.handleKeyChange(contact, senderIkB64);
        this.renderer.event(
          "security",
          `message claiming to be ${contact.alias} used the new (unconfirmed) key - DISCARDED`,
        );
        return "ack";
      }
      if (contact.ik === null) {
        this.contacts.set(contact.alias, { ...contact, ik: senderIkB64 });
        await this.saveContacts();
      }
      await this.store.putJson(`session/${senderUid}`, serializeSession(result.session, timestamp));
      await this.store.putJson(`msg/${senderUid}/${timestamp}`, {
        dir: "in",
        text,
        ts: timestamp,
      });
      this.renderer.plain(`  [${contact.alias}] ${text}`);
      if (result.session.reducedFs) {
        this.renderer.event("warning", "session has reduced forward secrecy (no one-time prekey)");
      }
      return "ack";
    }

    // Unknown sender: bind the claimed UID to the envelope's identity key
    // via a non-consuming bundle fetch before holding it as a request.
    try {
      const senderWire = await api.fetchBundle(this.token, senderUid, false);
      if (this.epoch !== epoch) {
        return "skip";
      }
      if (senderWire.ik_pub !== senderIkB64) {
        this.renderer.event(
          "security",
          "sender identity does not match its claimed UID - message DISCARDED",
        );
        return "ack";
      }
    } catch {
      if (this.epoch !== epoch) {
        return "skip";
      }
      this.renderer.event("failure", "could not verify sender identity - message discarded");
      return "ack";
    }
    const pending: PendingRequest = {
      text,
      session: serializeSession(result.session, timestamp),
      senderIk: senderIkB64,
      receivedAt: timestamp,
    };
    await this.store.putJson(`pending/${senderUid}`, pending);
    this.renderer.event(
      "warning",
      `new contact request from ${formatUid(senderUid)} - /add ${senderUid} [alias] to accept`,
    );
    return "ack";
  }

  private async drainInbox(): Promise<void> {
    if (this.token === null) {
      return;
    }
    const inbox = await api.fetchMessages(this.token);
    const acks: number[] = [];
    for (const message of inbox.messages) {
      let envelope: Uint8Array;
      try {
        envelope = fromBase64(message.envelope);
      } catch {
        acks.push(message.id); // not even base64: drop
        continue;
      }
      if ((await this.processEnvelope(envelope)) === "ack") {
        acks.push(message.id);
      }
    }
    if (acks.length > 0 && this.token !== null) {
      await api.ackMessages(this.token, acks);
    }
  }

  private connectWs(): void {
    if (typeof WebSocket === "undefined" || typeof location === "undefined") {
      return; // non-browser environment (tests)
    }
    this.ws?.close(); // never leak a previous socket across re-logins
    this.ws = new WsClient();
    this.ws.connect(this.token ?? "", {
      onToken: (token) => {
        // Rotation on WS connect (§2.3): adopt the fresh token everywhere.
        this.token = token;
      },
      onEnvelope: (id, envelope) => {
        this.rxTail = this.rxTail
          .then(async () => {
            if ((await this.processEnvelope(envelope)) === "ack") {
              this.ws?.ack([id]);
            }
          })
          .catch(() => {
            this.renderer.event("failure", "failed to process an incoming message");
          });
      },
      onClose: (intentional) => {
        if (!intentional) {
          this.renderer.event("warning", "live delivery disconnected - /login to reconnect");
        }
      },
    });
  }

  // ----- identity & key store flows (W2) ------------------------------------

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
    if (!secretStringsEqual(first, second)) {
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
    this.connectWs();
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
    await this.loadContacts();
    await this.loginWithIdentity();
    await this.postLoginMaintenance();
    await this.drainInbox();
    this.connectWs();
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
    if (secretStringsEqual(current, next)) {
      // Checked locally before anything touches the store: neither value
      // leaves this scope, and the answer reveals nothing the typist does
      // not already know.
      this.renderer.event(
        "warning",
        "the new passphrase is identical to the current one - rotating it changes nothing an attacker would have to guess",
      );
      const answer = await this.shell.readLine("rotate anyway? (y/N): ");
      if (answer === null || !/^y(es)?$/i.test(answer.trim())) {
        this.renderer.event("info", "rotation cancelled - run /rotate passphrase again with a different passphrase");
        return;
      }
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

  private async doSettingsMask(mask: "asterisk" | "hidden"): Promise<void> {
    // Non-secret preference stored unencrypted, so it applies before unlock
    // on the next session's first passphrase prompt too (§ store DisplayPrefs).
    this.shell.setSecretMask(mask);
    await this.store.setDisplayPrefs({ secretMask: mask });
    this.renderer.event(
      "success",
      mask === "hidden"
        ? "passphrase entry hidden - no characters echoed (sudo-style)"
        : "passphrase entry masked with asterisks",
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

function serializeSession(session: KxSession, establishedAt: number): StoredSession {
  return {
    rk: toBase64(session.rk),
    transcript: toBase64(session.transcript),
    peerIk: toBase64(session.peerIk),
    role: session.role,
    reducedFs: session.reducedFs,
    establishedAt,
  };
}

function wireToBundle(wire: api.WireBundle): Bundle {
  return {
    ikPub: fromBase64(wire.ik_pub),
    spkPub: fromBase64(wire.spk_pub),
    spkSig: fromBase64(wire.spk_sig),
    opk:
      wire.opk === null
        ? null
        : {
            pub: fromBase64(wire.opk.pub),
            index: wire.opk.index,
            leaves: wire.opk.leaf_hashes.map(fromBase64),
            rootSig: fromBase64(wire.opk.root_sig),
          },
  };
}
