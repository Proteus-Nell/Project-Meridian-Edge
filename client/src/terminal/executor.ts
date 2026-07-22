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
import { initRatchet, ratchetDecrypt, ratchetEncrypt } from "../crypto/ratchet";
import type { RatchetState } from "../crypto/ratchet";
import { decodeMsgEnvelope, encodeMsgEnvelope, envelopeType, ENVELOPE_TYPE_MSG } from "../crypto/envelope";
import { computeSafetyNumber, formatSafetyNumber } from "../crypto/safetynumber";
import { KeyStore, StoreLockedError } from "../crypto/store";
import type { ThemePrefs } from "../crypto/store";
import { resolveScheme } from "./theme";
import type { ColorSlot, EmblemName, ResolvedScheme, SchemeName } from "./theme";
import {
  AUTO_LOCK_MS,
  MAX_PAYLOAD_BYTES,
  OPK_BATCH_MAX,
  OPK_LOW_WATERMARK,
  SPK_RETENTION_DAYS,
  SPK_ROTATION_DAYS,
} from "../crypto/constants";
import { fromBase64, toBase64 } from "../util/base64";
import { secretStringsEqual } from "../util/secret";
import type { Command, DeleteScope, Duration, DurationUnit, ParseResult, ThemeElement, Weekday } from "./parser";
import { COMMAND_USAGE, formatUid, normalizeUid } from "./parser";
import { renderCommandHelp, renderHelp } from "./help";
import type { EventLevel, Renderer } from "./renderer";
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
  /** Mutual disappearing-message timer in seconds; null = off (§5.2). Shared
   * with the peer over the encrypted ratchet payload, last-writer-wins. */
  readonly timerSeconds: number | null;
}

interface PartialContact {
  uid: string;
  alias: string;
  ik?: string | null | undefined;
  verified?: boolean | undefined;
  keyChangeBlocked?: boolean | undefined;
  timerSeconds?: number | null | undefined;
}

function normalizeContact(c: PartialContact): Contact {
  return {
    uid: c.uid,
    alias: c.alias,
    ik: c.ik ?? null,
    verified: c.verified ?? false,
    keyChangeBlocked: c.keyChangeBlocked ?? false,
    timerSeconds: c.timerSeconds ?? null,
  };
}

const DURATION_UNIT_SECONDS: Record<DurationUnit, number> = {
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60,
  w: 7 * 24 * 60 * 60,
};

/** Parsed duration → seconds; null for "off" (§5.2/§5.3). */
function durationToSeconds(duration: Duration): number | null {
  return duration.kind === "off" ? null : duration.amount * DURATION_UNIT_SECONDS[duration.unit];
}

/** Compact human label for a whole-unit second count (e.g. 3600 → "1h"). */
function formatDuration(seconds: number): string {
  for (const unit of ["w", "d", "h", "m"] as const) {
    const size = DURATION_UNIT_SECONDS[unit];
    if (seconds % size === 0) {
      return `${seconds / size}${unit}`;
    }
  }
  return `${seconds}s`;
}

/** A locally stored message record. Written on send and on receive; never read
 * back for display (messages render live), so this is purely at-rest history
 * subject to the disappearing timer and local purge (§5.1-5.3). */
interface StoredMessage {
  readonly dir: "in" | "out";
  readonly text: string;
  readonly ts: number;
  /** Absolute epoch-ms deletion deadline from the mutual timer, if any (§5.2). */
  readonly tmrExpiresAt?: number;
  /** Shared per-message id (random 128-bit hex), carried in the encrypted
   * payload so a cooperative `/delete` can name it on both sides (§5.3a).
   * Absent on legacy records (they predate `/delete`) - those can still be
   * deleted locally, just not signalled to the peer. */
  readonly mid?: string;
}

/** Local retention cap (§5.3): personal, never transmitted, may be stricter
 * than the mutual timer. null = off. */
interface PurgeSettings {
  readonly seconds: number | null;
}

/** The encrypted ratchet payload (§4 body). Carries the message text and the
 * sender's current mutual-timer view so a `/timer` change propagates and both
 * sides converge last-writer-wins. A pure timer-control message has no text.
 * It can also carry `mid` (this message's shared id) and/or a cooperative
 * deletion directive (`deletes`: peer-side message ids to remove; `deleteSilent`:
 * suppress the peer-side notice) — see §5.3a and doDelete. */
interface AppPayload {
  readonly text: string | null;
  readonly timerSeconds: number | null;
  readonly mid: string | null;
  readonly deletes: readonly string[] | null;
  readonly deleteSilent: boolean;
}

function encodeAppPayload(payload: AppPayload): Uint8Array {
  const record: { m?: string; tmr: number; id?: string; del?: readonly string[]; ds?: boolean } = {
    tmr: payload.timerSeconds ?? 0,
  };
  if (payload.text !== null) {
    record.m = payload.text;
  }
  if (payload.mid !== null) {
    record.id = payload.mid;
  }
  if (payload.deletes !== null && payload.deletes.length > 0) {
    record.del = payload.deletes;
    if (payload.deleteSilent) {
      record.ds = true;
    }
  }
  return new TextEncoder().encode(JSON.stringify(record));
}

function decodeAppPayload(bytes: Uint8Array): AppPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const record = parsed as { m?: unknown; tmr?: unknown; id?: unknown; del?: unknown; ds?: unknown };
  const text = typeof record.m === "string" ? record.m : null;
  const tmr = typeof record.tmr === "number" && record.tmr > 0 ? record.tmr : null;
  const mid = typeof record.id === "string" ? record.id : null;
  const deletes =
    Array.isArray(record.del) && record.del.every((x) => typeof x === "string")
      ? (record.del as string[])
      : null;
  return { text, timerSeconds: tmr, mid, deletes, deleteSilent: record.ds === true };
}

/** Serialized KEM double-ratchet state (§4.4). All key material base64; the
 * skipped-key cache is a list of [chainId:n, base64 mk] pairs. */
interface StoredRatchet {
  readonly role: "initiator" | "responder";
  readonly rk: string;
  readonly cks: string;
  readonly ckr: string | null;
  readonly ns: number;
  readonly nr: number;
  readonly pn: number;
  readonly lastAction: "send" | "recv";
  readonly hks: string;
  readonly hkr: string;
  readonly nhkr: string | null;
  readonly sendKemSk: string | null;
  readonly sendKemPk: string | null;
  readonly peerKemPk: string | null;
  readonly sinceOffer: number;
  readonly recvChainId: number;
  readonly skipped: readonly (readonly [string, string])[];
}

interface StoredSession {
  readonly ratchet: StoredRatchet;
  readonly peerIk: string;
  readonly reducedFs: boolean;
  readonly establishedAt: number;
}

interface PendingRequest {
  readonly text: string;
  readonly session: StoredSession;
  readonly senderIk: string;
  readonly receivedAt: number;
  /** Shared id of the held first message, if it carried one (§5.3a). */
  readonly mid?: string | null;
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
  "settings-notify": "W6 (could-have)",
};

/** Animation state of the background emblem medallion: paused when idle
 * (locked / logged out), slowly spinning while a session is live, fast spin +
 * pulse while something awaits the user's acknowledgement (an unacked
 * key-change block or a held contact request — an unread notification). */
export type EmblemState = "idle" | "active" | "alert";

/** The UI surface the executor drives, implemented by terminal/chrome.ts in the
 * browser: right-edge ✓/✗ delivery ticks, the /clr screen wipe, the persistent
 * chat-context segment of the status strip (spec §1.5), the toggleable
 * atmosphere layers, and the medallion animation state. A null-object default
 * keeps the executor fully testable headless (no DOM), so existing tests
 * construct it without a chrome. */
export interface UiChrome {
  echoInput(line: string, kind?: "command" | "message"): void;
  confirmSent(): void;
  rejectSent(): void;
  clearScreen(announce?: boolean): void;
  setChatContext(text: string | null): void;
  applyTheme(theme: ThemePrefs): void;
  setEmblemState(state: EmblemState): void;
  applyScheme(scheme: ResolvedScheme): void;
  applyEmblem(name: EmblemName): void;
}

/** Which screen the transcript is showing — the home dashboard or a specific
 * conversation. Tracked so /return can toggle back to the previous one. */
type ViewRef = { readonly kind: "home" } | { readonly kind: "chat"; readonly uid: string };

const NULL_CHROME: UiChrome = {
  echoInput() {},
  confirmSent() {},
  rejectSent() {},
  clearScreen() {},
  setChatContext() {},
  applyTheme() {},
  setEmblemState() {},
  applyScheme() {},
  applyEmblem() {},
};

export class Executor {
  private readonly store: KeyStore;
  private identity: Identity | null = null;
  private token: string | null = null;
  private contacts = new Map<string, Contact>(); // key: alias
  /** The conversation the terminal is focused on (§1.5). null = the home view
   * (the dashboard of all conversations). Setting it via /chat switches the
   * transcript to that one conversation; /home clears it back to the dashboard. */
  private active: Contact | null = null;
  /** Per-contact (by uid) count of messages that arrived while their
   * conversation was not the focused view — surfaced on the home dashboard and
   * as a status-strip notice, cleared when you /chat them. In-memory only. */
  private unread = new Map<string, number>();
  /** The screen the transcript showed before the current one, so /return can
   * toggle back to it (and state where it went). In-memory only. */
  private previousView: ViewRef | null = null;
  private busy = false;
  /** Trust-on-first-use mode (§4.6a, /settings trust). When on (default), the
   * first identity key seen for a contact is auto-pinned and auto-marked
   * verified, and a later key change is auto-re-pinned (loudly warned, dropped to
   * UNVERIFIED) instead of blocking behind /ack. When off, verification is manual
   * (/verify + /verified) and a key change blocks until /ack. Loaded from the
   * encrypted store on login; defaults on until then. */
  private autoTrust = true;
  private wipeRequestedAt = 0;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private ws: WsClient | null = null;
  private rxTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly renderer: Renderer,
    private readonly shell: ShellIO,
    store?: KeyStore,
    private readonly now: () => number = () => Date.now(),
    private readonly chrome: UiChrome = NULL_CHROME,
  ) {
    this.store = store ?? new KeyStore();
  }

  /** Apply persisted display preferences before the first prompt. Safe to
   * call with no store yet (returns defaults). Best-effort: a read failure
   * just leaves the default masking and theme in place. */
  async init(): Promise<void> {
    try {
      const prefs = await this.store.getDisplayPrefs();
      this.shell.setSecretMask(prefs.secretMask);
      this.chrome.applyTheme(prefs.theme);
      this.chrome.applyScheme(resolveScheme(prefs.scheme, prefs.colorOverrides));
      this.chrome.applyEmblem(prefs.emblemGlyph);
    } catch {
      // ignore: defaults remain
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
          // A usage string may enumerate several forms joined by "  |  " (e.g.
          // /settings). Dumping them on one line is unreadable, so split and
          // print one form per line; single-form usages stay inline.
          const forms = result.usage.split("  |  ");
          if (forms.length > 1) {
            this.renderer.plain("    usage:");
            for (const form of forms) {
              this.renderer.plain(`      ${form}`);
            }
          } else {
            this.renderer.plain(`    usage: ${result.usage}`);
          }
        }
        if (result.suggestion !== undefined) {
          this.renderer.event("info", `did you mean ${result.suggestion}?`);
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
    this.run(() => this.sendActiveMessage(target, text));
  }

  /** Send one already-echoed outgoing message to `target`, then mark that row
   * delivered (✓) or failed (✗) with a status line on success. Does NOT wrap
   * its own run()/echo, so a caller can sequence it after other work inside a
   * single task — used both by a plain typed message (echoed in main.ts) and by
   * the `/chat <target> <message>` inline form (which echoes it after the view
   * switch). */
  private async sendActiveMessage(target: Contact, text: string): Promise<void> {
    let sent = false;
    try {
      sent = await this.sendFirstMessage(target, text);
    } catch (err) {
      // A thrown send (e.g. network) still marks the echoed line failed; the
      // specific reason is logged by reportError in run()'s catch.
      this.chrome.rejectSent();
      throw err;
    }
    if (sent) {
      this.chrome.confirmSent();
      this.renderer.status("success", `sent to ${target.alias}`);
    } else {
      // A graceful non-send already explained itself on the transcript/status.
      this.chrome.rejectSent();
    }
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
      case "settings-trust":
        this.run(() => this.doSettingsTrust(cmd.mode));
        return;
      case "settings-theme":
        this.run(() => this.doSettingsTheme(cmd.element, cmd.enabled));
        return;
      case "settings-scheme":
        this.run(() => this.doSettingsScheme(cmd.scheme));
        return;
      case "settings-emblem":
        this.run(() => this.doSettingsEmblem(cmd.emblem));
        return;
      case "settings-color":
        this.run(() => this.doSettingsColor(cmd.slot, cmd.hex));
        return;
      case "settings-color-reset":
        this.run(() => this.doSettingsColorReset());
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
        const previousBeforeChat = this.currentViewRef();
        if (previousBeforeChat.kind !== "chat" || previousBeforeChat.uid !== contact.uid) {
          this.previousView = previousBeforeChat; // remember where we came from for /return
        }
        this.active = contact;
        this.unread.delete(contact.uid); // opening the conversation clears its unread mark
        const trust = contact.verified ? "verified" : "UNVERIFIED";
        this.renderer.event("info", `chatting with: ${contact.alias} (${trust})`);
        if (contact.keyChangeBlocked) {
          this.renderer.event(
            "security",
            `identity key for ${contact.alias} changed and is UNACKNOWLEDGED - sending is blocked. /ack ${contact.alias}, then /verify + /verified to resume.`,
          );
        }
        this.shell.setPrompt(`[${contact.alias}] > `);
        this.refreshChatContext();
        if (cmd.message === undefined) {
          // Switch the transcript to the focused conversation view: only this
          // conversation's history, everything else hidden but retained
          // (reachable via /home). Runs on the render lane so a message typed
          // right after /chat is not blocked by the redraw.
          this.enqueueRender(() => this.renderActiveConversation());
          return;
        }
        // `/chat <target> <message>`: switch to the focused view, then echo and
        // send the inline message so it lands at the bottom exactly like /chat
        // followed by a typed message. Sequenced in one task (render → echo →
        // send) so the ✓/✗ tick pins to the echoed row. The send still flows
        // through sendFirstMessage, so a key-change block, unverified state,
        // disappearing timers and the ratchet all behave identically.
        const inlineMessage = cmd.message;
        this.run(async () => {
          await this.renderActiveConversation();
          this.chrome.echoInput(inlineMessage, "message");
          await this.sendActiveMessage(contact, inlineMessage);
        });
        return;
      }
      case "home": {
        const previousBeforeHome = this.currentViewRef();
        if (previousBeforeHome.kind !== "home") {
          this.previousView = previousBeforeHome; // remember where we came from for /return
        }
        this.active = null;
        this.shell.setPrompt("> ");
        this.refreshChatContext(); // clears the §1.5 context line
        this.enqueueRender(() => this.renderHome());
        return;
      }
      case "return":
        this.returnToPreviousView();
        return;
      case "contacts":
        this.run(() => this.doContacts());
        return;
      case "ack":
        this.run(() => this.doAck(cmd.alias));
        return;
      case "timer":
        this.run(() => this.doTimer(cmd.alias, cmd.duration));
        return;
      case "purge-set":
        this.run(() => this.doPurgeSet(cmd.duration));
        return;
      case "purge-now":
        this.run(() => this.doPurgeNow(cmd.alias));
        return;
      case "delete":
        this.run(() => this.doDelete(cmd.scope, cmd.silent));
        return;
      case "bench":
        this.run(() => this.doBench(cmd.suite));
        return;
      case "clr":
        this.chrome.clearScreen();
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
  /** A lane separate from the command `tail` for cosmetic view rebuilds
   * (renderActiveConversation / renderHome). Kept apart so enqueuing a redraw
   * never trips the `busy` guard — a redraw scheduled by /chat must not make an
   * immediately-following message report "another operation is in progress". */
  private renderTail: Promise<void> = Promise.resolve();

  /** Queue a view rebuild on the render lane. Failures are swallowed: a redraw
   * is cosmetic and must never surface as an operation error. */
  private enqueueRender(fn: () => Promise<void>): void {
    this.renderTail = this.renderTail.then(fn).catch(() => {});
  }

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

  /** Resolves when both lanes are quiescent: the in-flight async command (if
   * any) and any view rebuild it scheduled on the render lane. Loops until
   * neither lane advanced across a settle, so tests can await the full effect of
   * a command including its redraw. Capped so it can never spin forever. */
  async idle(): Promise<void> {
    for (let i = 0; i < 8; i += 1) {
      const t = this.tail;
      const r = this.renderTail;
      await t.catch(() => {});
      await r.catch(() => {});
      if (t === this.tail && r === this.renderTail) {
        return;
      }
    }
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
    // The conversation context is stale once locked (contacts reload on the
    // next /login, which refreshes it); clear the display, keep this.active so
    // an unlocked session resumes where it was.
    this.unread.clear();
    this.previousView = null;
    this.chrome.setChatContext(null);
    this.chrome.setEmblemState("idle");
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

  /** Load the trust-on-first-use mode from the encrypted store (defaults on). */
  private async loadTrustMode(): Promise<void> {
    const stored = await this.store.getJson<{ auto: boolean }>("settings/trust");
    this.autoTrust = stored?.auto ?? true;
  }

  /** Pin a contact's identity key, adopting it as verified when trust-on-first-use
   * is on (§4.6a). Returns the updated Contact; the caller persists it. */
  private pinKey(contact: Contact, ikB64: string): Contact {
    return { ...contact, ik: ikB64, verified: this.autoTrust ? true : contact.verified };
  }

  private resolveContact(target: string): Contact | null {
    return this.contacts.get(target) ?? this.findContactByUid(normalizeUid(target) ?? "");
  }

  /** Recompute the medallion animation state: idle without a live unlocked
   * session, alert while anything awaits acknowledgement (a key-change-blocked
   * contact or a held contact request), active otherwise. Best-effort — a
   * store read failing mid-teardown just leaves the previous state. */
  private async refreshEmblemState(): Promise<void> {
    if (this.token === null || !this.store.isUnlocked()) {
      this.chrome.setEmblemState("idle");
      return;
    }
    let alert = [...this.contacts.values()].some((c) => c.keyChangeBlocked);
    if (!alert) {
      try {
        alert = (await this.store.listKeys("pending/")).length > 0;
      } catch {
        // locked mid-check: the next lock/login transition will correct it
      }
    }
    this.chrome.setEmblemState(alert ? "alert" : "active");
  }

  /** Recompute the persistent status-strip context for the active conversation
   * (spec §1.5): `[chatting with: alias (verified|UNVERIFIED)] [timer: 1h]`.
   * Re-resolves from the contacts map so trust/timer mutations are reflected;
   * call after any state change that could alter it. */
  private refreshChatContext(): void {
    if (this.active === null) {
      this.chrome.setChatContext(null);
      return;
    }
    const contact = this.findContactByUid(this.active.uid) ?? this.active;
    const trust = contact.verified ? "verified" : "UNVERIFIED";
    const timer =
      contact.timerSeconds === null ? "" : ` [timer: ${formatDuration(contact.timerSeconds)}]`;
    this.chrome.setChatContext(`[chatting with: ${contact.alias} (${trust})]${timer}`);
  }

  /** The screen currently on the transcript: home when nothing is focused, else
   * the focused conversation (by uid). */
  private currentViewRef(): ViewRef {
    return this.active === null ? { kind: "home" } : { kind: "chat", uid: this.active.uid };
  }

  /** `/return`: toggle back to the screen shown before the current one, naming
   * where it went. The two screens swap each call, so /return alternates like a
   * back/forward button. Falls back to home if the remembered conversation's
   * contact is gone (removed or wiped). */
  private returnToPreviousView(): void {
    if (this.previousView === null) {
      this.renderer.event("info", "no previous screen to return to");
      return;
    }
    const current = this.currentViewRef();
    const target = this.previousView;
    this.previousView = current; // swap so a second /return comes back here
    if (target.kind === "home") {
      this.active = null;
      this.shell.setPrompt("> ");
      this.refreshChatContext();
      this.renderer.event("info", "returned to home");
      this.enqueueRender(() => this.renderHome());
      return;
    }
    const contact = this.findContactByUid(target.uid);
    if (contact === null) {
      this.active = null;
      this.previousView = null;
      this.shell.setPrompt("> ");
      this.refreshChatContext();
      this.renderer.event("warning", "that conversation is no longer available - returned to home");
      this.enqueueRender(() => this.renderHome());
      return;
    }
    this.active = contact;
    this.unread.delete(contact.uid);
    this.shell.setPrompt(`[${contact.alias}] > `);
    this.refreshChatContext();
    this.renderer.event("info", `returned to the conversation with ${contact.alias}`);
    this.enqueueRender(() => this.renderActiveConversation());
  }

  /** `/contacts`: list every saved contact with its alias, full UID, and trust
   * state, plus any saved contact-request UIDs still awaiting /add. A plain
   * informational listing (like /keys status) — it does not switch views. */
  private async doContacts(): Promise<void> {
    if (!this.store.isUnlocked()) {
      this.renderer.event("warning", "contacts live in the encrypted store - /login first");
      return;
    }
    const contacts = [...this.contacts.values()].sort((a, b) => a.alias.localeCompare(b.alias));
    if (contacts.length === 0) {
      this.renderer.event("info", "no contacts yet - /add <uid> [alias] to add one");
    } else {
      this.renderer.event("info", `contacts (${contacts.length}):`);
      const width = Math.max(...contacts.map((c) => c.alias.length));
      for (const contact of contacts) {
        const flags = [
          contact.verified ? "verified" : "UNVERIFIED",
          contact.keyChangeBlocked ? "KEY CHANGED — /ack" : "",
          contact.timerSeconds === null ? "" : `timer ${formatDuration(contact.timerSeconds)}`,
        ]
          .filter((s) => s.length > 0)
          .join(" · ");
        this.renderer.plain(`  ${contact.alias.padEnd(width)}  ${formatUid(contact.uid)}  ${flags}`);
      }
    }
    const pending = await this.store.listKeys("pending/");
    if (pending.length > 0) {
      this.renderer.event("info", `contact requests (${pending.length}) - /add to accept:`);
      for (const key of pending) {
        const uid = key.slice("pending/".length);
        this.renderer.plain(`  ${formatUid(uid)}`);
      }
    }
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
      await this.recordMessage(uid, "in", pending.text, pending.receivedAt, pending.mid ?? null);
      await this.store.deleteKey(`pending/${uid}`);
      this.contacts.set(name, this.pinKey(contact, pending.senderIk));
      await this.saveContacts();
      await this.refreshEmblemState(); // the held request is resolved
      this.renderer.event("success", `added contact ${name} (${formatUid(uid)})`);
      this.renderer.peerMessage(name, pending.text);
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
      // Auto-trust re-pins and lets /verify continue to the new safety number;
      // manual trust blocks here until /ack.
      if (!(await this.handleKeyChange(contact, bundleIk))) {
        return;
      }
    } else if (contact.ik === null) {
      this.contacts.set(contact.alias, this.pinKey(contact, bundleIk));
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
    this.refreshChatContext();
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
    this.refreshChatContext();
    await this.refreshEmblemState();
    this.renderer.event(
      "success",
      `acknowledged - ${contact.alias} remains UNVERIFIED; /verify then /verified to confirm the new key before sending`,
    );
  }

  /** Identity-key change detected for `contact` (§4.6): adopt the new key so the
   * safety number and future traffic reflect reality, and tear down any
   * established session so old chain keys cannot carry over. Manual trust marks
   * the contact UNVERIFIED and BLOCKED (returns false — the caller must abort the
   * action until /ack). Trust-on-first-use auto-re-pins, drops to UNVERIFIED but
   * does NOT block (returns true — the caller may proceed), and warns loudly so a
   * possible MITM is still visible. Either way a high-visibility event fires. */
  private async handleKeyChange(contact: Contact, newIkB64: string): Promise<boolean> {
    const blocked = !this.autoTrust;
    const updated: Contact = {
      ...contact,
      ik: newIkB64,
      verified: false,
      keyChangeBlocked: blocked,
    };
    this.contacts.set(contact.alias, updated);
    await this.saveContacts();
    await this.store.deleteKey(`session/${contact.uid}`);
    this.refreshChatContext();
    await this.refreshEmblemState();
    this.renderer.event(
      "security",
      blocked
        ? `IDENTITY KEY CHANGED for ${contact.alias} - this conversation is now blocked and marked UNVERIFIED. /ack ${contact.alias} to acknowledge, then /verify + /verified to confirm the new key before sending.`
        : `IDENTITY KEY CHANGED for ${contact.alias} - the new key was auto-accepted (trust-on-first-use) and the session reset; ${contact.alias} is now UNVERIFIED. If you did not expect this, treat it as a possible server MITM: /verify ${contact.alias} to compare the new safety number, or /settings trust manual to block on future changes.`,
    );
    return !blocked;
  }

  // ----- send (PQ-KX first message, §3) -------------------------------------

  private async sendFirstMessage(target: Contact, text: string): Promise<boolean> {
    if (this.identity === null || this.token === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return false;
    }
    if (target.keyChangeBlocked) {
      this.renderer.event(
        "security",
        `sending to ${target.alias} is blocked: an unacknowledged identity-key change was detected. /ack ${target.alias}, then /verify + /verified to resume.`,
      );
      return false;
    }
    const existing = await this.store.getJson<StoredSession>(`session/${target.uid}`);
    if (existing !== null) {
      // Session established: every message after the PQ-KX first one rides the
      // KEM double-ratchet (§4).
      return this.sendRatchetMessage(target, existing, text);
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
        return false;
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
      return false;
    }
    const bundleIk = toBase64(bundle.ikPub);
    if (target.ik !== null && target.ik !== bundleIk) {
      // Manual trust blocks the send; auto-trust re-pins and lets it proceed on
      // the new (freshly fetched) key after the loud warning.
      if (!(await this.handleKeyChange(target, bundleIk))) {
        return false;
      }
      target = this.findContactByUid(target.uid) ?? target;
    }

    const mid = this.newMessageId();
    const payload = new TextEncoder().encode(
      JSON.stringify({ u: this.identity.uid, m: text, id: mid }),
    );
    const { envelope, session } = initiateKx(this.identity.pub, this.identity.sec, bundle, payload);
    await api.sendMessage(this.token, target.uid, envelope);

    const timestamp = this.now();
    await this.store.putJson(`session/${target.uid}`, serializeSession(session, timestamp));
    await this.recordMessage(target.uid, "out", text, timestamp, mid);
    if (target.ik === null) {
      this.contacts.set(target.alias, this.pinKey(target, bundleIk));
      await this.saveContacts();
    }
    // The delivery tick + "sent to" status are raised by the caller
    // (handleMessage); the once-per-conversation handshake milestone still gets
    // a transcript line since it is not per-message noise.
    this.renderer.event("info", `PQ-KX handshake established with ${target.alias}`);
    if (session.reducedFs) {
      this.renderer.event(
        "warning",
        "reduced forward secrecy: recipient had no one-time prekeys left (§7.4) - heals with the W4 ratchet",
      );
    }
    return true;
  }

  /** Send a subsequent message through the KEM double-ratchet (§4). The ratchet
   * state is advanced, persisted write-ahead (so a failed send never risks key
   * reuse), and only then transmitted. The MSG envelope is opaque: it carries no
   * sender identity, so the recipient locates the session by trial decryption. */
  private async sendRatchetMessage(
    target: Contact,
    stored: StoredSession,
    text: string | null,
    control?: { readonly deletes?: readonly string[]; readonly deleteSilent?: boolean },
  ): Promise<boolean> {
    if (this.token === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return false;
    }
    const ratchet = deserializeRatchet(stored.ratchet);
    // A real message gets a fresh shared id so the peer stores it under the same
    // handle we do and a later /delete can name it on both sides (§5.3a).
    const mid = text !== null ? this.newMessageId() : null;
    // The payload carries the message text (if any) and our current mutual-timer
    // view, so a /timer change propagates to the peer over the encrypted body (§5.2);
    // it can also carry a cooperative deletion directive (control).
    const payload = encodeAppPayload({
      text,
      timerSeconds: target.timerSeconds,
      mid,
      deletes: control?.deletes ?? null,
      deleteSilent: control?.deleteSilent ?? false,
    });
    const body = ratchetEncrypt(ratchet, payload);
    const envelope = encodeMsgEnvelope(body);
    if (envelope.length > MAX_PAYLOAD_BYTES) {
      this.renderer.event("failure", "message too large after encryption - not sent");
      return false;
    }
    // Write-ahead the advanced ratchet before the send (§4.4): the message key is
    // already consumed, so persisting first prevents any reuse if the send fails.
    const timestamp = this.now();
    await this.store.putJson(`session/${target.uid}`, {
      ...stored,
      ratchet: serializeRatchet(ratchet),
    });
    await api.sendMessage(this.token, target.uid, envelope);
    // A real message is recorded at rest; the delivery tick + "sent" status are
    // raised by the caller. A pure timer/delete-control message (text === null)
    // carries no user text, so it neither records nor confirms.
    if (text !== null) {
      await this.recordMessage(target.uid, "out", text, timestamp, mid);
    }
    await this.purgeExpired();
    return true;
  }

  /** Store a message at rest (§5.1), stamping its disappearing-message deadline
   * from the contact's mutual timer if one is set (§5.2). */
  private async recordMessage(
    uid: string,
    dir: "in" | "out",
    text: string,
    ts: number,
    mid: string | null = null,
  ): Promise<void> {
    const timerSeconds = this.findContactByUid(uid)?.timerSeconds ?? null;
    const base: StoredMessage =
      timerSeconds === null
        ? { dir, text, ts }
        : { dir, text, ts, tmrExpiresAt: ts + timerSeconds * 1000 };
    const record: StoredMessage = mid === null ? base : { ...base, mid };
    // Guard against same-millisecond key collisions: two messages sharing a `ts`
    // would map to the same key and the second would silently overwrite the
    // first, leaving /delete unable to remove it and history incomplete. Append
    // a sub-index so every message gets a distinct, order-preserving key.
    // record.ts is left unchanged, so the disappearing-timer math and the
    // ts-sorted display order stay correct.
    let key = `msg/${uid}/${ts}`;
    if ((await this.store.getJson<StoredMessage>(key)) !== null) {
      let n = 1;
      while ((await this.store.getJson<StoredMessage>(`${key}.${n}`)) !== null) {
        n += 1;
      }
      key = `${key}.${n}`;
    }
    await this.store.putJson(key, record);
  }

  /** A fresh shared message id: random 128-bit, hex. Stamped on outgoing
   * messages and echoed to the peer in the payload so `/delete` can reference
   * the same message on both devices. */
  private newMessageId(): string {
    return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  }

  // ----- message lifecycle: disappearing timer & local purge (§5.1-5.3) -----

  /** Adopt a mutual-timer value the peer carried in its payload (last-writer-
   * wins) and announce the change inline, mirroring the sender's own line (§5.2). */
  private async applyIncomingTimer(
    uid: string,
    label: string,
    timerSeconds: number | null,
  ): Promise<void> {
    const contact = this.findContactByUid(uid);
    if (contact === null || contact.timerSeconds === timerSeconds) {
      return;
    }
    this.contacts.set(contact.alias, { ...contact, timerSeconds });
    await this.saveContacts();
    this.refreshChatContext();
    this.renderer.event(
      "info",
      timerSeconds === null
        ? `${label} turned off disappearing messages`
        : `${label} set disappearing messages to ${formatDuration(timerSeconds)}`,
    );
  }

  /** Delete at-rest messages past their mutual-timer deadline or the local
   * retention cap, whichever bites first (§5.2-5.3). Best-effort, on activity. */
  private async purgeExpired(): Promise<void> {
    if (!this.store.isUnlocked()) {
      return;
    }
    const cap = (await this.store.getJson<PurgeSettings>("settings/purge"))?.seconds ?? null;
    const now = this.now();
    for (const msgKey of await this.store.listKeys("msg/")) {
      const record = await this.store.getJson<StoredMessage>(msgKey);
      if (record === null) {
        continue;
      }
      const timerExpired = record.tmrExpiresAt !== undefined && now >= record.tmrExpiresAt;
      const capExpired = cap !== null && now >= record.ts + cap * 1000;
      if (timerExpired || capExpired) {
        await this.store.deleteKey(msgKey);
      }
    }
  }

  private async deleteMessages(prefix: string): Promise<number> {
    const keys = await this.store.listKeys(prefix);
    for (const key of keys) {
      await this.store.deleteKey(key);
    }
    return keys.length;
  }

  /** `/timer <alias> <duration|off>`: set the mutual disappearing timer, announce
   * it locally, and push it to the peer over the ratchet so both sides agree. */
  private async doTimer(alias: string, duration: Duration): Promise<void> {
    if (this.identity === null || this.token === null) {
      this.renderer.event("failure", "not logged in - /login first");
      return;
    }
    const contact = this.resolveContact(alias);
    if (contact === null) {
      this.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
      return;
    }
    const seconds = durationToSeconds(duration);
    const updated: Contact = { ...contact, timerSeconds: seconds };
    this.contacts.set(contact.alias, updated);
    await this.saveContacts();
    this.refreshChatContext();
    this.renderer.event(
      "info",
      seconds === null
        ? `disappearing messages turned off for ${contact.alias} (applies to both sides)`
        : `disappearing messages set to ${formatDuration(seconds)} for ${contact.alias} - applies to both sides, countdown starts on read`,
    );
    if (updated.keyChangeBlocked) {
      this.renderer.event(
        "warning",
        `sending to ${contact.alias} is blocked by an unacknowledged key change - the peer will get this timer once you /ack and resume`,
      );
      return;
    }
    const stored = await this.store.getJson<StoredSession>(`session/${contact.uid}`);
    if (stored === null) {
      this.renderer.event(
        "info",
        "the peer will receive this setting once your conversation is established",
      );
      return;
    }
    await this.sendRatchetMessage(updated, stored, null);
  }

  /** `/purge set <duration|off>`: local retention cap, never transmitted (§5.3). */
  private async doPurgeSet(duration: Duration): Promise<void> {
    if (!this.store.isUnlocked()) {
      this.renderer.event("warning", "locked or not registered - /login or /register");
      return;
    }
    const seconds = durationToSeconds(duration);
    await this.store.putJson("settings/purge", { seconds } satisfies PurgeSettings);
    await this.purgeExpired();
    this.renderer.event(
      "success",
      seconds === null
        ? "local retention cap cleared - at-rest messages kept until the mutual timer or /purge now"
        : `local retention cap set to ${formatDuration(seconds)} - local only, never sent, applied to every conversation`,
    );
  }

  /** `/purge now [alias]`: immediate local deletion of stored messages (§5.3).
   * Best-effort - browser deletion is not forensic erasure (documented). */
  private async doPurgeNow(alias: string | undefined): Promise<void> {
    if (!this.store.isUnlocked()) {
      this.renderer.event("warning", "locked or not registered - /login or /register");
      return;
    }
    if (alias === undefined) {
      const count = await this.deleteMessages("msg/");
      this.renderer.event("success", `purged ${count} stored message(s) across all conversations`);
      return;
    }
    const contact = this.resolveContact(alias);
    if (contact === null) {
      this.renderer.event("failure", `unknown contact: ${alias} - /add <uid> [alias] first`);
      return;
    }
    const count = await this.deleteMessages(`msg/${contact.uid}/`);
    this.renderer.event("success", `purged ${count} stored message(s) with ${contact.alias}`);
  }

  /** `/delete <last|N|all|purge> [/s]`: delete your own (outgoing) messages on
   * BOTH sides (§5.3a). `last`/`N`/`all` scope to the active conversation; `purge`
   * spans every conversation. Each deleted message is removed from local history
   * and, where a live session exists, a delete directive naming its shared id is
   * pushed to the peer over the encrypted ratchet so their copy is removed too.
   * `/s` makes it silent: no confirmation here and no notice on the peer's end.
   *
   * This is cooperative, not forensic: it depends on the peer's client honoring
   * the request, the peer may already have copies or screenshots, and browser
   * deletion is not forensic erasure (§5.4, §7.12). Messages with no live
   * session (or a key-change block) are removed locally but cannot be signalled. */
  private async doDelete(scope: DeleteScope, silent: boolean): Promise<void> {
    const report = (level: EventLevel, text: string): void => {
      if (!silent) {
        this.renderer.event(level, text);
      }
    };
    if (!this.store.isUnlocked()) {
      report("warning", "locked or not registered - /login or /register");
      return;
    }

    let victims: { key: string; uid: string; ts: number; mid: string | null }[];
    let scopeLabel: string;
    if (scope.kind === "purge") {
      victims = await this.collectOwnOutgoing("msg/");
      scopeLabel = "across all conversations";
    } else {
      if (this.active === null) {
        report("warning", "no active conversation - use /chat <alias|uid> first");
        return;
      }
      const contact = this.findContactByUid(this.active.uid) ?? this.active;
      const inChat = (await this.collectOwnOutgoing(`msg/${contact.uid}/`)).sort(
        (a, b) => a.ts - b.ts,
      );
      const limit = scope.kind === "all" ? inChat.length : scope.kind === "last" ? 1 : scope.count;
      victims = inChat.slice(Math.max(0, inChat.length - limit));
      scopeLabel = `with ${contact.alias}`;
    }

    if (victims.length === 0) {
      report("info", `no messages of yours to delete ${scopeLabel}`);
      return;
    }

    // Remove the local copies first, then ask each peer to remove theirs.
    for (const victim of victims) {
      await this.store.deleteKey(victim.key);
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
      if (await this.requestPeerDeletion(uid, mids, silent)) {
        signalled += mids.length;
      }
    }
    unreachable -= signalled;

    // Rebuild the on-screen conversation so the deleted lines actually vanish
    // from view (not just from storage). This runs even for a silent delete:
    // "silent" suppresses the local confirmation line and the peer-side notice
    // (§5.3a), but your OWN deleted messages must still disappear from your OWN
    // screen — leaving them visible is exactly the "didn't delete" symptom. The
    // append-only transcript can only drop a line by clearing and reprinting.
    if (this.active !== null) {
      await this.renderActiveConversation();
    }

    const tail =
      unreachable === 0
        ? "cooperative, not forensic erasure"
        : `${unreachable} could not be signalled to the peer (no live session) - removed locally only; cooperative, not forensic erasure`;
    report("success", `deleted ${victims.length} of your message(s) ${scopeLabel} - ${tail}`);
  }

  /** Gather your outgoing (`dir: "out"`) messages under `prefix`, tagged with the
   * conversation uid (parsed from the `msg/<uid>/<ts>` key) and shared id. Only
   * your own messages are eligible - a peer's incoming lines are never touched. */
  private async collectOwnOutgoing(
    prefix: string,
  ): Promise<{ key: string; uid: string; ts: number; mid: string | null }[]> {
    const out: { key: string; uid: string; ts: number; mid: string | null }[] = [];
    for (const key of await this.store.listKeys(prefix)) {
      const record = await this.store.getJson<StoredMessage>(key);
      if (record === null || record.dir !== "out") {
        continue;
      }
      const uid = key.split("/")[1] ?? "";
      out.push({ key, uid, ts: record.ts, mid: record.mid ?? null });
    }
    return out;
  }

  /** Rebuild the transcript as the focused conversation view: clear the screen
   * and reprint only the active conversation's stored history, oldest first.
   * This is what /chat switches into and what a /delete redraws — so a deleted
   * line actually disappears (xterm is append-only, so removing a specific past
   * line means clearing and reprinting what remains) rather than lingering in an
   * interleaved log. No-op when nothing is active or the store is locked. */
  private async renderActiveConversation(): Promise<void> {
    if (this.active === null || !this.store.isUnlocked()) {
      return;
    }
    const contact = this.findContactByUid(this.active.uid) ?? this.active;
    const records: StoredMessage[] = [];
    for (const key of await this.store.listKeys(`msg/${contact.uid}/`)) {
      const record = await this.store.getJson<StoredMessage>(key);
      if (record !== null) {
        records.push(record);
      }
    }
    records.sort((a, b) => a.ts - b.ts);
    this.chrome.clearScreen(false); // silent wipe before reprinting
    const trust = contact.verified ? "verified" : "UNVERIFIED";
    const timer =
      contact.timerSeconds === null ? "" : ` · timer ${formatDuration(contact.timerSeconds)}`;
    this.renderer.divider(`—— conversation with ${contact.alias} (${trust})${timer} ——`);
    if (records.length === 0) {
      this.renderer.plain("  (no messages yet — type to send the first one · /home to go back)");
    }
    for (const record of records) {
      if (record.dir === "in") {
        this.renderer.peerMessage(contact.alias, record.text);
      } else {
        this.renderer.ownMessage(record.text);
      }
    }
    if (contact.keyChangeBlocked) {
      this.renderer.event(
        "security",
        `sending to ${contact.alias} is blocked by an unacknowledged key change — /ack ${contact.alias}, then /verify + /verified to resume`,
      );
    }
  }

  /** Rebuild the transcript as the home view: the dashboard of every
   * conversation (the "everything else" that /chat hides and /home brings back).
   * Lists contacts with their trust, unread count, timer and any key-change
   * block, plus held contact requests. Falls back to a minimal screen while
   * locked/logged out. No untrusted markup — plain sanitized text only. */
  private async renderHome(): Promise<void> {
    this.chrome.clearScreen(false);
    this.renderer.divider("—— home ——");
    if (this.identity === null || !this.store.isUnlocked()) {
      this.renderer.plain("  locked — /login to unlock, or /register to create an identity");
      return;
    }
    const contacts = [...this.contacts.values()].sort((a, b) => a.alias.localeCompare(b.alias));
    if (contacts.length === 0) {
      this.renderer.plain("  no contacts yet — /add <uid> [alias] to add one");
    } else {
      this.renderer.plain("  contacts:");
      const width = Math.max(...contacts.map((c) => c.alias.length));
      for (const contact of contacts) {
        const unread = this.unread.get(contact.uid) ?? 0;
        const flags = [
          contact.verified ? "verified" : "UNVERIFIED",
          unread > 0 ? `${unread} unread` : "",
          contact.keyChangeBlocked ? "KEY CHANGED — /ack" : "",
          contact.timerSeconds === null ? "" : `timer ${formatDuration(contact.timerSeconds)}`,
        ]
          .filter((s) => s.length > 0)
          .join(" · ");
        this.renderer.plain(`    ${contact.alias.padEnd(width)}  ${flags}`);
      }
    }
    const pending = await this.store.listKeys("pending/");
    if (pending.length > 0) {
      this.renderer.plain("");
      this.renderer.plain("  contact requests:");
      for (const key of pending) {
        const uid = key.slice("pending/".length);
        this.renderer.plain(`    ${formatUid(uid)}  — /add ${uid} [alias] to accept`);
      }
    }
    this.renderer.plain("");
    this.renderer.divider(
      "  /chat <alias> to open a conversation · /contacts for UIDs · /help for commands",
    );
  }

  /** Render an incoming message according to the focused view (§1). When the
   * sender's conversation is the one on screen, append it live. Otherwise keep
   * the current view undisturbed: bump the sender's unread mark and post a
   * status-strip notice, and (only when sitting on the home dashboard) refresh
   * it so the new count shows. Either way the message is already stored. */
  private deliverIncoming(uid: string, label: string, text: string): void {
    if (this.isActiveConversation(uid)) {
      this.renderer.peerMessage(label, text);
      return;
    }
    this.unread.set(uid, (this.unread.get(uid) ?? 0) + 1);
    this.renderer.status("info", `new message from ${label} — /chat ${label} to read`);
    if (this.active === null) {
      this.enqueueRender(() => this.renderHome());
    }
  }

  /** True when `uid` is the conversation currently shown in the status context. */
  private isActiveConversation(uid: string): boolean {
    return this.active !== null && (this.findContactByUid(this.active.uid)?.uid ?? this.active.uid) === uid;
  }

  /** Push a cooperative delete directive to `uid` over the ratchet: the peer
   * removes the named messages they received from us. Returns false (caller
   * treats the ids as unreachable) when there is no live session or the
   * conversation is key-change-blocked. */
  private async requestPeerDeletion(
    uid: string,
    mids: readonly string[],
    silent: boolean,
  ): Promise<boolean> {
    const contact = this.findContactByUid(uid);
    if (contact === null || contact.keyChangeBlocked) {
      return false;
    }
    const stored = await this.store.getJson<StoredSession>(`session/${uid}`);
    if (stored === null) {
      return false;
    }
    return this.sendRatchetMessage(contact, stored, null, { deletes: mids, deleteSilent: silent });
  }

  /** A peer asked us to delete messages they had sent us (§5.3a). Remove the
   * matching incoming records by shared id and, unless the request was silent,
   * announce it inline so the deletion is visible rather than a silent gap. */
  private async applyIncomingDeletion(
    uid: string,
    label: string,
    mids: readonly string[],
    silent: boolean,
  ): Promise<void> {
    const wanted = new Set(mids);
    let removed = 0;
    for (const key of await this.store.listKeys(`msg/${uid}/`)) {
      const record = await this.store.getJson<StoredMessage>(key);
      if (record !== null && record.dir === "in" && record.mid !== undefined && wanted.has(record.mid)) {
        await this.store.deleteKey(key);
        removed += 1;
      }
    }
    // Redraw the conversation so the removed lines actually disappear from view.
    // This runs even for a SILENT request: `/s` suppresses the inline notice
    // below (§5.3a), not the screen's agreement with storage. Skipping it left
    // the peer's transcript showing messages that were already gone from the
    // store — the "delete /s didn't delete for the recipient" symptom, which
    // only showed up when the peer happened to be focused on that conversation.
    if (removed > 0 && this.isActiveConversation(uid)) {
      await this.renderActiveConversation();
    }
    if (!silent && removed > 0) {
      // Note who deleted them, just below the rebuilt history.
      this.renderer.event(
        "info",
        `${label} deleted ${removed} message(s) they had sent - removed from your history`,
      );
    }
  }

  // ----- benchmarks (§8) ----------------------------------------------------

  /** `/bench [suite]`: run the PQC-vs-classical benchmark suites (B1-B3) in the
   * browser and print the tables. The whole bench module - including its
   * classical baseline primitives - is dynamically imported so it only loads on
   * demand and never enters the main bundle (keeps the B5 delta honest). */
  private async doBench(suite: string | undefined): Promise<void> {
    const bench = await import("../bench/index");
    const parsed = bench.parseSuite(suite);
    if (parsed === null) {
      this.renderer.event("failure", "unknown suite - use b1, b2, b3, or omit for all");
      return;
    }
    this.renderer.event(
      "info",
      "running benchmarks (PQC vs classical primitives) - primitive latency takes a few seconds...",
    );
    const output = await bench.runBench(parsed, {
      onProgress: (message) => this.renderer.event("info", message),
    });
    for (const line of output.terminalLines) {
      this.renderer.plain(line);
    }
    // The full machine-readable report goes to the browser console for the
    // researcher to capture (the terminal shows the human-readable tables).
    if (typeof console !== "undefined") {
      console.log(output.markdown);
      console.log(output.json);
    }
    this.renderer.event("success", "benchmark complete - JSON + Markdown logged to the browser console");
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
    // A ratchet message (§4) routes to the trial-decrypt path; only a KX first
    // message consumes a prekey.
    if (envelopeType(envelopeBytes) === ENVELOPE_TYPE_MSG) {
      return this.processRatchetMessage(envelopeBytes);
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
    let mid: string | null = null;
    try {
      const parsed: unknown = JSON.parse(new TextDecoder().decode(result.plaintext));
      if (typeof parsed === "object" && parsed !== null) {
        const record = parsed as { u?: unknown; m?: unknown; id?: unknown };
        senderUid = typeof record.u === "string" ? normalizeUid(record.u) : null;
        text = typeof record.m === "string" ? record.m : null;
        mid = typeof record.id === "string" ? record.id : null;
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
        // Manual trust discards a message on a changed key and blocks; auto-trust
        // re-pins (loud warning) and accepts the message under the new key.
        if (!(await this.handleKeyChange(contact, senderIkB64))) {
          this.renderer.event(
            "security",
            `message claiming to be ${contact.alias} used the new (unconfirmed) key - DISCARDED`,
          );
          return "ack";
        }
      } else if (contact.ik === null) {
        this.contacts.set(contact.alias, this.pinKey(contact, senderIkB64));
        await this.saveContacts();
      }
      await this.store.putJson(`session/${senderUid}`, serializeSession(result.session, timestamp));
      await this.recordMessage(senderUid, "in", text, timestamp, mid);
      this.deliverIncoming(senderUid, contact.alias, text);
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
      mid,
    };
    await this.store.putJson(`pending/${senderUid}`, pending);
    await this.refreshEmblemState(); // an unread request now awaits /add
    this.renderer.event(
      "warning",
      `new contact request from ${formatUid(senderUid)} - /add ${senderUid} [alias] to accept`,
    );
    return "ack";
  }

  /** Decrypt a ratchet MSG (§4). Since the envelope carries no sender identity,
   * try each established session; the header AEAD authenticates the match and a
   * non-matching session fails without mutating its state. Delivery is idempotent:
   * a replay of an already-consumed message decrypts to nothing and is dropped. */
  private async processRatchetMessage(envelopeBytes: Uint8Array): Promise<"ack" | "skip"> {
    const body = decodeMsgEnvelope(envelopeBytes);
    if (body === null) {
      this.renderer.event("failure", "discarded malformed message");
      return "ack";
    }
    const epoch = this.epoch;
    for (const key of await this.store.listKeys("session/")) {
      if (this.epoch !== epoch || this.identity === null) {
        return "skip"; // locked out / wiped mid-scan
      }
      const stored = await this.store.getJson<StoredSession>(key);
      if (stored === null) {
        continue;
      }
      const ratchet = deserializeRatchet(stored.ratchet);
      const result = ratchetDecrypt(ratchet, body);
      if (!result.ok) {
        continue; // not this session (or an out-of-order/duplicate) - leave it untouched
      }
      const uid = key.slice("session/".length);
      const timestamp = this.now();
      if (this.epoch !== epoch) {
        return "skip"; // torn down while decrypting; leave queued server-side
      }
      await this.store.putJson(key, { ...stored, ratchet: serializeRatchet(ratchet) });
      const payload = decodeAppPayload(result.plaintext);
      if (payload === null) {
        this.renderer.event("failure", "discarded message with malformed payload");
        return "ack";
      }
      const contact = this.findContactByUid(uid);
      const label = contact?.alias ?? formatUid(uid);
      // Adopt a mutual-timer change carried by the peer and announce it (§5.2).
      await this.applyIncomingTimer(uid, label, payload.timerSeconds);
      // Honor a cooperative deletion the peer requested for messages they sent us (§5.3a).
      if (payload.deletes !== null) {
        await this.applyIncomingDeletion(uid, label, payload.deletes, payload.deleteSilent);
      }
      if (payload.text !== null) {
        await this.recordMessage(uid, "in", payload.text, timestamp, payload.mid);
        this.deliverIncoming(uid, label, payload.text);
      }
      await this.purgeExpired();
      return "ack";
    }
    this.renderer.event("failure", "discarded undecryptable message (no matching session)");
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
    await this.refreshEmblemState();
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
    await this.loadTrustMode();
    await this.loginWithIdentity();
    await this.postLoginMaintenance();
    await this.drainInbox();
    await this.purgeExpired(); // evict anything past its timer/cap while offline (§5)
    this.connectWs();
    await this.maybeRotationPrompt();
    this.refreshChatContext(); // restore the §1.5 context line if a chat was active
    await this.refreshEmblemState();
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
    // Read-modify-write so the theme block is preserved.
    this.shell.setSecretMask(mask);
    const prefs = await this.store.getDisplayPrefs();
    await this.store.setDisplayPrefs({ ...prefs, secretMask: mask });
    this.renderer.event(
      "success",
      mask === "hidden"
        ? "passphrase entry hidden - no characters echoed (sudo-style)"
        : "passphrase entry masked with asterisks",
    );
  }

  /** `/settings trust <auto|manual>`: switch trust-on-first-use (§4.6a). Auto
   * (default) pins and verifies a contact's first key automatically and
   * auto-re-pins a later key change with a loud warning instead of blocking on
   * /ack; manual restores the strict flow (/verify + /verified, /ack on change).
   * Stored encrypted since it governs a security posture. */
  private async doSettingsTrust(mode: "auto" | "manual"): Promise<void> {
    if (!this.store.isUnlocked()) {
      this.renderer.event("failure", "store is locked - /login first (trust setting lives encrypted)");
      return;
    }
    this.autoTrust = mode === "auto";
    await this.store.putJson("settings/trust", { auto: this.autoTrust });
    if (this.autoTrust) {
      this.renderer.event(
        "success",
        "trust-on-first-use ON - new contacts are auto-verified, and a key change is auto-accepted with a warning (no /verify, /verified, or /ack needed). Convenient, but it trusts the server not to swap keys; use /settings trust manual for out-of-band verification.",
      );
    } else {
      this.renderer.event(
        "success",
        "manual verification ON - compare safety numbers with /verify + /verified, and a key change blocks until /ack (strongest MITM protection).",
      );
    }
  }

  /** `/settings theme <element|all> <on|off>`: toggle an atmosphere layer.
   * Purely cosmetic, persisted unencrypted (like the mask) so it applies
   * before unlock; works while locked for the same reason. */
  private async doSettingsTheme(element: ThemeElement | "all", enabled: boolean): Promise<void> {
    const prefs = await this.store.getDisplayPrefs();
    const theme: ThemePrefs =
      element === "all"
        ? { emblem: enabled, scanlines: enabled, vignette: enabled, dock: enabled }
        : { ...prefs.theme, [element]: enabled };
    await this.store.setDisplayPrefs({ ...prefs, theme });
    this.chrome.applyTheme(theme);
    this.renderer.event(
      "success",
      element === "all"
        ? `all theme layers turned ${enabled ? "on" : "off"}`
        : `theme layer '${element}' turned ${enabled ? "on" : "off"}`,
    );
  }

  /** `/settings scheme <dark|parchment|olive>`: switch the base palette. Kept
   * with the other cosmetic prefs — unencrypted, applies before unlock. */
  private async doSettingsScheme(scheme: SchemeName): Promise<void> {
    const prefs = await this.store.getDisplayPrefs();
    await this.store.setDisplayPrefs({ ...prefs, scheme });
    this.chrome.applyScheme(resolveScheme(scheme, prefs.colorOverrides));
    this.renderer.event("success", `color scheme set to '${scheme}'`);
  }

  /** `/settings emblem <pq|globe|tree>`: choose the medallion glyph. */
  private async doSettingsEmblem(emblem: EmblemName): Promise<void> {
    const prefs = await this.store.getDisplayPrefs();
    await this.store.setDisplayPrefs({ ...prefs, emblemGlyph: emblem });
    this.chrome.applyEmblem(emblem);
    this.renderer.event("success", `emblem set to '${emblem}'`);
  }

  /** `/settings color <slot> <#rrggbb>`: override one slot of the active
   * scheme with a custom HEX value (the terminal-native color picker). */
  private async doSettingsColor(slot: ColorSlot, hex: string): Promise<void> {
    const prefs = await this.store.getDisplayPrefs();
    const colorOverrides = { ...prefs.colorOverrides, [slot]: hex };
    await this.store.setDisplayPrefs({ ...prefs, colorOverrides });
    this.chrome.applyScheme(resolveScheme(prefs.scheme, colorOverrides));
    this.renderer.event("success", `${slot} set to ${hex} (on the '${prefs.scheme}' scheme)`);
  }

  /** `/settings color reset`: drop all HEX overrides, back to the pure scheme. */
  private async doSettingsColorReset(): Promise<void> {
    const prefs = await this.store.getDisplayPrefs();
    await this.store.setDisplayPrefs({ ...prefs, colorOverrides: {} });
    this.chrome.applyScheme(resolveScheme(prefs.scheme, {}));
    this.renderer.event("success", `custom colors cleared - pure '${prefs.scheme}' scheme restored`);
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
    this.refreshChatContext();
    this.shell.setPrompt("> ");
    this.renderer.event("success", "local store destroyed (browser deletion is not forensic erasure)");
  }

  private printHelp(topic: keyof typeof COMMAND_USAGE | undefined): void {
    const lines = topic !== undefined ? renderCommandHelp(topic) : renderHelp();
    for (const line of lines) {
      this.renderer.plain(line);
    }
  }
}

function serializeRatchet(state: RatchetState): StoredRatchet {
  return {
    role: state.role,
    rk: toBase64(state.rk),
    cks: toBase64(state.cks),
    ckr: state.ckr === null ? null : toBase64(state.ckr),
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    lastAction: state.lastAction,
    hks: toBase64(state.hks),
    hkr: toBase64(state.hkr),
    nhkr: state.nhkr === null ? null : toBase64(state.nhkr),
    sendKemSk: state.sendKemSk === null ? null : toBase64(state.sendKemSk),
    sendKemPk: state.sendKemPk === null ? null : toBase64(state.sendKemPk),
    peerKemPk: state.peerKemPk === null ? null : toBase64(state.peerKemPk),
    sinceOffer: state.sinceOffer,
    recvChainId: state.recvChainId,
    skipped: [...state.skipped].map(([k, v]) => [k, toBase64(v)] as const),
  };
}

function deserializeRatchet(stored: StoredRatchet): RatchetState {
  return {
    role: stored.role,
    rk: fromBase64(stored.rk),
    cks: fromBase64(stored.cks),
    ckr: stored.ckr === null ? null : fromBase64(stored.ckr),
    ns: stored.ns,
    nr: stored.nr,
    pn: stored.pn,
    lastAction: stored.lastAction,
    hks: fromBase64(stored.hks),
    hkr: fromBase64(stored.hkr),
    nhkr: stored.nhkr === null ? null : fromBase64(stored.nhkr),
    sendKemSk: stored.sendKemSk === null ? null : fromBase64(stored.sendKemSk),
    sendKemPk: stored.sendKemPk === null ? null : fromBase64(stored.sendKemPk),
    peerKemPk: stored.peerKemPk === null ? null : fromBase64(stored.peerKemPk),
    sinceOffer: stored.sinceOffer,
    recvChainId: stored.recvChainId,
    skipped: new Map(stored.skipped.map(([k, v]) => [k, fromBase64(v)])),
  };
}

/** Establish a stored session from a completed handshake: initialise the ratchet
 * from RK0 and wipe the handshake's transient root/transcript copy (§4). */
function serializeSession(session: KxSession, establishedAt: number): StoredSession {
  const ratchet = serializeRatchet(initRatchet(session.rk, session.role));
  session.rk.fill(0);
  session.transcript.fill(0);
  return {
    ratchet,
    peerIk: toBase64(session.peerIk),
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
