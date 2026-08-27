// Shared executor context: the UiChrome surface the executor drives, the
// internal-state contract every flow module works against, and the small
// helpers (contact lookup, status refresh) used across modules.
//
// ExecutorInternals is internal to the executor/ package: only the Executor
// class implements it, and nothing outside the package should depend on it.

import type { KeyStore } from "../../crypto/store";
import type { ThemePrefs } from "../../crypto/store";
import type { WsClient } from "../../net/ws";
import { DEFAULT_HELP_COLUMNS } from "../help";
import type { Renderer } from "../renderer";
import type { ShellIO } from "../shell";
import type { AccessibilityPrefs, EmblemName, ResolvedScheme, TextStyle } from "../theme";
import { formatDuration } from "./format";
import { normalizeContact } from "./records";
import type { Contact, Identity } from "./records";
import { loadGroups } from "./groups";
import type { Group } from "./groups";
import { normalizeUid } from "../parser";

/** Animation state of the background emblem medallion: paused when idle
 * (locked / logged out), slowly spinning while a session is live, fast spin
 * plus pulse while something awaits the user's acknowledgement (an unacked
 * key-change block or a held contact request). */
export type EmblemState = "idle" | "active" | "alert";

/** The UI surface the executor drives, implemented by terminal/chrome.ts in
 * the browser: right-edge delivery ticks, the /clr screen wipe, the
 * persistent chat-context segment of the status strip, the
 * toggleable atmosphere layers, and the medallion animation state. A
 * null-object default keeps the executor fully testable headless (no DOM). */
export interface UiChrome {
  echoInput(line: string, kind?: "command" | "message"): void;
  confirmSent(): void;
  rejectSent(): void;
  /** Append an inbound-discard notice to the right-side panel (see
   * renderer.NoticeSink). Cleared by clearScreen. */
  noteDiscarded(code: string, text: string): void;
  clearScreen(announce?: boolean): void;
  setChatContext(text: string | null): void;
  applyTheme(theme: ThemePrefs): void;
  setEmblemState(state: EmblemState): void;
  applyScheme(scheme: ResolvedScheme): void;
  applyEmblem(name: EmblemName): void;
  /** Follow /settings timestamps for the echo of a message you send, so the
   * live line and the same line replayed by renderer.ownMessage agree. */
  setMessageTimestamps(enabled: boolean): void;
  /** Apply the text metrics (face, size, letter spacing, line height) to both
   * terminals and the DOM. All four change the cell box, so the implementation
   * must re-fit afterwards or the column count silently goes stale. */
  applyTextStyle(style: TextStyle): void;
  /** Apply the accessibility switches: xterm's screen-reader live region and
   * the forced reduced-motion class. */
  applyAccessibility(prefs: AccessibilityPrefs): void;
  /** Ask the browser for notification permission. Returns what the user (or a
   * previous decision, or the platform) settled on, so /settings notify can
   * report the truth instead of assuming it worked. */
  requestNotifyPermission(): Promise<"granted" | "denied" | "unsupported">;
  /** Raise a desktop notification that a message arrived.
   *
   * Deliberately takes no arguments: it carries no sender, no alias and no
   * text. A notification leaves the browser for the operating system's
   * notification centre, which may log it, mirror it to other devices, or show
   * it on a lock screen, none of which this app controls. Saying only that
   * something arrived keeps the metadata this project is careful about inside
   * the app that is careful about it. */
  notifyMessage(): void;
  /** Current width of the transcript in character cells, so output that has to
   * be laid out (/help) can fit the screen it is printed on instead of assuming
   * a desktop terminal. */
  columns(): number;
}

export const NULL_CHROME: UiChrome = {
  echoInput() {},
  confirmSent() {},
  rejectSent() {},
  noteDiscarded() {},
  clearScreen() {},
  setChatContext() {},
  applyTheme() {},
  setEmblemState() {},
  applyScheme() {},
  applyEmblem() {},
  setMessageTimestamps() {},
  applyTextStyle() {},
  applyAccessibility() {},
  requestNotifyPermission: () => Promise.resolve("unsupported" as const),
  notifyMessage() {},
  columns: () => DEFAULT_HELP_COLUMNS,
};

/** Which screen the transcript is showing: the home dashboard or a specific
 * conversation, one-to-one or group. Tracked so /return can toggle back to
 * the previous one. */
export type ViewRef =
  | { readonly kind: "home" }
  | { readonly kind: "chat"; readonly uid: string }
  | { readonly kind: "group"; readonly gid: string };

/** The executor's collaborators and mutable state, as seen by the flow
 * modules (identity, messaging, trust, lifecycle, settings, views). The
 * Executor class implements this; flow functions take it as their first
 * parameter instead of being methods, which is what lets the implementation
 * live in focused modules. */
export interface ExecutorInternals {
  readonly store: KeyStore;
  readonly renderer: Renderer;
  readonly shell: ShellIO;
  readonly chrome: UiChrome;
  readonly now: () => number;

  identity: Identity | null;
  token: string | null;
  /** Saved contacts keyed by alias. */
  contacts: Map<string, Contact>;
  /** The conversation the terminal is focused on. null = the home
   * view. Set via /chat; cleared by /home. */
  active: Contact | null;
  /** The group conversation the terminal is focused on, if any. Held beside
   * `active` rather than folded into it: at most one of the two is ever set,
   * and every existing one-to-one code path keeps reading `active` unchanged. */
  activeGroup: Group | null;
  /** Per-contact (by uid) count of messages that arrived while their
   * conversation was not the focused view. In-memory only. */
  unread: Map<string, number>;
  /** The screen shown before the current one, for /return. In-memory only. */
  previousView: ViewRef | null;
  /** Trust-on-first-use mode (a, /settings trust). When true
   * (default), a contact's first key is auto-pinned and auto-verified, and a
   * later key change is auto-re-pinned with a loud warning instead of
   * blocking behind /ack. */
  autoTrust: boolean;
  /** Desktop-notification preference (/settings notify), cached from the
   * encrypted store on unlock. Off until loaded, so a message arriving mid-
   * login never notifies against a preference nobody has read yet. */
  notify: boolean;
  /** Bumped on every lock/logout/wipe; in-flight receive continuations check
   * it and bail instead of writing to torn-down state. */
  epoch: number;
  /** Timestamp of a pending /wipe first confirmation, 0 when none. */
  wipeRequestedAt: number;
  ws: WsClient | null;

  /** Queue a cosmetic view rebuild on the render lane (never the command
   * lane, so a redraw cannot block a typed message). */
  enqueueRender(fn: () => Promise<void>): void;
  /** Tear down the unlocked session: close WS, zeroize the identity secret,
   * lock the store, clear volatile view state. */
  lockLocal(): void;
  /** (Re)connect the WS delivery channel for the current session token. */
  connectWs(): void;
  /** Restart the idle auto-lock countdown. */
  touchAutoLock(): void;
}

export async function loadContacts(x: ExecutorInternals): Promise<void> {
  const stored = (await x.store.getJson<Contact[]>("contacts")) ?? [];
  x.contacts = new Map(stored.map((c) => [c.alias, normalizeContact(c)]));
}

export async function saveContacts(x: ExecutorInternals): Promise<void> {
  await x.store.putJson("contacts", [...x.contacts.values()]);
}

export function findContactByUid(x: ExecutorInternals, uid: string): Contact | null {
  for (const contact of x.contacts.values()) {
    if (contact.uid === uid) {
      return contact;
    }
  }
  return null;
}

export function resolveContact(x: ExecutorInternals, target: string): Contact | null {
  return x.contacts.get(target) ?? findContactByUid(x, normalizeUid(target) ?? "");
}

/** Load the trust-on-first-use mode from the encrypted store (defaults on). */
export async function loadTrustMode(x: ExecutorInternals): Promise<void> {
  const stored = await x.store.getJson<{ auto: boolean }>("settings/trust");
  x.autoTrust = stored?.auto ?? true;
}

/** Load the desktop-notification preference from the encrypted store (defaults
 * off). Cached on the executor for the same reason the trust mode is: the
 * receive path consults it per message and should not hit the store each
 * time. */
export async function loadNotifyMode(x: ExecutorInternals): Promise<void> {
  const stored = await x.store.getJson<NotifySettings>(NOTIFY_SETTINGS_KEY);
  x.notify = stored?.enabled ?? false;
}

export const NOTIFY_SETTINGS_KEY = "settings/notify";

// ----- the duress armed flag -------------------------------------------------
//
// Lives here rather than in duress.ts so identity.ts can write it without
// importing that module, which would close the cycle the UnlockRejectionHook
// exists to keep open.
//
// Two properties, and they are the whole reason this is not a putJson call:
//
//   1. THE RECORD ALWAYS EXISTS. IndexedDB key names are stored in the clear;
//      only values are sealed. A record written the first time /duress set or
//      /duress off runs would therefore announce, to anyone who images the
//      database with no passphrase at all, that this device has configured the
//      feature - which is the one fact it promises to hide. It is written at
//      store creation instead, exactly as crypto/store.ts writes its decoy
//      envelope from the start and for exactly the same reason.
//   2. THE RECORD IS ONE CONSTANT LENGTH. XChaCha20-Poly1305 is length-
//      preserving, so `{"armed":true}` and `{"armed":false}` differ by a byte
//      in the ciphertext and would leak the state the presence check no longer
//      does. A fixed-size buffer removes the distinguisher rather than relying
//      on the two encodings happening to match.
export const DURESS_SETTINGS_KEY = "settings/duress";

/** Padded well past the one bit it carries, so the size stays constant if this
 * record ever gains a field. */
const DURESS_FLAG_BYTES = 32;

function encodeDuressFlag(armed: boolean): Uint8Array {
  const out = new Uint8Array(DURESS_FLAG_BYTES);
  out[0] = armed ? 1 : 0;
  return out;
}

/** What the stored record says, and whether it is already in the padded form.
 * Understands the pre-padding JSON shape so a store written by an earlier build
 * is read correctly rather than reported as disarmed, which is the dangerous
 * direction to fail: it would tell someone the wipe trigger is off while it is
 * still armed. */
async function readDuressRecord(
  x: ExecutorInternals,
): Promise<{ armed: boolean; padded: boolean } | null> {
  const bytes = await x.store.getBytes(DURESS_SETTINGS_KEY);
  if (bytes === null) {
    return null;
  }
  if (bytes.length === DURESS_FLAG_BYTES) {
    return { armed: bytes[0] === 1, padded: true };
  }
  try {
    const legacy = JSON.parse(new TextDecoder().decode(bytes)) as { armed?: unknown };
    return { armed: legacy.armed === true, padded: false };
  } catch {
    return null;
  }
}

export async function readDuressArmed(x: ExecutorInternals): Promise<boolean> {
  return (await readDuressRecord(x))?.armed ?? false;
}

export async function writeDuressArmed(x: ExecutorInternals, armed: boolean): Promise<void> {
  await x.store.putBytes(DURESS_SETTINGS_KEY, encodeDuressFlag(armed));
}

/** Write the record if it is absent, and rewrite it at the fixed size if it is
 * a legacy JSON one, preserving whatever it said. Called at store creation and
 * at every login, so a store that predates this record acquires one on next
 * unlock instead of staying identifiable by its absence forever. */
export async function ensureDuressRecord(x: ExecutorInternals): Promise<void> {
  const record = await readDuressRecord(x);
  if (record?.padded === true) {
    return;
  }
  await writeDuressArmed(x, record?.armed ?? false);
}

/** Whether a desktop notification is raised for a message that arrives while
 * the tab is in the background. Stored ENCRYPTED beside the trust mode rather
 * than with the display preferences: it is not a look-and-feel choice, it
 * decides whether the existence of your conversations escapes the browser into
 * the operating system's notification centre. Nothing needs to read it before
 * unlock, because notifications only ever fire for a logged-in session. */
export interface NotifySettings {
  readonly enabled: boolean;
}

/** Pin a contact's identity key, adopting it as verified when trust-on-first-
 * use is on (a). Returns the updated Contact; the caller persists it. */
export function pinKey(x: ExecutorInternals, contact: Contact, ikB64: string): Contact {
  return { ...contact, ik: ikB64, verified: x.autoTrust ? true : contact.verified };
}

/** The screen currently on the transcript: home when nothing is focused, else
 * the focused conversation, one-to-one (by uid) or group (by gid).
 * `activeGroup` is checked first since at most one of it and `active` is ever
 * set, but only `active` used to be read here, which is what made /return
 * report "home" while a group was actually on screen. */
export function currentViewRef(x: ExecutorInternals): ViewRef {
  if (x.activeGroup !== null) {
    return { kind: "group", gid: x.activeGroup.gid };
  }
  return x.active === null ? { kind: "home" } : { kind: "chat", uid: x.active.uid };
}

/** True when `uid` is the conversation currently shown in the status context. */
export function isActiveConversation(x: ExecutorInternals, uid: string): boolean {
  return x.active !== null && (findContactByUid(x, x.active.uid)?.uid ?? x.active.uid) === uid;
}

/** Recompute the persistent status-strip context for the active conversation
 *: `[chatting with: alias (verified|UNVERIFIED)] [timer: 1h]`.
 * Re-resolves from the contacts map so trust/timer mutations are reflected;
 * call after any state change that could alter it. */
export function refreshChatContext(x: ExecutorInternals): void {
  if (x.active === null) {
    x.chrome.setChatContext(null);
    return;
  }
  const contact = findContactByUid(x, x.active.uid) ?? x.active;
  const trust = contact.verified ? "verified" : "UNVERIFIED";
  const timer =
    contact.timerSeconds === null ? "" : ` [timer: ${formatDuration(contact.timerSeconds)}]`;
  x.chrome.setChatContext(`[chatting with: ${contact.alias} (${trust})]${timer}`);
}

/** Recompute the medallion animation state: idle without a live unlocked
 * session, alert while anything awaits acknowledgement (a key-change-blocked
 * contact, a held contact request, or a group holding a member this device
 * has no contact entry for), active otherwise. Best-effort: a store read
 * failing mid-teardown just leaves the previous state. */
export async function refreshEmblemState(x: ExecutorInternals): Promise<void> {
  if (x.token === null || !x.store.isUnlocked()) {
    x.chrome.setEmblemState("idle");
    return;
  }
  let alert = [...x.contacts.values()].some((c) => c.keyChangeBlocked);
  if (!alert) {
    try {
      alert = (await x.store.listKeys("pending/")).length > 0;
    } catch {
      // locked mid-check: the next lock/login transition will correct it
    }
  }
  if (!alert) {
    try {
      // A member with no contact entry has no pinned key and no session, so
      // nothing can be encrypted to them until /group sync adds them. That is
      // as much a thing awaiting the user's action as an unacked key change.
      const self = x.identity?.uid ?? null;
      for (const group of await loadGroups(x)) {
        if (group.members.some((uid) => uid !== self && findContactByUid(x, uid) === null)) {
          alert = true;
          break;
        }
      }
    } catch {
      // locked mid-check: the next lock/login transition will correct it
    }
  }
  x.chrome.setEmblemState(alert ? "alert" : "active");
}
