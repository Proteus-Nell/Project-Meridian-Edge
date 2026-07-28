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
import type { EmblemName, ResolvedScheme } from "../theme";
import { formatDuration } from "./format";
import { normalizeContact } from "./records";
import type { Contact, Identity } from "./records";
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
  columns: () => DEFAULT_HELP_COLUMNS,
};

/** Which screen the transcript is showing: the home dashboard or a specific
 * conversation. Tracked so /return can toggle back to the previous one. */
export type ViewRef = { readonly kind: "home" } | { readonly kind: "chat"; readonly uid: string };

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

/** Pin a contact's identity key, adopting it as verified when trust-on-first-
 * use is on (a). Returns the updated Contact; the caller persists it. */
export function pinKey(x: ExecutorInternals, contact: Contact, ikB64: string): Contact {
  return { ...contact, ik: ikB64, verified: x.autoTrust ? true : contact.verified };
}

/** The screen currently on the transcript: home when nothing is focused, else
 * the focused conversation (by uid). */
export function currentViewRef(x: ExecutorInternals): ViewRef {
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
 * contact or a held contact request), active otherwise. Best-effort: a store
 * read failing mid-teardown just leaves the previous state. */
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
  x.chrome.setEmblemState(alert ? "alert" : "active");
}
