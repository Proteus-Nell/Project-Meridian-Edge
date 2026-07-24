// The command executor: consumes the parser's typed union in one switch
// (§1.2) and dispatches into the flow modules (identity, contacts,
// trust, messaging, lifecycle, settings, views, bench). This class owns the
// mutable session state and the async plumbing: a command lane, a render
// lane for cosmetic view rebuilds, the idle auto-lock, and the WS delivery
// channel. Flow logic lives in the sibling modules; a command that is not
// implemented yet answers with its scheduled milestone so the surface stays
// honest about what exists.

import { WsClient } from "../../net/ws";
import { ApiError } from "../../net/api";
import { KeyStore, StoreLockedError } from "../../crypto/store";
import { AUTO_LOCK_MS } from "../../crypto/constants";
import { resolveScheme } from "../theme";
import type { Command, ParseResult } from "../parser";
import { COMMAND_USAGE } from "../parser";
import { renderCommandHelp, renderHelp } from "../help";
import type { Renderer } from "../renderer";
import type { ShellIO } from "../shell";
import { NULL_CHROME, currentViewRef, findContactByUid, refreshChatContext, resolveContact } from "./context";
import type { ExecutorInternals, UiChrome, ViewRef } from "./context";
import type { Contact, Identity } from "./records";
import { doBench } from "./bench";
import { doAdd, doContacts, doRemove, doRename } from "./contacts";
import {
  doKeysRefill,
  doKeysStatus,
  doLock,
  doLogin,
  doLogout,
  doLogoutOthers,
  doRecover,
  doRegister,
  doRotatePassphrase,
  doSessions,
  doWhoami,
  doWipe,
} from "./identity";
import { doDelete, doPurgeNow, doPurgeSet, doTimer } from "./lifecycle";
import { processEnvelope, sendActiveMessage } from "./messaging";
import {
  doSettingsColor,
  doSettingsColorReset,
  doSettingsEmblem,
  doSettingsMask,
  doSettingsRotation,
  doSettingsScheme,
  doSettingsTheme,
  doSettingsTrust,
} from "./settings";
import { doAck, doVerified, doVerify } from "./trust";
import { renderActiveConversation, renderHome, returnToPreviousView } from "./views";

const SEGMENT_OF: Partial<Record<Command["name"], string>> = {
  "settings-notify": "W6 (could-have)",
};

export class Executor implements ExecutorInternals {
  readonly store: KeyStore;
  identity: Identity | null = null;
  token: string | null = null;
  contacts = new Map<string, Contact>();
  active: Contact | null = null;
  unread = new Map<string, number>();
  previousView: ViewRef | null = null;
  autoTrust = true;
  epoch = 0;
  wipeRequestedAt = 0;
  ws: WsClient | null = null;

  private busy = false;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private rxTail: Promise<void> = Promise.resolve();
  private tail: Promise<void> = Promise.resolve();
  /** A lane separate from the command `tail` for cosmetic view rebuilds.
   * Kept apart so enqueuing a redraw never trips the `busy` guard: a redraw
   * scheduled by /chat must not make an immediately-following message report
   * "another operation is in progress". */
  private renderTail: Promise<void> = Promise.resolve();

  readonly renderer: Renderer;
  readonly shell: ShellIO;
  readonly chrome: UiChrome;
  readonly now: () => number;

  constructor(
    renderer: Renderer,
    shell: ShellIO,
    store?: KeyStore,
    now: () => number = () => Date.now(),
    chrome: UiChrome = NULL_CHROME,
  ) {
    this.renderer = renderer;
    this.shell = shell;
    this.store = store ?? new KeyStore();
    this.now = now;
    this.chrome = chrome;
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
        this.renderer.error(result.code, result.error);
        if (result.usage !== undefined) {
          // A usage string may enumerate several forms joined by "  |  "
          // (e.g. /settings); print one form per line so it stays readable.
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
    const target = findContactByUid(this, this.active.uid) ?? this.active;
    this.run(() => sendActiveMessage(this, target, text));
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
        this.run(() => doRegister(this));
        return;
      case "recover":
        this.run(() => doRecover(this));
        return;
      case "login":
        this.run(() => doLogin(this));
        return;
      case "logout":
        this.run(() => (cmd.all ? doLogoutOthers(this) : doLogout(this)));
        return;
      case "sessions":
        this.run(() => doSessions(this));
        return;
      case "lock":
        doLock(this);
        return;
      case "rotate-passphrase":
        this.run(() => doRotatePassphrase(this));
        return;
      case "keys-status":
        this.run(() => doKeysStatus(this));
        return;
      case "keys-refill":
        this.run(() => doKeysRefill(this));
        return;
      case "settings-rotation":
        this.run(() => doSettingsRotation(this, cmd.setting));
        return;
      case "settings-mask":
        this.run(() => doSettingsMask(this, cmd.mask));
        return;
      case "settings-trust":
        this.run(() => doSettingsTrust(this, cmd.mode));
        return;
      case "settings-theme":
        this.run(() => doSettingsTheme(this, cmd.element, cmd.enabled));
        return;
      case "settings-scheme":
        this.run(() => doSettingsScheme(this, cmd.scheme));
        return;
      case "settings-emblem":
        this.run(() => doSettingsEmblem(this, cmd.emblem));
        return;
      case "settings-color":
        this.run(() => doSettingsColor(this, cmd.slot, cmd.hex));
        return;
      case "settings-color-reset":
        this.run(() => doSettingsColorReset(this));
        return;
      case "wipe":
        this.run(() => doWipe(this));
        return;
      case "add":
        this.run(() => doAdd(this, cmd.uid, cmd.alias));
        return;
      case "remove":
        this.run(() => doRemove(this, cmd.target, cmd.purge));
        return;
      case "rename":
        this.run(() => doRename(this, cmd.target, cmd.alias));
        return;
      case "verify":
        this.run(() => doVerify(this, cmd.alias));
        return;
      case "verified":
        this.run(() => doVerified(this, cmd.alias));
        return;
      case "whoami":
        doWhoami(this);
        return;
      case "chat":
        this.openChat(cmd.target, cmd.message);
        return;
      case "home": {
        const previousBeforeHome = currentViewRef(this);
        if (previousBeforeHome.kind !== "home") {
          this.previousView = previousBeforeHome; // remember for /return
        }
        this.active = null;
        this.shell.setPrompt("> ");
        refreshChatContext(this); // clears the §1.5 context line
        this.enqueueRender(() => renderHome(this));
        return;
      }
      case "return":
        returnToPreviousView(this);
        return;
      case "contacts":
        this.run(() => doContacts(this));
        return;
      case "ack":
        this.run(() => doAck(this, cmd.alias));
        return;
      case "timer":
        this.run(() => doTimer(this, cmd.alias, cmd.duration));
        return;
      case "purge-set":
        this.run(() => doPurgeSet(this, cmd.duration));
        return;
      case "purge-now":
        this.run(() => doPurgeNow(this, cmd.alias));
        return;
      case "delete":
        this.run(() => doDelete(this, cmd.scope, cmd.silent));
        return;
      case "bench":
        this.run(() => doBench(this, cmd.suite));
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

  /** `/chat <target> [message]`: focus a conversation (§1.5) and, with
   * the inline form, echo and send the trailing message exactly as if it had
   * been typed after switching. */
  private openChat(target: string, message: string | undefined): void {
    const contact = resolveContact(this, target);
    if (contact === null) {
      this.renderer.error("E501", target);
      return;
    }
    const previousBeforeChat = currentViewRef(this);
    if (previousBeforeChat.kind !== "chat" || previousBeforeChat.uid !== contact.uid) {
      this.previousView = previousBeforeChat; // remember for /return
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
    refreshChatContext(this);
    if (message === undefined) {
      // Switch the transcript to the focused conversation view on the render
      // lane so a message typed right after /chat is not blocked by the redraw.
      this.enqueueRender(() => renderActiveConversation(this));
      return;
    }
    // Inline form: sequence render, echo, send in one task so the delivery
    // tick pins to the echoed row. The send flows through the same core as a
    // typed message, so key-change blocks, trust state, timers and the
    // ratchet behave identically.
    this.run(async () => {
      await renderActiveConversation(this);
      this.chrome.echoInput(message, "message");
      await sendActiveMessage(this, contact, message);
    });
  }

  // ----- async command plumbing -------------------------------------------

  enqueueRender(fn: () => Promise<void>): void {
    // Failures are swallowed: a redraw is cosmetic and must never surface as
    // an operation error.
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
   * neither lane advanced across a settle, so tests can await the full
   * effect of a command including its redraw. Capped so it can never spin
   * forever. */
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
        this.renderer.error("E301");
        return;
      }
      if (err.status === 401) {
        this.token = null;
        this.renderer.error("E202");
        return;
      }
      this.renderer.error("E302");
      return;
    }
    if (err instanceof StoreLockedError) {
      this.renderer.error("E401");
      return;
    }
    this.renderer.error("E599");
  }

  touchAutoLock(): void {
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

  lockLocal(): void {
    this.epoch += 1;
    this.ws?.close();
    this.ws = null;
    if (this.identity !== null) {
      this.identity.sec.fill(0);
      this.identity = null;
    }
    // The conversation context is stale once locked (contacts reload on the
    // next /login, which refreshes it); clear the display, keep this.active
    // so an unlocked session resumes where it was.
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

  connectWs(): void {
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
            if ((await processEnvelope(this, envelope)) === "ack") {
              this.ws?.ack([id]);
            }
          })
          .catch(() => {
            this.renderer.error("E509");
          });
      },
      onClose: (intentional) => {
        if (!intentional) {
          this.renderer.event("warning", "live delivery disconnected - /login to reconnect");
        }
      },
    });
  }

  private printHelp(topic: keyof typeof COMMAND_USAGE | undefined): void {
    const lines = topic !== undefined ? renderCommandHelp(topic) : renderHelp();
    for (const line of lines) {
      this.renderer.plain(line);
    }
  }
}
