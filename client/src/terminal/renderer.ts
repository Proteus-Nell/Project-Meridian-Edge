// Typed event renderer: every output line is a typed event
// written as plain text into the transcript terminal via xterm.js `write` with
// ANSI colors - content is never markup. User-influenced text is stripped of
// control characters so a hostile message cannot inject terminal escape
// sequences. The latest event is also mirrored to the DOM status strip through
// an abstract StatusSink (the renderer itself touches no DOM); the sink writes
// it as textContent, so there is still no markup path for any content.

import { ERRORS } from "./messages";
import type { ErrorCode } from "./messages";

export type EventLevel = "success" | "warning" | "failure" | "info" | "security";

/** Failures are emitted through error() with a catalogued E-code; event()
 * takes every other level. */
export type GlyphLevel = Exclude<EventLevel, "failure">;

const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";

const PREFIX: Record<GlyphLevel, string> = {
  success: "\x1b[32m[✓]" + RESET,
  warning: "\x1b[33m[!]" + RESET,
  info: "\x1b[36m[*]" + RESET,
  security: "\x1b[1;97;41m[SECURITY]" + RESET,
};

/** Strip C0 controls, DEL, and C1 controls (incl. CSI U+009B) so that no
 * untrusted text can smuggle escape sequences into the terminal. */
export function sanitizeText(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      continue;
    }
    out += ch;
  }
  return out;
}

/** Destination for fully rendered lines (the transcript terminal). */
export interface LineSink {
  printLine(line: string): void;
}

/** Ephemeral one-line status surface - the footer strip above the command line.
 * Distinct from the scrolling transcript: it shows only the latest status,
 * overwriting in place, so operational chatter ("sent", errors) does not have to
 * accumulate in the log. Rendered as DOM text (textContent), never markup. */
export interface StatusSink {
  status(level: EventLevel, text: string): void;
}

/** Destination for inbound-discard notices - the right-side panel. These
 * describe something that happened TO the user (a message that could not be
 * read), not a command that failed, so they are collected in their own list
 * instead of interleaving with the conversation. Rendered as DOM text
 * (textContent), never markup. */
export interface NoticeSink {
  noteDiscarded(code: string, text: string): void;
}

/** The transcript's day-divider state (see Renderer.markMessageDay), as the
 * chrome sees it. The echo of a message you send is written by chrome.ts rather
 * than the renderer - main.ts echoes before the executor is handed the line -
 * so the one object that knows which day the transcript is on has to be
 * reachable from there too, or your own first message after midnight would be
 * the one line that never gets a date. Implemented by Renderer; injected into
 * Chrome by main.ts. */
export interface DayMarker {
  markMessageDay(at?: number): void;
  resetMessageDay(): void;
}

/** Weekday and month names, spelled out here rather than taken from
 * toLocaleDateString for the same reason the clock is assembled by hand: the
 * output is then fixed, testable, and identical on every host, instead of
 * varying with whatever locale data the browser happens to ship. */
const WEEKDAY_NAMES = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
] as const;

const MONTH_NAMES = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
] as const;

/** The local calendar day of an instant, as a key two instants can be compared
 * by. Local, not UTC, because it has to agree with the local HH:MM:SS printed
 * beside it: a message at 23:30 belongs to the day the reader saw on the
 * clock, not to whatever day it was in UTC. */
function dayKey(d: Date): string {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

/** `Thursday, 27 August 2026`. */
function formatDay(d: Date): string {
  return `${WEEKDAY_NAMES[d.getDay()] ?? ""}, ${d.getDate()} ${MONTH_NAMES[d.getMonth()] ?? ""} ${d.getFullYear()}`;
}

export class Renderer implements DayMarker {
  /** Whether conversation lines carry the time beside them
   * (/settings timestamps). On unless the stored display preferences say
   * otherwise, which executor.init() applies once they have been read. Typed
   * events and errors are stamped unconditionally and are not affected: this
   * governs the conversation only. */
  private messageTimestamps = true;

  /** The day of the last conversation line printed since the screen was last
   * cleared, or null when none has been. Only ever compared, never displayed:
   * what is displayed is built fresh by formatDay. */
  private lastDay: string | null = null;

  constructor(
    private readonly sink: LineSink,
    private readonly now: () => Date = () => new Date(),
    private readonly statusSink: StatusSink | null = null,
    private readonly noticeSink: NoticeSink | null = null,
  ) {}

  /** Follow /settings timestamps. Applied at startup from the stored display
   * preferences and again whenever the setting changes. */
  setMessageTimestamps(enabled: boolean): void {
    this.messageTimestamps = enabled;
  }

  /** Open a new day in the transcript when `at` falls on a later calendar day
   * than the last conversation line printed, by writing a dated divider ahead
   * of it. A bare `HH:MM:SS` answers "when today", and nothing else: without
   * this, a conversation resumed after a week reads as though it never paused.
   *
   * Called by peerMessage and ownMessage for themselves, so every rendered
   * conversation line is covered - live, replayed, or held behind a contact
   * request - and by chrome.echoInput for the one conversation line the
   * renderer does not write. Silent while /settings timestamps is off: the
   * setting governs every time the conversation shows. */
  markMessageDay(at?: number): void {
    if (!this.messageTimestamps) {
      return;
    }
    const d = at === undefined ? this.now() : new Date(at);
    const key = dayKey(d);
    if (key === this.lastDay) {
      return;
    }
    this.lastDay = key;
    this.divider(`-- ${formatDay(d)} --`);
  }

  /** Forget which day the transcript is on. Every screen wipe has to call this:
   * the dividers that were on screen are gone, so the next message must date
   * itself again rather than assume a line the reader can no longer see. */
  resetMessageDay(): void {
    this.lastDay = null;
  }

  event(level: GlyphLevel, text: string): void {
    const clean = sanitizeText(text);
    this.sink.printLine(`${DIM}${this.timestamp()}${RESET} ${PREFIX[level]} ${clean}`);
    // Mirror the latest typed event into the footer status strip so current
    // state is visible at a glance without scanning the transcript.
    this.statusSink?.status(level, clean);
  }

  /** A user-facing failure: the catalogued E-code replaces the glyph
   * (`[E301] Rate limit reached. ...`), so every error on screen is
   * reportable and looked up in docs/MESSAGES.md. Text comes from the
   * ERRORS catalog; args are the builder's parameters. */
  error<C extends ErrorCode>(code: C, ...args: Parameters<(typeof ERRORS)[C]>): void {
    const build = ERRORS[code] as (...a: ReadonlyArray<unknown>) => string;
    const clean = sanitizeText(build(...args));
    this.sink.printLine(`${DIM}${this.timestamp()}${RESET} ${RED}[${code}]${RESET} ${clean}`);
    this.statusSink?.status("failure", `[${code}] ${clean}`);
  }

  /** An inbound message that could not be delivered to the user. Deliberately
   * writes NO transcript line: these arrive unprompted and would otherwise
   * interrupt the conversation view. The catalogued text goes to the
   * discarded-notice panel and the status strip, so it is noticed once and
   * remains reviewable without scrolling the transcript. */
  discarded<C extends ErrorCode>(code: C, ...args: Parameters<(typeof ERRORS)[C]>): void {
    const build = ERRORS[code] as (...a: ReadonlyArray<unknown>) => string;
    const clean = sanitizeText(build(...args));
    this.noticeSink?.noteDiscarded(code, clean);
    this.statusSink?.status("warning", `[${code}] ${clean}`);
  }

  /** Update only the footer status strip - no transcript line. Used where a
   * durable log entry would be noise (e.g. per-message "sent" confirmations,
   * which also surface as a right-side tick). */
  status(level: EventLevel, text: string): void {
    this.statusSink?.status(level, sanitizeText(text));
  }

  /** Plain output (help text, banners). Still sanitized, still text-only. */
  plain(text: string): void {
    this.sink.printLine(sanitizeText(text));
  }

  /** A dim structural line - conversation-view headers and the home dashboard
   * rules. The dim styling wraps the already-sanitized text (peerMessage-style),
   * so no untrusted escape survives. */
  divider(text: string): void {
    this.sink.printLine(`${DIM}${sanitizeText(text)}${RESET}`);
  }

  /** An incoming conversation line: the peer's alias in bright cyan so chat
   * traffic reads distinctly from system output. Label and text are both
   * untrusted (alias is user-chosen, text is peer-sent) - both sanitized.
   * `at` is the message's own epoch-ms instant, passed when history is
   * replayed so a rebuilt view shows when the message arrived rather than
   * when it was reprinted; omit it for a message arriving now. */
  peerMessage(label: string, text: string, at?: number): void {
    this.markMessageDay(at);
    this.sink.printLine(
      `${this.messagePrefix(at, "  ")}\x1b[96m[${sanitizeText(label)}]${RESET} ${sanitizeText(text)}`,
    );
  }

  /** One of your own sent messages, replayed when a conversation view is rebuilt
   * (e.g. after a /delete redraw). Mirrors the live command-line echo - a dim
   * `> ` marker then the message text. Sanitized like everything else. */
  ownMessage(text: string, at?: number): void {
    this.markMessageDay(at);
    this.sink.printLine(`${this.messagePrefix(at, "")}${DIM}> ${RESET}${sanitizeText(text)}`);
  }

  /** What a conversation line starts with: a dim timestamp when the setting is
   * on, and `gutter` - the line's original lead-in - when it is off, so turning
   * the setting off leaves the transcript exactly as it looked before the
   * setting existed. */
  private messagePrefix(at: number | undefined, gutter: string): string {
    return this.messageTimestamps ? `${DIM}${this.timestamp(at)}${RESET} ` : gutter;
  }

  /** `HH:MM:SS` in the viewer's local time, for `at` when given and for now
   * otherwise. Local rather than UTC because it is read by the person sitting
   * in front of it; it never leaves the device. */
  private timestamp(at?: number): string {
    const d = at === undefined ? this.now() : new Date(at);
    const pad = (n: number): string => n.toString().padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
}
