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

export class Renderer {
  /** Whether conversation lines carry the time beside them
   * (/settings timestamps). On unless the stored display preferences say
   * otherwise, which executor.init() applies once they have been read. Typed
   * events and errors are stamped unconditionally and are not affected: this
   * governs the conversation only. */
  private messageTimestamps = true;

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
    this.sink.printLine(
      `${this.messagePrefix(at, "  ")}\x1b[96m[${sanitizeText(label)}]${RESET} ${sanitizeText(text)}`,
    );
  }

  /** One of your own sent messages, replayed when a conversation view is rebuilt
   * (e.g. after a /delete redraw). Mirrors the live command-line echo - a dim
   * `> ` marker then the message text. Sanitized like everything else. */
  ownMessage(text: string, at?: number): void {
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
