// Typed event renderer (CLAUDE.md §1.3): every output line is a typed event
// written as plain text into the transcript terminal via xterm.js `write` with
// ANSI colors — content is never markup. User-influenced text is stripped of
// control characters so a hostile message cannot inject terminal escape
// sequences. The latest event is also mirrored to the DOM status strip through
// an abstract StatusSink (the renderer itself touches no DOM); the sink writes
// it as textContent, so there is still no markup path for any content.

export type EventLevel = "success" | "warning" | "failure" | "info" | "security";

const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

const PREFIX: Record<EventLevel, string> = {
  success: "\x1b[32m[✓]" + RESET,
  warning: "\x1b[33m[!]" + RESET,
  failure: "\x1b[31m[✗]" + RESET,
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

/** Ephemeral one-line status surface — the footer strip above the command line.
 * Distinct from the scrolling transcript: it shows only the latest status,
 * overwriting in place, so operational chatter ("sent", errors) does not have to
 * accumulate in the log. Rendered as DOM text (textContent), never markup. */
export interface StatusSink {
  status(level: EventLevel, text: string): void;
}

export class Renderer {
  constructor(
    private readonly sink: LineSink,
    private readonly now: () => Date = () => new Date(),
    private readonly statusSink: StatusSink | null = null,
  ) {}

  event(level: EventLevel, text: string): void {
    const clean = sanitizeText(text);
    this.sink.printLine(`${DIM}${this.timestamp()}${RESET} ${PREFIX[level]} ${clean}`);
    // Mirror the latest typed event into the footer status strip so current
    // state is visible at a glance without scanning the transcript.
    this.statusSink?.status(level, clean);
  }

  /** Update only the footer status strip — no transcript line. Used where a
   * durable log entry would be noise (e.g. per-message "sent" confirmations,
   * which also surface as a right-side tick). */
  status(level: EventLevel, text: string): void {
    this.statusSink?.status(level, sanitizeText(text));
  }

  /** Plain output (help text, banners). Still sanitized, still text-only. */
  plain(text: string): void {
    this.sink.printLine(sanitizeText(text));
  }

  /** A dim structural line — conversation-view headers and the home dashboard
   * rules. The dim styling wraps the already-sanitized text (peerMessage-style),
   * so no untrusted escape survives. */
  divider(text: string): void {
    this.sink.printLine(`${DIM}${sanitizeText(text)}${RESET}`);
  }

  /** An incoming conversation line: the peer's alias in bright cyan so chat
   * traffic reads distinctly from system output. Label and text are both
   * untrusted (alias is user-chosen, text is peer-sent) — both sanitized. */
  peerMessage(label: string, text: string): void {
    this.sink.printLine(`  \x1b[96m[${sanitizeText(label)}]${RESET} ${sanitizeText(text)}`);
  }

  /** One of your own sent messages, replayed when a conversation view is rebuilt
   * (e.g. after a /delete redraw). Mirrors the live command-line echo — a dim
   * `> ` marker then the message text. Sanitized like everything else. */
  ownMessage(text: string): void {
    this.sink.printLine(`${DIM}> ${RESET}${sanitizeText(text)}`);
  }

  private timestamp(): string {
    const d = this.now();
    const pad = (n: number): string => n.toString().padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }
}
