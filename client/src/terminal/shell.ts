// Line discipline over xterm.js: single-line editing with
// cursor movement, history (up/down), Ctrl+L clear, Ctrl+U kill-line, and Tab
// completion. The shell drives a dedicated *input* terminal pinned at the bottom
// of the UI; transcript output goes to a separate *output* terminal via
// printLine, so async command output never has to redraw the input line. The
// input buffer is only ever surfaced to the autosuggest listener when no masked
// (passphrase) prompt is active, so secrets never leak to the suggestion path.

import type { LineSink } from "./renderer";

/** The subset of xterm.js Terminal the shell needs (test seam). */
export interface TerminalLike {
  write(data: string): void;
  onData(handler: (data: string) => void): void;
}

const MAX_LINE_LENGTH = 4096;
const MAX_HISTORY = 100;

interface PendingInput {
  resolve: (value: string | null) => void;
  savedPrompt: string;
  mask: boolean;
}

/** How masked (passphrase) input is echoed: 'asterisk' shows one '*' per
 * character (leaks length to a shoulder-surfer); 'hidden' shows nothing at
 * all, sudo-style. Toggleable via /settings mask. */
export type SecretMask = "asterisk" | "hidden";

/** What command flows need from the shell (test seam for the executor). */
export interface ShellIO {
  readSecret(promptText: string): Promise<string | null>;
  readLine(promptText: string): Promise<string | null>;
  setPrompt(prompt: string): void;
  setSecretMask(mask: SecretMask): void;
}

/** Fills the input buffer on Tab. Given the current buffer, returns the completed
 * buffer, or null to leave it unchanged. The completion policy lives in the
 * caller (see terminal/suggest.ts); the shell just applies the result. */
export type Completer = (buffer: string) => string | null;

/** The shell's view of the autosuggest dropdown (implemented by Chrome). While
 * the dropdown is open, arrow keys move its highlight instead of recalling
 * history, Enter/Tab fill the highlighted completion instead of submitting,
 * and Esc closes it. accept() returns null when no row has been navigated to,
 * so plain Enter still submits the typed line. */
export interface SuggestionNav {
  isOpen(): boolean;
  move(delta: 1 | -1): void;
  accept(): string | null;
  close(): void;
}

export class Shell implements LineSink, ShellIO {
  private buffer = "";
  private cursor = 0;
  private history: string[] = [];
  private historyIndex = -1; // -1 = editing a fresh line
  private draft = "";
  private prompt = "> ";
  private pending: PendingInput | null = null;
  private secretMask: SecretMask = "asterisk";
  private completer: Completer | null = null;
  private inputChangeHandler: ((buffer: string) => void) | null = null;
  private clearHandler: (() => void) | null = null;
  private suggestionNav: SuggestionNav | null = null;

  constructor(
    private readonly inputTerm: TerminalLike,
    private readonly outputTerm: TerminalLike,
    private readonly onLine: (line: string) => void,
  ) {}

  /** Masked input for passphrases: echoes '*', bypasses history and the line
   * handler. Resolves null if the user cancels with Ctrl+C. */
  readSecret(promptText: string): Promise<string | null> {
    return this.readInput(promptText, true);
  }

  /** Unmasked prompt for confirmations (y/N). Bypasses history and the line
   * handler like readSecret, so answers never pollute either. */
  readLine(promptText: string): Promise<string | null> {
    return this.readInput(promptText, false);
  }

  private readInput(promptText: string, mask: boolean): Promise<string | null> {
    return new Promise((resolve) => {
      this.pending = { resolve, savedPrompt: this.prompt, mask };
      this.buffer = "";
      this.cursor = 0;
      this.historyIndex = -1;
      this.prompt = promptText;
      this.redraw();
    });
  }

  attach(): void {
    this.inputTerm.onData((data) => this.handleData(data));
    this.redraw();
  }

  /** Register the Tab completion provider. */
  setCompleter(completer: Completer): void {
    this.completer = completer;
  }

  /** Register the dropdown navigator (arrow/Enter/Tab/Esc routing target). */
  setSuggestionNav(nav: SuggestionNav): void {
    this.suggestionNav = nav;
  }

  /** Replace the input buffer (dropdown click-to-pick path). Ignored while a
   * masked/confirm prompt is active so a pick can never land in a passphrase. */
  setBuffer(text: string): void {
    if (this.pending !== null) {
      return;
    }
    this.buffer = text;
    this.cursor = text.length;
    this.redraw();
  }

  /** The dropdown participates in key routing only when it is actually open
   * and no prompt is pending (prompts already force it closed via notifyInput,
   * but the guard keeps the invariant local). */
  private navActive(): SuggestionNav | null {
    return this.pending === null && this.suggestionNav?.isOpen() === true
      ? this.suggestionNav
      : null;
  }

  /** Notified whenever the (unmasked) input buffer changes, for live autosuggest.
   * While a masked/confirm prompt is active the buffer is reported as empty, so a
   * passphrase in progress is never handed to the suggestion path. */
  onInputChange(handler: (buffer: string) => void): void {
    this.inputChangeHandler = handler;
  }

  /** Invoked on Ctrl+L (and reused by /clr): clears the transcript terminal. */
  setClearHandler(handler: () => void): void {
    this.clearHandler = handler;
  }

  setPrompt(prompt: string): void {
    this.prompt = prompt;
    this.redraw();
  }

  setSecretMask(mask: SecretMask): void {
    this.secretMask = mask;
    if (this.pending?.mask === true) {
      this.redraw(); // reflect the change on an in-progress prompt
    }
  }

  printLine(line: string): void {
    // Input lives in a separate terminal, so transcript output is a plain append
    // with no need to clear or restore the prompt line.
    this.outputTerm.write(`${line}\r\n`);
  }

  private handleData(data: string): void {
    let i = 0;
    while (i < data.length) {
      const ch = data[i] ?? "";
      if (ch === "\x1b") {
        i += this.handleEscape(data.slice(i));
        continue;
      }
      this.handleChar(ch);
      i += 1;
    }
  }

  /** Returns the number of characters consumed from `data`. */
  private handleEscape(data: string): number {
    if (data === "\x1b") {
      // A lone ESC byte is the Esc key itself: close the dropdown if open.
      this.navActive()?.close();
      return 1;
    }
    if (data.startsWith("\x1b[A")) {
      const nav = this.navActive();
      if (nav !== null) {
        nav.move(-1);
      } else {
        this.historyPrev();
      }
      return 3;
    }
    if (data.startsWith("\x1b[B")) {
      const nav = this.navActive();
      if (nav !== null) {
        nav.move(1);
      } else {
        this.historyNext();
      }
      return 3;
    }
    if (data.startsWith("\x1b[C")) {
      if (this.cursor < this.buffer.length) {
        this.cursor += 1;
        this.redraw();
      }
      return 3;
    }
    if (data.startsWith("\x1b[D")) {
      if (this.cursor > 0) {
        this.cursor -= 1;
        this.redraw();
      }
      return 3;
    }
    if (data.startsWith("\x1b[H")) {
      this.cursor = 0;
      this.redraw();
      return 3;
    }
    if (data.startsWith("\x1b[F")) {
      this.cursor = this.buffer.length;
      this.redraw();
      return 3;
    }
    if (data.startsWith("\x1b[3~")) {
      if (this.cursor < this.buffer.length) {
        this.buffer = this.buffer.slice(0, this.cursor) + this.buffer.slice(this.cursor + 1);
        this.redraw();
      }
      return 4;
    }
    return 1; // unknown escape: swallow ESC, ignore
  }

  private handleChar(ch: string): void {
    switch (ch) {
      case "\r":
      case "\n": {
        // With a highlighted dropdown row, Enter fills the completion instead
        // of submitting; a plain Enter (no row navigated to) submits as usual.
        const accepted = this.navActive()?.accept() ?? null;
        if (accepted !== null) {
          this.buffer = accepted;
          this.cursor = accepted.length;
          this.redraw();
          return;
        }
        this.submit();
        return;
      }
      case "\t": {
        this.complete();
        return;
      }
      case "\x7f": // backspace
      case "\b": {
        if (this.cursor > 0) {
          this.buffer = this.buffer.slice(0, this.cursor - 1) + this.buffer.slice(this.cursor);
          this.cursor -= 1;
          this.redraw();
        }
        return;
      }
      case "\x0c": {
        // Ctrl+L: clear the transcript, keep the current input line
        this.clearHandler?.();
        return;
      }
      case "\x15": {
        // Ctrl+U: kill line
        this.buffer = "";
        this.cursor = 0;
        this.redraw();
        return;
      }
      case "\x03": {
        // Ctrl+C: abandon the current line (cancels a pending prompt)
        this.outputTerm.write("^C\r\n");
        this.buffer = "";
        this.cursor = 0;
        this.historyIndex = -1;
        if (this.pending !== null) {
          const pending = this.pending;
          this.pending = null;
          this.prompt = pending.savedPrompt;
          pending.resolve(null);
        }
        this.redraw();
        return;
      }
      default: {
        const cp = ch.codePointAt(0) ?? 0;
        if (cp < 0x20 || cp === 0x7f) {
          return; // ignore other control characters
        }
        if (this.buffer.length >= MAX_LINE_LENGTH) {
          return;
        }
        this.buffer = this.buffer.slice(0, this.cursor) + ch + this.buffer.slice(this.cursor);
        this.cursor += 1;
        this.redraw();
      }
    }
  }

  /** Tab: a highlighted dropdown row wins; otherwise ask the completer to
   * extend the buffer (longest common prefix). No-op during a masked/confirm
   * prompt so completion never fires while a passphrase is being typed. */
  private complete(): void {
    if (this.pending !== null) {
      return;
    }
    const accepted = this.navActive()?.accept() ?? null;
    if (accepted !== null) {
      this.buffer = accepted;
      this.cursor = accepted.length;
      this.redraw();
      return;
    }
    if (this.completer === null) {
      return;
    }
    const completed = this.completer(this.buffer);
    if (completed !== null && completed !== this.buffer) {
      this.buffer = completed;
      this.cursor = completed.length;
      this.redraw();
    }
  }

  private submit(): void {
    const line = this.buffer;
    this.buffer = "";
    this.cursor = 0;
    this.historyIndex = -1;
    if (this.pending !== null) {
      // Prompted lines never touch history or the line handler.
      const pending = this.pending;
      this.pending = null;
      this.prompt = pending.savedPrompt;
      pending.resolve(line);
      this.redraw();
      return;
    }
    if (line.trim().length > 0 && line !== this.history[this.history.length - 1]) {
      this.history.push(line);
      if (this.history.length > MAX_HISTORY) {
        this.history.shift();
      }
    }
    this.onLine(line);
    this.redraw();
  }

  private historyPrev(): void {
    if (this.history.length === 0 || this.pending !== null) {
      return;
    }
    if (this.historyIndex === -1) {
      this.draft = this.buffer;
      this.historyIndex = this.history.length - 1;
    } else if (this.historyIndex > 0) {
      this.historyIndex -= 1;
    }
    this.buffer = this.history[this.historyIndex] ?? "";
    this.cursor = this.buffer.length;
    this.redraw();
  }

  private historyNext(): void {
    if (this.historyIndex === -1 || this.pending !== null) {
      return;
    }
    if (this.historyIndex < this.history.length - 1) {
      this.historyIndex += 1;
      this.buffer = this.history[this.historyIndex] ?? "";
    } else {
      this.historyIndex = -1;
      this.buffer = this.draft;
    }
    this.cursor = this.buffer.length;
    this.redraw();
  }

  private redraw(): void {
    const masked = this.pending?.mask === true;
    const hidden = masked && this.secretMask === "hidden";
    const shown = hidden ? "" : masked ? "*".repeat(this.buffer.length) : this.buffer;
    this.inputTerm.write(`\r\x1b[2K${this.prompt}${shown}`);
    // In hidden mode nothing is echoed, so the cursor stays at the prompt;
    // moving back by the (invisible) tail would walk it into the prompt.
    const back = hidden ? 0 : this.buffer.length - this.cursor;
    if (back > 0) {
      this.inputTerm.write(`\x1b[${back}D`);
    }
    this.notifyInput();
  }

  /** Surface the current input to the autosuggest listener. Reported as empty
   * whenever a masked/confirm prompt is active, so a passphrase in progress is
   * never handed to the suggestion path. */
  private notifyInput(): void {
    if (this.inputChangeHandler === null) {
      return;
    }
    this.inputChangeHandler(this.pending === null ? this.buffer : "");
  }
}
