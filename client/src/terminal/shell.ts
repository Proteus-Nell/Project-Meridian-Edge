// Line discipline over xterm.js (CLAUDE.md §1.1): single-line editing with
// cursor movement, history (up/down), Ctrl+L clear, Ctrl+U kill-line. The
// shell owns the prompt; output from elsewhere goes through printLine so the
// input line is cleanly redrawn under it (needed for async command output).

import type { LineSink } from "./renderer";

/** The subset of xterm.js Terminal the shell needs (test seam). */
export interface TerminalLike {
  write(data: string): void;
  onData(handler: (data: string) => void): void;
}

const MAX_LINE_LENGTH = 4096;
const MAX_HISTORY = 100;

interface SecretRequest {
  resolve: (value: string | null) => void;
  savedPrompt: string;
}

export class Shell implements LineSink {
  private buffer = "";
  private cursor = 0;
  private history: string[] = [];
  private historyIndex = -1; // -1 = editing a fresh line
  private draft = "";
  private prompt = "> ";
  private secret: SecretRequest | null = null;

  constructor(
    private readonly term: TerminalLike,
    private readonly onLine: (line: string) => void,
  ) {}

  /** Masked input for passphrases: echoes '*', bypasses history and the
   * line handler. Resolves null if the user cancels with Ctrl+C. */
  readSecret(promptText: string): Promise<string | null> {
    return new Promise((resolve) => {
      this.secret = { resolve, savedPrompt: this.prompt };
      this.buffer = "";
      this.cursor = 0;
      this.historyIndex = -1;
      this.prompt = promptText;
      this.redraw();
    });
  }

  attach(): void {
    this.term.onData((data) => this.handleData(data));
    this.redraw();
  }

  setPrompt(prompt: string): void {
    this.prompt = prompt;
    this.redraw();
  }

  printLine(line: string): void {
    // Clear the input line, print the output, then restore prompt + buffer.
    this.term.write(`\r\x1b[2K${line}\r\n`);
    this.redraw();
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
    if (data.startsWith("\x1b[A")) {
      this.historyPrev();
      return 3;
    }
    if (data.startsWith("\x1b[B")) {
      this.historyNext();
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
        this.submit();
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
        // Ctrl+L: clear screen, keep the current input line
        this.term.write("\x1b[2J\x1b[H");
        this.redraw();
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
        // Ctrl+C: abandon the current line (cancels a secret prompt)
        this.term.write("^C\r\n");
        this.buffer = "";
        this.cursor = 0;
        this.historyIndex = -1;
        if (this.secret !== null) {
          const pending = this.secret;
          this.secret = null;
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

  private submit(): void {
    const line = this.buffer;
    this.term.write("\r\n");
    this.buffer = "";
    this.cursor = 0;
    this.historyIndex = -1;
    if (this.secret !== null) {
      // Secret lines never touch history or the line handler.
      const pending = this.secret;
      this.secret = null;
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
    if (this.history.length === 0 || this.secret !== null) {
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
    if (this.historyIndex === -1 || this.secret !== null) {
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
    const shown = this.secret !== null ? "*".repeat(this.buffer.length) : this.buffer;
    this.term.write(`\r\x1b[2K${this.prompt}${shown}`);
    const back = this.buffer.length - this.cursor;
    if (back > 0) {
      this.term.write(`\x1b[${back}D`);
    }
  }
}
