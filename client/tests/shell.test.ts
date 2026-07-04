import { describe, expect, it } from "vitest";

import { Shell } from "../src/terminal/shell";
import type { TerminalLike } from "../src/terminal/shell";

class FakeTerm implements TerminalLike {
  written = "";
  private handler: ((data: string) => void) | null = null;

  write(data: string): void {
    this.written += data;
  }

  onData(handler: (data: string) => void): void {
    this.handler = handler;
  }

  feed(data: string): void {
    if (this.handler === null) {
      throw new Error("shell not attached");
    }
    this.handler(data);
  }
}

function setup(): { term: FakeTerm; lines: string[]; shell: Shell } {
  const term = new FakeTerm();
  const lines: string[] = [];
  const shell = new Shell(term, (line) => lines.push(line));
  shell.attach();
  return { term, lines, shell };
}

describe("Shell", () => {
  it("submits a typed line on Enter", () => {
    const { term, lines } = setup();
    term.feed("/whoami\r");
    expect(lines).toEqual(["/whoami"]);
  });

  it("handles backspace editing", () => {
    const { term, lines } = setup();
    term.feed("helpp");
    term.feed("\x7f");
    term.feed("\r");
    expect(lines).toEqual(["help"]);
  });

  it("inserts at the cursor after arrow-left", () => {
    const { term, lines } = setup();
    term.feed("hllo");
    term.feed("\x1b[D\x1b[D\x1b[D"); // left x3 → cursor after 'h'
    term.feed("e");
    term.feed("\r");
    expect(lines).toEqual(["hello"]);
  });

  it("recalls history with up/down", () => {
    const { term, lines } = setup();
    term.feed("first\r");
    term.feed("second\r");
    term.feed("\x1b[A\x1b[A"); // up x2 → "first"
    term.feed("\r");
    expect(lines).toEqual(["first", "second", "first"]);
  });

  it("kills the line with Ctrl+U", () => {
    const { term, lines } = setup();
    term.feed("garbage");
    term.feed("\x15");
    term.feed("ok\r");
    expect(lines).toEqual(["ok"]);
  });

  it("clears the screen on Ctrl+L without losing the buffer", () => {
    const { term, lines } = setup();
    term.feed("keep");
    term.feed("\x0c");
    expect(term.written).toContain("\x1b[2J");
    term.feed("\r");
    expect(lines).toEqual(["keep"]);
  });

  it("ignores stray control bytes in pasted input", () => {
    const { term, lines } = setup();
    term.feed("a\x00\x01b\r");
    expect(lines).toEqual(["ab"]);
  });

  describe("readSecret", () => {
    it("masks input, bypasses history and the line handler", async () => {
      const { term, lines, shell } = setup();
      const promise = shell.readSecret("passphrase: ");
      term.feed("hunter22");
      expect(term.written).toContain("********");
      expect(term.written).not.toContain("hunter22");
      term.feed("\r");
      await expect(promise).resolves.toBe("hunter22");
      expect(lines).toEqual([]); // never reached the line handler
      term.feed("\x1b[A\r"); // history recall: secret must not be there
      expect(lines).toEqual([""]);
    });

    it("resolves null on Ctrl+C and restores the prompt", async () => {
      const { term, shell } = setup();
      const promise = shell.readSecret("passphrase: ");
      term.feed("abc");
      term.feed("\x03");
      await expect(promise).resolves.toBeNull();
      term.feed("visible\r");
      expect(term.written).toContain("visible");
    });
  });
});
