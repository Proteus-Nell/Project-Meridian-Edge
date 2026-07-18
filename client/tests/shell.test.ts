import { describe, expect, it } from "vitest";

import { Shell } from "../src/terminal/shell";
import type { SuggestionNav, TerminalLike } from "../src/terminal/shell";

class FakeNav implements SuggestionNav {
  open = false;
  accepted: string | null = null;
  moved: number[] = [];
  closed = 0;
  isOpen(): boolean {
    return this.open;
  }
  move(delta: 1 | -1): void {
    this.moved.push(delta);
  }
  accept(): string | null {
    return this.accepted;
  }
  close(): void {
    this.closed += 1;
  }
}

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

function setup(): { input: FakeTerm; output: FakeTerm; lines: string[]; shell: Shell } {
  const input = new FakeTerm();
  const output = new FakeTerm();
  const lines: string[] = [];
  const shell = new Shell(input, output, (line) => lines.push(line));
  shell.attach();
  return { input, output, lines, shell };
}

describe("Shell", () => {
  it("submits a typed line on Enter", () => {
    const { input, lines } = setup();
    input.feed("/whoami\r");
    expect(lines).toEqual(["/whoami"]);
  });

  it("handles backspace editing", () => {
    const { input, lines } = setup();
    input.feed("helpp");
    input.feed("\x7f");
    input.feed("\r");
    expect(lines).toEqual(["help"]);
  });

  it("inserts at the cursor after arrow-left", () => {
    const { input, lines } = setup();
    input.feed("hllo");
    input.feed("\x1b[D\x1b[D\x1b[D"); // left x3 → cursor after 'h'
    input.feed("e");
    input.feed("\r");
    expect(lines).toEqual(["hello"]);
  });

  it("recalls history with up/down", () => {
    const { input, lines } = setup();
    input.feed("first\r");
    input.feed("second\r");
    input.feed("\x1b[A\x1b[A"); // up x2 → "first"
    input.feed("\r");
    expect(lines).toEqual(["first", "second", "first"]);
  });

  it("kills the line with Ctrl+U", () => {
    const { input, lines } = setup();
    input.feed("garbage");
    input.feed("\x15");
    input.feed("ok\r");
    expect(lines).toEqual(["ok"]);
  });

  it("invokes the clear handler on Ctrl+L without losing the buffer", () => {
    const { input, lines, shell } = setup();
    let cleared = 0;
    shell.setClearHandler(() => {
      cleared += 1;
    });
    input.feed("keep");
    input.feed("\x0c");
    expect(cleared).toBe(1);
    input.feed("\r");
    expect(lines).toEqual(["keep"]);
  });

  it("ignores stray control bytes in pasted input", () => {
    const { input, lines } = setup();
    input.feed("a\x00\x01b\r");
    expect(lines).toEqual(["ab"]);
  });

  it("prints transcript output to the output terminal, leaving the input line untouched", () => {
    const { input, output, shell } = setup();
    const inputBefore = input.written;
    shell.printLine("hello world");
    expect(output.written).toContain("hello world\r\n");
    expect(input.written).toBe(inputBefore);
  });

  describe("Tab completion", () => {
    it("applies the completer's result to the buffer", () => {
      const { input, lines, shell } = setup();
      shell.setCompleter((buffer) => (buffer === "/lo" ? "/login" : null));
      input.feed("/lo");
      input.feed("\t");
      input.feed("\r");
      expect(lines).toEqual(["/login"]);
    });

    it("does nothing when the completer returns null", () => {
      const { input, lines, shell } = setup();
      shell.setCompleter(() => null);
      input.feed("xyz");
      input.feed("\t");
      input.feed("\r");
      expect(lines).toEqual(["xyz"]);
    });

    it("never completes during a masked prompt", async () => {
      const { input, shell } = setup();
      let called = false;
      shell.setCompleter(() => {
        called = true;
        return "leaked";
      });
      const promise = shell.readSecret("passphrase: ");
      input.feed("\t");
      expect(called).toBe(false);
      input.feed("pw\r");
      await expect(promise).resolves.toBe("pw");
    });
  });

  describe("suggestion navigation (dropdown open)", () => {
    it("routes arrows to the nav instead of history while open", () => {
      const { input, lines, shell } = setup();
      const nav = new FakeNav();
      shell.setSuggestionNav(nav);
      input.feed("first\r"); // seed history
      nav.open = true;
      input.feed("/l");
      input.feed("\x1b[A\x1b[B");
      expect(nav.moved).toEqual([-1, 1]);
      input.feed("\r"); // no highlighted row (accept null) → submits typed text
      // The buffer was never replaced by the history entry.
      expect(lines).toEqual(["first", "/l"]);
    });

    it("falls back to history when the dropdown is closed", () => {
      const { input, lines, shell } = setup();
      const nav = new FakeNav();
      shell.setSuggestionNav(nav);
      input.feed("first\r");
      nav.open = false;
      input.feed("\x1b[A\r");
      expect(nav.moved).toEqual([]);
      expect(lines).toEqual(["first", "first"]);
    });

    it("Enter fills the highlighted completion instead of submitting", () => {
      const { input, lines, shell } = setup();
      const nav = new FakeNav();
      shell.setSuggestionNav(nav);
      nav.open = true;
      nav.accepted = "/login ";
      input.feed("/lo");
      input.feed("\r"); // fills, does not submit
      expect(lines).toEqual([]);
      nav.open = false;
      nav.accepted = null;
      input.feed("\r"); // now submits the filled buffer
      expect(lines).toEqual(["/login "]);
    });

    it("Enter submits normally when no row is highlighted", () => {
      const { input, lines, shell } = setup();
      const nav = new FakeNav();
      shell.setSuggestionNav(nav);
      nav.open = true; // open but accept() returns null (nothing navigated to)
      input.feed("abc\r");
      expect(lines).toEqual(["abc"]);
    });

    it("Tab prefers the highlighted row over the prefix completer", () => {
      const { input, lines, shell } = setup();
      const nav = new FakeNav();
      let completerCalled = false;
      shell.setSuggestionNav(nav);
      shell.setCompleter(() => {
        completerCalled = true;
        return "/wrong";
      });
      nav.open = true;
      nav.accepted = "/register ";
      input.feed("/re");
      input.feed("\t");
      expect(completerCalled).toBe(false);
      nav.open = false;
      nav.accepted = null;
      input.feed("\r");
      expect(lines).toEqual(["/register "]);
    });

    it("a lone Esc closes the dropdown", () => {
      const { input, shell } = setup();
      const nav = new FakeNav();
      shell.setSuggestionNav(nav);
      nav.open = true;
      input.feed("\x1b");
      expect(nav.closed).toBe(1);
    });

    it("setBuffer replaces the line (click-to-pick) but never a pending prompt", async () => {
      const { input, lines, shell } = setup();
      shell.setBuffer("/chat ");
      input.feed("bob\r");
      expect(lines).toEqual(["/chat bob"]);

      const promise = shell.readSecret("passphrase: ");
      shell.setBuffer("evil"); // ignored while the prompt is pending
      input.feed("pw\r");
      await expect(promise).resolves.toBe("pw");
    });

    it("nav is inert during a masked prompt", async () => {
      const { input, shell } = setup();
      const nav = new FakeNav();
      shell.setSuggestionNav(nav);
      nav.open = true;
      const promise = shell.readSecret("passphrase: ");
      input.feed("\x1b[A\x1b");
      expect(nav.moved).toEqual([]);
      expect(nav.closed).toBe(0);
      input.feed("pw\r");
      await expect(promise).resolves.toBe("pw");
    });
  });

  describe("input-change notifications (autosuggest)", () => {
    it("reports the live buffer as it changes", () => {
      const { input, shell } = setup();
      const seen: string[] = [];
      shell.onInputChange((b) => seen.push(b));
      input.feed("/h");
      expect(seen[seen.length - 1]).toBe("/h");
    });

    it("reports empty during a masked prompt so a passphrase never reaches the listener", async () => {
      const { input, shell } = setup();
      const seen: string[] = [];
      shell.onInputChange((b) => seen.push(b));
      const promise = shell.readSecret("passphrase: ");
      input.feed("s");
      input.feed("e");
      expect(seen.every((b) => b === "")).toBe(true);
      input.feed("cret\r");
      await expect(promise).resolves.toBe("secret");
    });
  });

  describe("readSecret", () => {
    it("masks input, bypasses history and the line handler", async () => {
      const { input, lines, shell } = setup();
      const promise = shell.readSecret("passphrase: ");
      input.feed("hunter22");
      expect(input.written).toContain("********");
      expect(input.written).not.toContain("hunter22");
      input.feed("\r");
      await expect(promise).resolves.toBe("hunter22");
      expect(lines).toEqual([]); // never reached the line handler
      input.feed("\x1b[A\r"); // history recall: secret must not be there
      expect(lines).toEqual([""]);
    });

    it("resolves null on Ctrl+C and restores the prompt", async () => {
      const { input, output, shell } = setup();
      const promise = shell.readSecret("passphrase: ");
      input.feed("abc");
      input.feed("\x03");
      await expect(promise).resolves.toBeNull();
      expect(output.written).toContain("^C"); // cancel echoed to the transcript
      input.feed("visible\r");
      expect(input.written).toContain("visible");
    });

    it("hidden mask mode echoes nothing but still captures input", async () => {
      const { input, lines, shell } = setup();
      shell.setSecretMask("hidden");
      const promise = shell.readSecret("passphrase: ");
      input.feed("hunter22");
      expect(input.written).not.toContain("*");
      expect(input.written).not.toContain("hunter22");
      input.feed("\r");
      await expect(promise).resolves.toBe("hunter22");
      expect(lines).toEqual([]);
    });

    it("switching mask style back to asterisk restores echoing", async () => {
      const { input, shell } = setup();
      shell.setSecretMask("hidden");
      shell.setSecretMask("asterisk");
      const promise = shell.readSecret("passphrase: ");
      input.feed("abcd");
      expect(input.written).toContain("****");
      input.feed("\r");
      await expect(promise).resolves.toBe("abcd");
    });

    it("editing works in hidden mode (backspace) without leaking", async () => {
      const { input, shell } = setup();
      shell.setSecretMask("hidden");
      const promise = shell.readSecret("unlock: ");
      input.feed("passXX");
      input.feed("\x7f\x7f"); // erase the two X's
      input.feed("word");
      input.feed("\r");
      // No echoed input characters at all - not the interim nor the result.
      for (const leak of ["passXX", "password", "word"]) {
        expect(input.written).not.toContain(leak);
      }
      await expect(promise).resolves.toBe("password");
    });
  });

  describe("readLine", () => {
    it("echoes input visibly but still bypasses history and the handler", async () => {
      const { input, lines, shell } = setup();
      const promise = shell.readLine("rotate anyway? (y/N): ");
      input.feed("y");
      expect(input.written).toContain("rotate anyway? (y/N): y");
      input.feed("\r");
      await expect(promise).resolves.toBe("y");
      expect(lines).toEqual([]);
      input.feed("\x1b[A\r"); // history must not contain the answer
      expect(lines).toEqual([""]);
    });
  });
});
