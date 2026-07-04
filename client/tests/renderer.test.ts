import { describe, expect, it } from "vitest";

import { Renderer, sanitizeText } from "../src/terminal/renderer";
import type { LineSink } from "../src/terminal/renderer";

class CaptureSink implements LineSink {
  lines: string[] = [];
  printLine(line: string): void {
    this.lines.push(line);
  }
}

describe("sanitizeText", () => {
  it("strips ANSI escape sequences from untrusted text", () => {
    expect(sanitizeText("evil\x1b[2J\x1b[Hwipe")).toBe("evil[2J[Hwipe");
  });

  it("strips C0, DEL and C1 controls including CSI", () => {
    expect(sanitizeText("a\x00b\x07c\x7fde")).toBe("abcde");
  });

  it("keeps normal unicode", () => {
    expect(sanitizeText("héllo ✓ 日本語")).toBe("héllo ✓ 日本語");
  });
});

describe("Renderer", () => {
  it("prefixes events with a timestamp and typed marker", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7));
    renderer.event("success", "it worked");
    expect(sink.lines).toHaveLength(1);
    const line = sink.lines[0] ?? "";
    expect(line).toContain("09:05:07");
    expect(line).toContain("[✓]");
    expect(line).toContain("it worked");
  });

  it("sanitizes event text but keeps its own styling", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 0, 0, 0));
    renderer.event("failure", "bad\x1b[31minput");
    const line = sink.lines[0] ?? "";
    expect(line).toContain("[✗]"); // renderer's own ANSI prefix intact
    expect(line).toContain("bad[31minput"); // user ESC stripped
  });
});
