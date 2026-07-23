import { describe, expect, it } from "vitest";

import { Renderer, sanitizeText } from "../src/terminal/renderer";
import type { EventLevel, LineSink, NoticeSink, StatusSink } from "../src/terminal/renderer";

class CaptureSink implements LineSink {
  lines: string[] = [];
  printLine(line: string): void {
    this.lines.push(line);
  }
}

class CaptureStatus implements StatusSink {
  last: { level: EventLevel; text: string } | null = null;
  status(level: EventLevel, text: string): void {
    this.last = { level, text };
  }
}

class CaptureNotices implements NoticeSink {
  notices: { code: string; text: string }[] = [];
  noteDiscarded(code: string, text: string): void {
    this.notices.push({ code, text });
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
    renderer.event("warning", "bad\x1b[31minput");
    const line = sink.lines[0] ?? "";
    expect(line).toContain("[!]"); // renderer's own ANSI prefix intact
    expect(line).toContain("bad[31minput"); // user ESC stripped
  });

  it("renders failures with their catalogued E-code instead of a glyph", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7));
    renderer.error("E301");
    const line = sink.lines[0] ?? "";
    expect(line).toContain("[E301]");
    expect(line).toContain("rate limit reached - try again later");
    expect(line).not.toContain("✗");
  });

  it("builds parameterized error messages from the catalog", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.error("E501", "mallory");
    const line = sink.lines[0] ?? "";
    expect(line).toContain("[E501]");
    expect(line).toContain("unknown contact: mallory - /add <uid> [alias] first");
  });
});

describe("Renderer peer messages", () => {
  it("colors the alias label and sanitizes both untrusted fields", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.peerMessage("bob\x1b[31m", "hi\x1b[2Jthere");
    const line = sink.lines[0] ?? "";
    expect(line).toContain("\x1b[96m"); // renderer's own label styling intact
    expect(line).toContain("[bob[31m]"); // alias ESC stripped
    expect(line).toContain("hi[2Jthere"); // message ESC stripped
    expect(line).not.toContain("\x1b[2J");
  });
});

describe("Renderer status strip", () => {
  it("mirrors the latest event into the status sink (sanitized, no ANSI)", () => {
    const sink = new CaptureSink();
    const status = new CaptureStatus();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 0, 0, 0), status);
    renderer.event("warning", "bad\x1b[31minput");
    expect(status.last).toEqual({ level: "warning", text: "bad[31minput" });
  });

  it("mirrors failures with the E-code embedded in the status text", () => {
    const sink = new CaptureSink();
    const status = new CaptureStatus();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 0, 0, 0), status);
    renderer.error("E203");
    expect(status.last).toEqual({ level: "failure", text: "[E203] unlock failed" });
  });

  it("status() updates the strip only, with no transcript line", () => {
    const sink = new CaptureSink();
    const status = new CaptureStatus();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 0, 0, 0), status);
    renderer.status("success", "sent to bob");
    expect(status.last).toEqual({ level: "success", text: "sent to bob" });
    expect(sink.lines).toEqual([]);
  });

  it("is a no-op without a status sink (default)", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    expect(() => renderer.status("info", "noop")).not.toThrow();
    expect(sink.lines).toEqual([]);
  });
});

describe("Renderer discarded-message notices", () => {
  it("routes to the notice panel and status strip, never the transcript", () => {
    const sink = new CaptureSink();
    const status = new CaptureStatus();
    const notices = new CaptureNotices();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 0, 0, 0), status, notices);

    renderer.discarded("E505");

    // The whole point: an inbound discard must not interrupt the transcript.
    expect(sink.lines).toEqual([]);
    expect(notices.notices).toHaveLength(1);
    expect(notices.notices[0]?.code).toBe("E505");
    expect(notices.notices[0]?.text).toContain("cannot read");
    expect(notices.notices[0]?.text).toContain("/chat");
    // Surfaced once on the strip so it is noticed, as a warning not a failure.
    expect(status.last?.level).toBe("warning");
    expect(status.last?.text).toContain("[E505]");
  });

  it("explains a stale-prekey contact attempt as someone trying to reach you", () => {
    const notices = new CaptureNotices();
    const renderer = new Renderer(new CaptureSink(), undefined, null, notices);
    renderer.discarded("E511");
    expect(notices.notices[0]?.text).toContain("trying to start a conversation");
    expect(notices.notices[0]?.text).toContain("/remove");
  });

  it("does not claim a contact attempt for damaged envelopes", () => {
    const notices = new CaptureNotices();
    const renderer = new Renderer(new CaptureSink(), undefined, null, notices);
    renderer.discarded("E512");
    expect(notices.notices[0]?.text).toContain("damaged or tampered");
    expect(notices.notices[0]?.text).not.toContain("trying to start");
  });

  it("is a no-op without a notice sink (headless default)", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    expect(() => renderer.discarded("E507")).not.toThrow();
    expect(sink.lines).toEqual([]);
  });
});
