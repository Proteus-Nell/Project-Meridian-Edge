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

/** A dated divider opens each new day in the transcript (see the day-divider
 * suite below); every other assertion in this file is about a message line, so
 * they filter the dividers out rather than indexing around them. */
const DAY_DIVIDER = /-- \w+day, \d{1,2} \w+ \d{4} --/;

function messageLines(sink: CaptureSink): string[] {
  return sink.lines.filter((line) => !DAY_DIVIDER.test(line));
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
    expect(line).toContain("Rate limit reached. Please wait a few minutes and try again.");
    expect(line).not.toContain("✗");
  });

  it("builds parameterized error messages from the catalog", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.error("E501", "mallory");
    const line = sink.lines[0] ?? "";
    expect(line).toContain("[E501]");
    expect(line).toContain("There is no contact called 'mallory'");
  });
});

describe("Renderer peer messages", () => {
  it("colors the alias label and sanitizes both untrusted fields", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.peerMessage("bob\x1b[31m", "hi\x1b[2Jthere");
    const line = messageLines(sink)[0] ?? "";
    expect(line).toContain("\x1b[96m"); // renderer's own label styling intact
    expect(line).toContain("[bob[31m]"); // alias ESC stripped
    expect(line).toContain("hi[2Jthere"); // message ESC stripped
    expect(line).not.toContain("\x1b[2J");
  });
});

describe("Renderer message timestamps", () => {
  const AT = new Date(2026, 6, 4, 21, 30, 15).getTime();

  it("stamps conversation lines with the local time by default", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7));
    renderer.peerMessage("alice", "hello there");
    renderer.ownMessage("hi back");
    const [peer, own] = messageLines(sink);
    expect(peer).toContain("09:05:07");
    expect(peer).toContain("[alice]");
    expect(peer).toContain("hello there");
    expect(own).toContain("09:05:07");
    expect(own).toContain("hi back");
  });

  it("uses the message's own instant when history is replayed", () => {
    // A view rebuild happens long after the messages it reprints; stamping
    // them with the rebuild's clock would silently rewrite the transcript.
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7));
    renderer.peerMessage("alice", "hello there", AT);
    renderer.ownMessage("hi back", AT);
    for (const line of messageLines(sink)) {
      expect(line).toContain("21:30:15");
      expect(line).not.toContain("09:05:07");
    }
  });

  it("goes back to the unstamped lines when the setting is off", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7));
    renderer.setMessageTimestamps(false);
    renderer.peerMessage("alice", "hello there", AT);
    renderer.ownMessage("hi back", AT);
    // No dividers either, so the two messages are the only two lines.
    expect(sink.lines).toHaveLength(2);
    expect(sink.lines[0]).not.toContain("21:30:15");
    expect(sink.lines[0]).not.toContain("09:05:07");
    expect(sink.lines[0]?.startsWith("  \x1b[96m[alice]")).toBe(true);
    expect(sink.lines[1]?.startsWith(`\x1b[2m> `)).toBe(true);
  });

  it("leaves typed events stamped whatever the setting says", () => {
    // The setting governs the conversation only: an event line has carried a
    // time since long before it existed.
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7));
    renderer.setMessageTimestamps(false);
    renderer.event("success", "it worked");
    renderer.error("E301");
    expect(sink.lines[0]).toContain("09:05:07");
    expect(sink.lines[1]).toContain("09:05:07");
  });

  it("closes the timestamp colour before the peer's name and text", () => {
    // Same property the marker colours have: nothing the renderer tints can
    // bleed into content.
    const sink = new CaptureSink();
    new Renderer(sink, () => new Date(2026, 6, 4, 9, 5, 7)).peerMessage("alice", "hello");
    expect(messageLines(sink)[0]).toContain("\x1b[2m09:05:07\x1b[0m ");
  });
});

describe("Renderer day dividers", () => {
  const JUL_4 = new Date(2026, 6, 4, 21, 30, 15).getTime();
  const JUL_5 = new Date(2026, 6, 5, 9, 5, 7).getTime();
  const JUL_5_LATER = new Date(2026, 6, 5, 23, 59, 59).getTime();

  it("dates the first conversation line, whatever day it is", () => {
    const sink = new CaptureSink();
    new Renderer(sink).peerMessage("alice", "hello", JUL_4);
    expect(sink.lines[0]).toContain("-- Saturday, 4 July 2026 --");
    expect(sink.lines[1]).toContain("hello");
  });

  it("opens a new day once, and stays quiet inside it", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.peerMessage("alice", "see you next week", JUL_4);
    renderer.peerMessage("alice", "morning", JUL_5);
    renderer.ownMessage("morning", JUL_5_LATER);
    const dividers = sink.lines.filter((l) => l.includes("2026 --"));
    expect(dividers).toHaveLength(2);
    expect(dividers[0]).toContain("-- Saturday, 4 July 2026 --");
    expect(dividers[1]).toContain("-- Sunday, 5 July 2026 --");
  });

  it("dates a live message from the clock when no instant is given", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 7, 27, 9, 5, 7));
    renderer.peerMessage("alice", "morning");
    expect(sink.lines[0]).toContain("-- Thursday, 27 August 2026 --");
  });

  it("dates the next line again after the screen is cleared", () => {
    // The dividers on screen went with the wipe, so the day the transcript is
    // on is no longer visible and has to be restated.
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.peerMessage("alice", "hello", JUL_4);
    renderer.resetMessageDay();
    renderer.peerMessage("alice", "hello again", JUL_4);
    expect(sink.lines.filter((l) => l.includes("4 July 2026"))).toHaveLength(2);
  });

  it("prints no divider while /settings timestamps is off", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.setMessageTimestamps(false);
    renderer.peerMessage("alice", "see you next week", JUL_4);
    renderer.peerMessage("alice", "morning", JUL_5);
    expect(sink.lines).toHaveLength(2);
    expect(sink.lines.some((l) => l.includes("2026"))).toBe(false);
  });

  it("marks the day for a line it does not print itself (the sent echo)", () => {
    // chrome.echoInput writes your own message and calls this first, so the
    // divider lands above an echo the renderer never sees.
    const sink = new CaptureSink();
    const renderer = new Renderer(sink, () => new Date(2026, 7, 27, 9, 5, 7));
    renderer.markMessageDay();
    expect(sink.lines[0]).toContain("-- Thursday, 27 August 2026 --");
    // ... and the reply that follows on the same day does not repeat it.
    renderer.peerMessage("alice", "morning", new Date(2026, 7, 27, 9, 6, 0).getTime());
    expect(sink.lines.filter((l) => l.includes("27 August 2026"))).toHaveLength(1);
  });

  it("splits days by the local clock, not UTC", () => {
    // The divider sits beside a local HH:MM:SS, so it has to agree with it: a
    // late-evening message belongs to the day the reader saw on the clock.
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.peerMessage("alice", "late", new Date(2026, 6, 4, 23, 30, 0).getTime());
    renderer.peerMessage("alice", "later", new Date(2026, 6, 4, 23, 59, 59).getTime());
    expect(sink.lines.filter((l) => l.includes("2026 --"))).toHaveLength(1);
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
    expect(status.last).toEqual({ level: "failure", text: "[E203] Unlock failed. Please check your passphrase and try again." });
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

// The property that makes /settings color event safe to expose: a marker
// colour can be set to anything, including the background, without ever
// making the WORDS of an event unreadable. Every colour sequence is closed
// before the message text begins, so the text renders in the scheme's default
// foreground no matter what the marker was set to.
describe("event colour never reaches the message text", () => {
  const SGR = /\x1b\[[0-9;]*m/g; // eslint-disable-line no-control-regex

  /** The portion of a line after the last colour reset: what the terminal
   * paints in the default foreground. */
  function uncoloredTail(line: string): string {
    const lastReset = line.lastIndexOf("\x1b[0m");
    return lastReset === -1 ? "" : line.slice(lastReset + 4);
  }

  it("closes the marker colour before the message on every event level", () => {
    for (const level of ["success", "warning", "info", "security"] as const) {
      const sink = new CaptureSink();
      new Renderer(sink).event(level, "the message body");
      const line = sink.lines[0] ?? "";
      expect(uncoloredTail(line), level).toContain("the message body");
      // and the body itself carries no colour sequence of its own
      expect(uncoloredTail(line).match(SGR), level).toBeNull();
    }
  });

  it("closes the E-code colour before the error text", () => {
    const sink = new CaptureSink();
    new Renderer(sink).error("E301");
    const line = sink.lines[0] ?? "";
    expect(uncoloredTail(line)).toContain("Rate limit reached");
    expect(uncoloredTail(line).match(SGR)).toBeNull();
  });

  it("closes the peer-name colour before the peer's text", () => {
    const sink = new CaptureSink();
    new Renderer(sink).peerMessage("alice", "hello there");
    const line = messageLines(sink)[0] ?? "";
    expect(uncoloredTail(line)).toContain("hello there");
  });

  it("keeps the level's meaning in the marker text, not only its colour", () => {
    const sink = new CaptureSink();
    const renderer = new Renderer(sink);
    renderer.event("warning", "careful");
    renderer.event("security", "look at this");
    renderer.error("E203");
    const text = sink.lines.join("\n");
    expect(text).toContain("[!]");
    expect(text).toContain("[SECURITY]");
    expect(text).toContain("[E203]");
  });
});
