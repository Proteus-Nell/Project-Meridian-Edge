// The startup banner is the only onboarding a first-time user gets, so these
// tests guard the two things that make it work: it names the path to a first
// conversation, and it fits a narrow terminal without wrapping.

import { describe, expect, it } from "vitest";

import { BANNER_MAX_COLUMNS, bannerLines, visibleWidth } from "../src/terminal/banner";
import { COMMAND_USAGE, isCommandWord } from "../src/terminal/parser";

const lines = bannerLines();
const plain = lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, "")).join("\n");

describe("startup banner", () => {
  it("fits the narrow-viewport width budget on every line", () => {
    for (const line of lines) {
      expect(visibleWidth(line), JSON.stringify(line)).toBeLessThanOrEqual(BANNER_MAX_COLUMNS);
    }
  });

  it("walks a beginner through the first three steps in order", () => {
    const register = plain.indexOf("/register");
    const whoami = plain.indexOf("/whoami");
    const add = plain.indexOf("/add");
    expect(register).toBeGreaterThan(-1);
    expect(whoami).toBeGreaterThan(register);
    expect(add).toBeGreaterThan(whoami);
    expect(plain).toContain("/chat");
    expect(plain).toContain("/help");
  });

  it("explains the product in plain language before naming the cryptography", () => {
    expect(plain).toContain("private messenger");
    // The PQC name-drop is a closing footnote, not the opening pitch.
    expect(plain.indexOf("ML-KEM-768")).toBeGreaterThan(plain.indexOf("private messenger"));
  });

  it("tells the user how plain text is treated", () => {
    expect(plain.toLowerCase()).toContain("does not start with /");
  });

  it("only advertises commands the parser actually accepts", () => {
    for (const match of plain.matchAll(/\/([a-z]+)/g)) {
      const word = match[1] ?? "";
      expect(isCommandWord(word), `banner names /${word}`).toBe(true);
      expect(COMMAND_USAGE[word as keyof typeof COMMAND_USAGE]).toBeDefined();
    }
  });

  it("keeps the wordmark frame aligned", () => {
    const [top, mid, bottom] = lines;
    expect(visibleWidth(top ?? "")).toBe(visibleWidth(mid ?? ""));
    expect(visibleWidth(mid ?? "")).toBe(visibleWidth(bottom ?? ""));
  });
});
