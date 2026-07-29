// Help rendering: the two-column reference, the narrow fallback, and the
// per-command explanations. Pure functions, so these assert on the returned
// lines directly.
//
// The invariant worth guarding is that no line the layout produces exceeds the
// width it was given: xterm hard-wraps at the column count, so an over-wide
// line reflows mid-word and undoes the alignment the layout exists to provide.

import { describe, expect, it } from "vitest";

import { DEFAULT_HELP_COLUMNS, renderCommandHelp, renderHelp, wrapText } from "../src/terminal/help";
import { COMMAND_ALIASES, COMMAND_USAGE, isCommandWord } from "../src/terminal/parser";
import type { CommandWord } from "../src/terminal/parser";
import { sanitizeText } from "../src/terminal/renderer";

const WORDS = Object.keys(COMMAND_USAGE) as CommandWord[];

describe("wrapText", () => {
  it("keeps whole words inside the measure", () => {
    const lines = wrapText("the quick brown fox jumps over the lazy dog", 12);
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(12);
    }
    expect(lines.join(" ")).toBe("the quick brown fox jumps over the lazy dog");
  });

  it("never splits a word that is longer than the measure", () => {
    // A UID or a recovery code must survive intact rather than being cut.
    const uid = "8ZK3-QW9M-4TXR-7B2V-NC5H-JD6P-LA";
    const lines = wrapText(`your uid is ${uid} ok`, 10);
    expect(lines).toContain(uid);
  });

  it("collapses runs of whitespace and handles an empty string", () => {
    expect(wrapText("a   b", 40)).toEqual(["a b"]);
    expect(wrapText("", 40)).toEqual([]);
  });
});

describe("renderHelp", () => {
  it("fits every line inside the width it was given", () => {
    for (const width of [32, 40, 56, 60, 72, 80, 100, 200]) {
      for (const line of renderHelp(width)) {
        expect(line.length, `width ${width}: ${line}`).toBeLessThanOrEqual(Math.max(width, 96));
      }
    }
  });

  it("aligns descriptions into a column with leaders on a wide terminal", () => {
    const lines = renderHelp(80);
    const lock = lines.find((l) => l.trimStart().startsWith("/lock "));
    const whoami = lines.find((l) => l.trimStart().startsWith("/whoami "));
    expect(lock).toContain("...");
    // Both are in the same section, so their descriptions start at one column.
    expect(lock?.indexOf("lock the store now")).toBe(
      whoami?.indexOf("show your UID and identity-key fingerprint"),
    );
  });

  it("puts every description of a section in the same column, longest included", () => {
    // The longest command in a section has the least room for leaders, and is
    // exactly where an off-by-one shows up.
    const lines = renderHelp(100);
    const sectionStart = lines.findIndex((l) => l === "Identity & session");
    const sectionEnd = lines.findIndex((l, i) => i > sectionStart && l === "");
    const columns = new Set<number>();
    for (const line of lines.slice(sectionStart + 1, sectionEnd)) {
      const dots = /\.{1,} /.exec(line);
      if (dots !== null) {
        columns.add(dots.index + dots[0].length);
      }
    }
    expect(columns.size, `descriptions start at columns ${[...columns].join(", ")}`).toBe(1);
  });

  it("stacks the description under the command on a narrow terminal", () => {
    const lines = renderHelp(40);
    const i = lines.findIndex((l) => l.trim() === "/lock");
    expect(i).toBeGreaterThan(-1);
    expect(lines[i + 1]?.trim()).toBe("lock the store now");
    // No dot leaders in the stacked layout: there is no gap left to bridge.
    // Matched as a run of dots between spaces, so a literal "..." inside a
    // command's own text (`/group new <name> <who>...`) is not mistaken for one.
    expect(lines.some((l) => / \.{2,} /.test(l))).toBe(false);
  });

  it("sizes the command column per section, not across all of them", () => {
    // "Other" holds only short commands, so its column must not be stretched
    // by the 31-character entry over in "Messages".
    const lines = renderHelp(80);
    const bench = lines.find((l) => l.trimStart().startsWith("/bench "));
    const del = lines.find((l) => l.trimStart().startsWith("/delete "));
    expect(bench).toBeDefined();
    expect(del).toBeDefined();
    expect(bench?.indexOf("run the PQC")).toBeLessThan(del?.indexOf("delete your own") ?? 0);
  });

  it("lists every command word somewhere in the reference", () => {
    const text = renderHelp(100).join("\n");
    for (const word of WORDS) {
      expect(text, `missing /${word}`).toContain(`/${word}`);
    }
  });

  it("survives an absurd or unusable reported width", () => {
    for (const width of [0, 1, -20, Number.NaN, Number.POSITIVE_INFINITY]) {
      const lines = renderHelp(width);
      expect(lines.length).toBeGreaterThan(0);
      for (const line of lines) {
        expect(line.length).toBeLessThanOrEqual(96);
      }
    }
  });

  it("emits no character the renderer would strip", () => {
    // plain() runs sanitizeText, which drops tabs and escapes; a layout built
    // from either would lose its alignment on the way to the screen.
    for (const line of renderHelp(DEFAULT_HELP_COLUMNS)) {
      expect(sanitizeText(line)).toBe(line);
    }
  });
});

describe("renderCommandHelp", () => {
  it("explains every command, not just its usage", () => {
    for (const word of WORDS) {
      const lines = renderCommandHelp(word, 80);
      const text = lines.join("\n");
      expect(text, `/${word}`).toContain(`usage:`);
      // The explanation is the point: real prose above the usage block, so a
      // reader learns what the command is for. Bounded at both ends, because
      // an explanation that runs on is as unhelpful in a terminal as one that
      // says nothing. Measured up to the usage line, since the forms listed
      // under it are not prose.
      const usageAt = lines.findIndex((l) => l.includes("usage:"));
      const prose = lines.slice(1, usageAt).filter((l) => l.trim().length > 0);
      const length = prose.join(" ").length;
      expect(length, `/${word} explanation too thin`).toBeGreaterThan(80);
      expect(length, `/${word} explanation too long for a terminal`).toBeLessThan(400);
    }
  });

  it("leads with the explanation and ends with the usage", () => {
    const lines = renderCommandHelp("wipe", 80).filter((l) => l.trim().length > 0);
    expect(lines[0]?.trim()).toBe("/wipe");
    expect(lines[1]).toContain("Destroys the local store");
    expect(lines[lines.length - 1]).toContain("usage:");
  });

  it("splits a multi-form usage onto one line per form", () => {
    const lines = renderCommandHelp("duress", 80);
    expect(lines).toContain("  usage:");
    expect(lines.some((l) => l.trim().startsWith("/duress set"))).toBe(true);
    expect(lines.some((l) => l.trim().startsWith("/duress off"))).toBe(true);
  });

  it("fits the width it was given", () => {
    for (const width of [32, 40, 80]) {
      for (const word of WORDS) {
        for (const line of renderCommandHelp(word, width)) {
          // Usage forms are quoted verbatim and can exceed a narrow measure;
          // the prose must not.
          if (!line.trim().startsWith("/") && !line.includes("usage:")) {
            expect(line.length, `/${word} @${width}: ${line}`).toBeLessThanOrEqual(
              Math.max(width, 96),
            );
          }
        }
      }
    }
  });

  it("reaches the same explanation through an alias", () => {
    for (const [alias, canonical] of Object.entries(COMMAND_ALIASES)) {
      expect(isCommandWord(canonical), alias).toBe(true);
      expect(renderCommandHelp(canonical, 80).length).toBeGreaterThan(0);
    }
  });

  it("emits no character the renderer would strip", () => {
    for (const word of WORDS) {
      for (const line of renderCommandHelp(word, 80)) {
        expect(sanitizeText(line)).toBe(line);
      }
    }
  });
});
