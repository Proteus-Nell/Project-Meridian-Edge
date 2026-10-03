// The copy button beside /whoami's UID: where it can sit on the line the
// renderer printed, and how a click reaches the clipboard. chrome.ts wires
// these to real xterm markers and a real <button>; everything that decides
// anything lives in copy.ts, tested here against a buffer laid out the way
// xterm lays one out.

import { describe, expect, it } from "vitest";

import {
  COPY_CELLS,
  firstRowOf,
  locateValue,
  needsOwnRow,
  placeCopyButton,
  writeClipboard,
} from "../src/terminal/copy";
import type { BufferView } from "../src/terminal/copy";

/** Rows of a terminal `cols` wide, filled the way xterm fills them: a line
 * longer than a row continues on the next, flagged isWrapped; one that exactly
 * fills its last row does not spill an empty one. */
class FakeBuffer implements BufferView {
  private readonly rows: { text: string; isWrapped: boolean }[] = [];

  constructor(private readonly cols: number) {}

  /** Print a line, returning the row it starts on. */
  print(line: string): number {
    const start = this.rows.length;
    if (line.length === 0) {
      this.rows.push({ text: "", isWrapped: false });
      return start;
    }
    for (let i = 0; i < line.length; i += this.cols) {
      this.rows.push({ text: line.slice(i, i + this.cols), isWrapped: i > 0 });
    }
    return start;
  }

  getLine(y: number): ReturnType<BufferView["getLine"]> {
    const row = this.rows[y];
    if (row === undefined) {
      return undefined;
    }
    return {
      isWrapped: row.isWrapped,
      translateToString: (trimRight = false, startColumn = 0, endColumn = this.cols) => {
        const cells = row.text.padEnd(this.cols).slice(startColumn, endColumn);
        return trimRight ? cells.trimEnd() : cells;
      },
    };
  }
}

const UID = "7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ01-23";
/** What /whoami prints, as it reaches the screen: 50 cells, with the UID
 * starting at cell 18. */
const UID_LINE = `12:34:56 [*] UID: ${UID}`;

describe("needsOwnRow", () => {
  it("leaves the button beside a line with room after it", () => {
    expect(needsOwnRow(UID_LINE.length, 80)).toBe(false);
    // 50 cells, a cell of gap, then the button: exactly 57.
    expect(needsOwnRow(UID_LINE.length, 50 + 1 + COPY_CELLS)).toBe(false);
  });

  it("reserves a row when the line ends too close to the edge", () => {
    expect(needsOwnRow(UID_LINE.length, 50 + COPY_CELLS)).toBe(true);
    // The band a large phone's portrait width lands in.
    expect(needsOwnRow(UID_LINE.length, 52)).toBe(true);
  });

  it("reserves a row when the line exactly fills its last row", () => {
    expect(needsOwnRow(UID_LINE.length, 50)).toBe(true);
    expect(needsOwnRow(UID_LINE.length, 25)).toBe(true); // two full rows
  });

  it("measures only the last row of a wrapped line", () => {
    // 40 + 10: the second row has room.
    expect(needsOwnRow(UID_LINE.length, 40)).toBe(false);
  });
});

describe("firstRowOf", () => {
  it("walks back over continuation rows to where the line starts", () => {
    const buffer = new FakeBuffer(20);
    buffer.print("before");
    const start = buffer.print(UID_LINE); // 20 + 20 + 10
    expect(firstRowOf(buffer, start + 2)).toBe(start);
    expect(firstRowOf(buffer, start)).toBe(start);
  });

  it("does not run back into the previous line", () => {
    const buffer = new FakeBuffer(20);
    const before = buffer.print("x".repeat(30)); // wraps itself
    const start = buffer.print("short");
    expect(firstRowOf(buffer, start)).toBe(start);
    expect(firstRowOf(buffer, before + 1)).toBe(before);
  });
});

describe("placeCopyButton", () => {
  it("sits one cell clear of the end of the line when there is room", () => {
    const buffer = new FakeBuffer(80);
    const start = buffer.print(UID_LINE);
    expect(placeCopyButton(buffer, start, null, 80, UID)).toEqual({ row: start, x: 51 });
  });

  it("follows a wrapped line onto the row where it ends", () => {
    const buffer = new FakeBuffer(40);
    const start = buffer.print(UID_LINE); // 40 + 10
    expect(placeCopyButton(buffer, start, null, 40, UID)).toEqual({ row: start + 1, x: 11 });
  });

  it("drops to the reserved row, under the value, when it does not fit beside", () => {
    const buffer = new FakeBuffer(52);
    const start = buffer.print(UID_LINE);
    const spare = buffer.print("");
    expect(placeCopyButton(buffer, start, spare, 52, UID)).toEqual({ row: spare, x: 18 });
  });

  it("goes nowhere rather than over text when no row was reserved", () => {
    const buffer = new FakeBuffer(52);
    const start = buffer.print(UID_LINE);
    buffer.print("12:34:56 [*] identity-key fingerprint (SHA-512/128): 00ff");
    expect(placeCopyButton(buffer, start, null, 52, UID)).toBeNull();
    // A reserved row that has since scrolled away counts as none.
    expect(placeCopyButton(buffer, start, -1, 52, UID)).toBeNull();
  });

  it("keeps a button on the reserved row inside the screen", () => {
    const buffer = new FakeBuffer(34);
    const start = buffer.print(`${"x".repeat(30)}ABCD`); // fills the row
    const spare = buffer.print("");
    expect(placeCopyButton(buffer, start, spare, 34, "ABCD")).toEqual({
      row: spare,
      x: 34 - COPY_CELLS,
    });
  });

  it("moves back beside the line once a resize leaves room again", () => {
    // The same line and reserved row, laid out again after the screen widened.
    const buffer = new FakeBuffer(90);
    const start = buffer.print(UID_LINE);
    const spare = buffer.print("");
    expect(placeCopyButton(buffer, start, spare, 90, UID)).toEqual({ row: start, x: 51 });
  });

  it("fits nowhere on a screen narrower than the button", () => {
    const buffer = new FakeBuffer(COPY_CELLS - 1);
    const start = buffer.print(UID_LINE);
    const spare = buffer.print("");
    expect(placeCopyButton(buffer, start, spare, COPY_CELLS - 1, UID)).toBeNull();
  });
});

describe("locateValue", () => {
  it("finds the value on the line's first row", () => {
    const buffer = new FakeBuffer(80);
    const start = buffer.print(UID_LINE);
    expect(locateValue(buffer, start, 80, UID)).toEqual({ row: start, col: 18 });
  });

  it("finds a value that starts on a continuation row", () => {
    const buffer = new FakeBuffer(10);
    const start = buffer.print(UID_LINE);
    expect(locateValue(buffer, start, 10, UID)).toEqual({ row: start + 1, col: 8 });
  });

  it("reads only the logical line it was given", () => {
    const buffer = new FakeBuffer(80);
    const start = buffer.print("12:34:56 [*] something else");
    buffer.print(UID_LINE);
    expect(locateValue(buffer, start, 80, UID)).toBeNull();
    expect(locateValue(buffer, start, 80, "")).toBeNull();
  });
});

describe("writeClipboard", () => {
  it("writes exactly the value and reports success", async () => {
    const written: string[] = [];
    const host = {
      clipboard: {
        writeText: (text: string) => {
          written.push(text);
          return Promise.resolve();
        },
      },
    };
    expect(await writeClipboard(UID, host)).toBe(true);
    expect(written).toEqual([UID]);
  });

  it("reports failure where there is no clipboard, as over plain http", async () => {
    expect(await writeClipboard(UID, {})).toBe(false);
    expect(await writeClipboard(UID, undefined)).toBe(false);
  });

  it("reports a refused write as a failure instead of throwing", async () => {
    const host = {
      clipboard: {
        writeText: () => Promise.reject(new DOMException("denied", "NotAllowedError")),
      },
    };
    expect(await writeClipboard(UID, host)).toBe(false);
  });
});
