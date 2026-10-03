// Copying a value out of the transcript - the UID /whoami prints - through a
// button beside it: where that button can sit, and how a click reaches the
// clipboard. Pure functions over a small view of xterm's buffer and of the
// browser's navigator, so they are unit-tested without a DOM; chrome.ts builds
// the button and pins it.
//
// The button is anchored to the row the app printed, never found by matching
// text. A peer who sends a message reading "UID: ..." gets no button, because
// nothing about their line was ever offered one.

/** The slice of xterm's IBuffer this module reads. */
export interface BufferView {
  getLine(y: number):
    | {
        readonly isWrapped: boolean;
        translateToString(trimRight?: boolean, startColumn?: number, endColumn?: number): string;
      }
    | undefined;
}

/** What the button says. What assistive technology reads names the value. */
export const COPY_TEXT = "copy";

/** Cells the button spans: its word plus a cell of padding either side. */
export const COPY_CELLS = COPY_TEXT.length + 2;

/** Blank cells between the end of the value and the button. */
const COPY_GAP = 1;

/** Whether a line `cells` wide, printed at `cols` columns, ends too close to
 * the right edge for the button to sit beside it. Decided from the line's width
 * at the moment it is printed, because the row reserved under it has to be
 * written in sequence with it. */
export function needsOwnRow(cells: number, cols: number): boolean {
  // xterm wraps only when another character arrives, so a line that exactly
  // fills its last row ends on that row rather than spilling an empty one.
  const lastRow = cells <= 0 ? 0 : ((cells - 1) % cols) + 1;
  return lastRow + COPY_GAP + COPY_CELLS > cols;
}

/** The first row of the logical line `row` belongs to. xterm lays a long line
 * over several rows, marking each continuation row isWrapped. */
export function firstRowOf(buffer: BufferView, row: number): number {
  let first = row;
  while (first > 0 && buffer.getLine(first)?.isWrapped === true) {
    first -= 1;
  }
  return first;
}

function lastRowOf(buffer: BufferView, start: number): number {
  let last = start;
  while (buffer.getLine(last + 1)?.isWrapped === true) {
    last += 1;
  }
  return last;
}

/** The text of the logical line starting at `start`, as one string whose
 * offsets map back to cells. A row followed by a continuation is full by
 * definition of a wrap, so it is read at exactly `cols` cells (a row can hold
 * stale cells past `cols` after a resize); only the last row is trimmed. One
 * character per cell, which holds for the ASCII a copyable line carries. */
function logicalText(buffer: BufferView, start: number, cols: number): string {
  const last = lastRowOf(buffer, start);
  let text = "";
  for (let row = start; row < last; row += 1) {
    text += buffer.getLine(row)?.translateToString(false, 0, cols) ?? "";
  }
  return text + (buffer.getLine(last)?.translateToString(true) ?? "");
}

/** A cell for the button: the buffer row, and the column its left edge sits at. */
export interface CopyPlacement {
  readonly row: number;
  readonly x: number;
}

/** Where the button goes for the line starting at `start`, as that line is
 * laid out now:
 *
 *  - beside the line's last row, a cell clear of the text, when it fits there;
 *  - otherwise on the row reserved under the line (`spare`), lined up under
 *    the value;
 *  - otherwise nowhere. A button laid over text would hide part of the very
 *    thing it copies.
 *
 * Recomputed on every reflow, since a resize rewraps the line. */
export function placeCopyButton(
  buffer: BufferView,
  start: number,
  spare: number | null,
  cols: number,
  value: string,
): CopyPlacement | null {
  if (cols < COPY_CELLS) {
    return null;
  }
  const last = lastRowOf(buffer, start);
  const end = buffer.getLine(last)?.translateToString(true).length ?? 0;
  if (end + COPY_GAP + COPY_CELLS <= cols) {
    return { row: last, x: end + COPY_GAP };
  }
  if (spare === null || spare < 0) {
    return null;
  }
  const at = locateValue(buffer, start, cols, value);
  return { row: spare, x: Math.min(at?.col ?? 0, cols - COPY_CELLS) };
}

/** Where `value` starts on screen, so it can be selected for copying by hand.
 * Null when the line no longer carries it. */
export function locateValue(
  buffer: BufferView,
  start: number,
  cols: number,
  value: string,
): { readonly row: number; readonly col: number } | null {
  const offset = value.length === 0 ? -1 : logicalText(buffer, start, cols).lastIndexOf(value);
  if (offset < 0) {
    return null;
  }
  return { row: start + Math.floor(offset / cols), col: offset % cols };
}

/** The part of the browser's navigator a copy needs. `clipboard` is missing
 * outright from a page served over plain http, which is not a secure context. */
export interface ClipboardHost {
  readonly clipboard?: { writeText(text: string): Promise<void> };
}

/** Put `value` on the clipboard. False when the browser would not: no
 * clipboard on this connection, or a write it refused. Never throws, so a click
 * has exactly one outcome to report. */
export async function writeClipboard(
  value: string,
  host: ClipboardHost | undefined,
): Promise<boolean> {
  const clipboard = host?.clipboard;
  if (clipboard === undefined) {
    return false;
  }
  try {
    await clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
