// The style mirror is what keeps the deployed terminal legible: xterm generates
// its cell metrics, ANSI palette and cursor as <style> elements, and the
// production CSP's `style-src 'self'` blocks all of them. These tests guard the
// three properties that make the mirror safe to leave in place - it copies what
// was blocked, it leaves alone what was not, and it updates a mirror in place
// rather than adopting a fresh sheet on every theme change.
//
// The client's suites run on node with no DOM, so the sync step is exercised
// through the StyleSheetHost seam with stand-ins for the two browser types.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { syncBlockedStyles } from "../src/terminal/stylemirror";
import type { StyleSheetHost } from "../src/terminal/stylemirror";

const read = (rel: string): string =>
  readFileSync(new URL(`../node_modules/@xterm/xterm/${rel}`, import.meta.url), "utf8");

/** Stand-in for a constructed CSSStyleSheet: records what was written to it. */
class FakeSheet {
  text = "";
  replaceCount = 0;
  replaceSync(text: string): void {
    this.text = text;
    this.replaceCount += 1;
  }
}

/** Stand-in for a <style> element. `sheet: null` is exactly what the browser
 * reports for one the CSP refused to apply. */
function styleEl(textContent: string, blocked = true): HTMLStyleElement {
  return { textContent, sheet: blocked ? null : {} } as unknown as HTMLStyleElement;
}

function host(): StyleSheetHost {
  return { adoptedStyleSheets: [] };
}

function newMirrors(): Map<HTMLStyleElement, CSSStyleSheet> {
  return new Map<HTMLStyleElement, CSSStyleSheet>();
}

const create = (): CSSStyleSheet => new FakeSheet() as unknown as CSSStyleSheet;

describe("style mirror", () => {
  it("adopts a sheet carrying the rules the CSP blocked", () => {
    const target = host();
    const source = styleEl(".xterm-rows { white-space: pre }");

    syncBlockedStyles([source], newMirrors(), target, create);

    expect(target.adoptedStyleSheets).toHaveLength(1);
    const [mirror] = target.adoptedStyleSheets as unknown as FakeSheet[];
    expect(mirror?.text).toBe(".xterm-rows { white-space: pre }");
  });

  it("ignores a style element that was applied normally", () => {
    // Dev, or any origin without the strict CSP: xterm's own sheet is live, so
    // mirroring it would apply every rule twice.
    const target = host();

    syncBlockedStyles([styleEl(".xterm-rows { white-space: pre }", false)], newMirrors(), target, create);

    expect(target.adoptedStyleSheets).toHaveLength(0);
  });

  it("updates a mirror in place when xterm rewrites its sheet", () => {
    // xterm regenerates this text on every /settings scheme, font and fontsize
    // change. Adopting a new sheet each time would grow adoptedStyleSheets for
    // the life of the session and leave stale rules winning by order.
    const target = host();
    const mirrors = newMirrors();
    const source = styleEl(".xterm-rows { font-size: 15px }");

    syncBlockedStyles([source], mirrors, target, create);
    source.textContent = ".xterm-rows { font-size: 22px }";
    syncBlockedStyles([source], mirrors, target, create);

    expect(target.adoptedStyleSheets).toHaveLength(1);
    const [mirror] = target.adoptedStyleSheets as unknown as FakeSheet[];
    expect(mirror?.text).toBe(".xterm-rows { font-size: 22px }");
    expect(mirror?.replaceCount).toBe(2);
  });

  it("keeps mirroring the rest when one sheet cannot be parsed", () => {
    const target = host();
    const failing = styleEl("@import url(nope.css);");
    const failingCreate = (): CSSStyleSheet => {
      const sheet = new FakeSheet();
      const original = sheet.replaceSync.bind(sheet);
      sheet.replaceSync = (text: string): void => {
        if (text.startsWith("@import")) {
          throw new Error("replaceSync rejects @import");
        }
        original(text);
      };
      return sheet as unknown as CSSStyleSheet;
    };

    syncBlockedStyles([failing, styleEl(".xterm-dim { color: red }")], newMirrors(), target, failingCreate);

    expect(target.adoptedStyleSheets).toHaveLength(1);
    const [mirror] = target.adoptedStyleSheets as unknown as FakeSheet[];
    expect(mirror?.text).toBe(".xterm-dim { color: red }");
  });

  it("mirrors each blocked sheet exactly once across both terminals", () => {
    // Six in production: dimensions, theme and scrollbar, per terminal.
    const target = host();
    const mirrors = newMirrors();
    const sources = Array.from({ length: 6 }, (_, i) => styleEl(`.s${i} { color: red }`));

    syncBlockedStyles(sources, mirrors, target, create);
    syncBlockedStyles(sources, mirrors, target, create);

    expect(target.adoptedStyleSheets).toHaveLength(6);
  });
});

// The mirror only earns its place while xterm keeps building the terminal's
// styling at runtime. If an upgrade moved those rules into the shipped
// stylesheet, or stopped emitting them as <style> elements, the mirror would
// quietly become a no-op and the CSP breakage would return with this suite
// still green - the exact failure the mirror exists to prevent.
//
// These assert that contract against the installed package. They are not a
// substitute for exercising the mirror in a browser: the client's suites run on
// node with no DOM, and the repo carries no browser driver, so the wiring in
// main.ts is verified by hand against `npm run build && npm run preview` (which
// serves the production CSP - see vite.config.ts).
describe("xterm's runtime styling contract", () => {
  const lib = read("lib/xterm.js");
  const css = read("css/xterm.css");

  it("still builds its styling as <style> elements the CSP will block", () => {
    expect(lib).toContain('createElement("style")');
  });

  it("still generates the cell metrics rather than shipping them", () => {
    // `white-space: pre` on the visible rows is what keeps the banner's column
    // alignment; xterm.css only sets it on the screen-reader tree.
    expect(lib).toContain("white-space: pre");
    expect(css).not.toContain(".xterm-rows {");
  });

  it("still generates every caret visual, so a blocked sheet means no cursor", () => {
    // The keyframe names interpolate the terminal id, so only the prefix is
    // a literal in the bundle.
    expect(lib).toContain("@keyframes ");
    expect(lib).toContain("blink_block_");
    // The only cursor rule the shipped stylesheet carries is the mouse pointer.
    const cursorRules = [...css.matchAll(/\.xterm-cursor[\w-]*/g)].map((m) => m[0]);
    expect(new Set(cursorRules)).toEqual(new Set([".xterm-cursor-pointer"]));
  });
});
