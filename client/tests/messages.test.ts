// Drift guard between the error catalog (src/terminal/messages.ts) and the
// human table (docs/MESSAGES.md): every code must be documented, every code
// the docs mention must exist, and zero-argument messages must appear in the
// docs verbatim. Fails the build when the two disagree.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ERRORS, ERROR_CODES } from "../src/terminal/messages";

const doc = readFileSync(
  fileURLToPath(new URL("../../docs/MESSAGES.md", import.meta.url)),
  "utf-8",
);

describe("docs/MESSAGES.md drift", () => {
  it("documents every catalogued error code as a table row", () => {
    for (const code of ERROR_CODES) {
      expect(doc, `missing table row for ${code}`).toMatch(new RegExp(`^\\| ${code} \\|`, "m"));
    }
  });

  it("mentions no error code that the catalog does not define", () => {
    const mentioned = new Set(doc.match(/\bE\d{3}\b/g) ?? []);
    // Family placeholders like E1xx are not literal codes and never match.
    for (const code of mentioned) {
      expect(ERROR_CODES as readonly string[], `undocumented catalog code ${code}`).toContain(code);
    }
  });

  it("quotes every fixed (zero-argument) message verbatim", () => {
    for (const code of ERROR_CODES) {
      const build = ERRORS[code] as (...args: never[]) => string;
      if (build.length === 0) {
        expect(doc, `stale text for ${code}`).toContain(build());
      }
    }
  });

  it("keeps codes unique and inside their documented families", () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
    for (const code of ERROR_CODES) {
      expect(code).toMatch(/^E[1-5]\d{2}$/);
    }
  });
});
