// Drift guard between the error catalog (src/terminal/messages.ts) and the
// human-readable table (MESSAGES.md): every code must be documented, every code
// the table mentions must exist, and zero-argument messages must appear in the
// table verbatim.
//
// MESSAGES.md is an internal working document that is not present in every
// checkout, so the comparison tests skip cleanly when it is missing rather than
// failing the suite. The catalog's own invariants need no document and are
// therefore always enforced.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { ERRORS, ERROR_CODES } from "../src/terminal/messages";

// Repo root first, then the historical docs/ location, so the guard keeps
// working on either side of the move.
const CANDIDATES = ["../../MESSAGES.md", "../../docs/MESSAGES.md"];

function readTable(): string | null {
  for (const relative of CANDIDATES) {
    try {
      return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf-8");
    } catch {
      // Not at this location; try the next one.
    }
  }
  return null;
}

const found = readTable();
// Non-null by the time the suite below runs: the describe is skipped when the
// table is absent, so the fallback is never actually compared against.
const doc = found ?? "";

describe.skipIf(found === null)("MESSAGES.md drift", () => {
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
      const build: (...args: never[]) => string = ERRORS[code];
      if (build.length === 0) {
        expect(doc, `stale text for ${code}`).toContain(build());
      }
    }
  });
});

// Intrinsic to the catalog, so these run whether or not the table is present.
describe("error catalog invariants", () => {
  it("keeps codes unique and inside their documented families", () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
    for (const code of ERROR_CODES) {
      expect(code).toMatch(/^E[1-5]\d{2}$/);
    }
  });
});
