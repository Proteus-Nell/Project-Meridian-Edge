#!/usr/bin/env python3
"""CI security audit gates (CLAUDE.md sections 0, 5, 7.9).

Exits non-zero if a forbidden pattern appears in an application code path.

Scope:
  - client/src/**/*.ts, client/index.html  (TypeScript application code)
  - server/app/**/*.py                     (Python application code)

bench/ is deliberately out of scope: classical baselines (X25519, Ed25519)
live there by design for the B1/B2 comparisons.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Classical asymmetric crypto is banned from application code paths (section 0).
CLASSICAL_CRYPTO: list[str] = [
    r"\bRSA\b",
    r"\bECDH\b",
    r"\bECDSA\b",
    r"\b[Xx]25519\b",
    r"\b[Ee]d25519\b",
    r"\bsecp256",
    r"\bP-?256\b",
    r"\bP-?384\b",
    r"@noble/curves",
    r"\btweetnacl\b",
]

# Client: no HTML injection paths, no dynamic code, no weak randomness,
# no persistent token storage (sections 0, 1, 2.3).
CLIENT_FORBIDDEN: list[str] = [
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"dangerouslySetInnerHTML",
    r"\beval\s*\(",
    r"new\s+Function\s*\(",
    r"\bMath\.random\b",
    r"\bdocument\.write\b",
    r"\blocalStorage\b",
]

# Server: no dynamic code, no pickle, no weak randomness, no f-string SQL
# (sections 0, 7.3).
SERVER_FORBIDDEN: list[str] = [
    r"\beval\s*\(",
    r"(?<!_)\bexec\s*\(",
    r"\bpickle\b",
    r"^\s*import random\b",
    r"^\s*from random import\b",
    r"\.execute(?:many)?\(\s*f[\"']",
    r"f[\"'][^\"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b",
]


def scan(files: list[Path], patterns: list[str]) -> list[str]:
    compiled = [re.compile(p, re.MULTILINE) for p in patterns]
    findings: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in compiled:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                rel = path.relative_to(ROOT)
                findings.append(f"{rel}:{line}: forbidden pattern {pattern.pattern!r}")
    return findings


def main() -> int:
    client_files = sorted((ROOT / "client" / "src").rglob("*.ts"))
    client_html = ROOT / "client" / "index.html"
    if client_html.exists():
        client_files.append(client_html)
    server_files = sorted((ROOT / "server" / "app").rglob("*.py"))

    findings: list[str] = []
    findings += scan(client_files + server_files, CLASSICAL_CRYPTO)
    findings += scan(client_files, CLIENT_FORBIDDEN)
    findings += scan(server_files, SERVER_FORBIDDEN)

    if findings:
        print(f"AUDIT FAILED: {len(findings)} finding(s)")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(
        f"audit clean: {len(client_files)} client file(s), "
        f"{len(server_files)} server file(s) scanned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
