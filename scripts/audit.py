#!/usr/bin/env python3
"""CI security audit gates.

Exits non-zero if a forbidden pattern appears in an application code path, or if
the page-level CSP has drifted between the places that declare it.

Scope:
  - client/src/**/*.ts, client/index.html  (TypeScript application code)
  - server/app/**/*.py                     (Python application code)
  - deploy/nginx.conf, deploy/Caddyfile,
    client/vite.config.ts                  (the page-level CSP, cross-checked)
  - deploy/nginx.conf, deploy/Caddyfile    (the request-body cap, checked against
                                            the largest valid request)

Out of scope by design: the top-level bench/ AND client/src/bench/. Both hold
the classical baselines (X25519, Ed25519) that exist only as the B1/B2
comparison yardstick - the browser benchmark harness lives under
client/src/bench/ so Vite/tsc/vitest see it, but it is not application code.
"""

from __future__ import annotations

import re
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Classical asymmetric crypto is banned from application code paths: this
# project's asymmetric primitives are ML-KEM-768 and ML-DSA-65 only.
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
# no persistent token storage (the session token must live in memory only).
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

# Server: no dynamic code, no pickle, no weak randomness, no f-string SQL.
SERVER_FORBIDDEN: list[str] = [
    r"\beval\s*\(",
    r"(?<!_)\bexec\s*\(",
    r"\bpickle\b",
    r"^\s*import random\b",
    r"^\s*from random import\b",
    r"\.execute(?:many)?\(\s*f[\"']",
    r"f[\"'][^\"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b",
]


# The page-level CSP is written in three places that must not drift: the two
# edge configs that serve it, and the Vite preview server that rehearses it
# locally. Nothing compared them until they had already diverged - `style-src
# 'self'` blocks the <style> elements xterm generates for its cell metrics, ANSI
# palette and cursor, and no local path applied the header, so a terminal that
# had lost its column alignment, its colours and its caret looked perfect in dev
# (see client/src/terminal/stylemirror.ts).
CSP_SOURCES: tuple[str, ...] = (
    "deploy/nginx.conf",
    "deploy/Caddyfile",
    "client/vite.config.ts",
)

# The one directive allowed to differ: each source names its own origin (nginx's
# $host, Caddy's domain variable, localhost under preview). It still has to be
# confined to 'self' plus that origin, which is asserted separately.
CSP_HOST_DIRECTIVE = "connect-src"


def extract_csp(path: Path) -> str | None:
    """Pull the page-level CSP out of an edge config, or out of the Vite config's
    PRODUCTION_CSP array. Returns None when the file carries no CSP at all."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".ts":
        block = re.search(r"const PRODUCTION_CSP\s*=\s*\[(.*?)\]\s*\.join", text, re.DOTALL)
        if block is None:
            return None
        # Each array element is one directive. Only the outer delimiter counts:
        # the values themselves contain single quotes ('self', 'none'), and one
        # element is a template literal (the local ws origin interpolates the
        # port), so match double-quoted and backticked literals and nothing else.
        return "; ".join(
            double or backtick
            for double, backtick in re.findall(r'"([^"]*)"|`([^`]*)`', block.group(1))
        )
    header = re.search(r'Content-Security-Policy\s+"([^"]+)"', text)
    return None if header is None else header.group(1)


def parse_directives(csp: str) -> dict[str, str]:
    """`default-src 'self'; style-src 'self'` -> {default-src: 'self', ...}."""
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        words = part.split()
        if words:
            directives[words[0]] = " ".join(words[1:])
    return directives


def check_csp() -> list[str]:
    """Every CSP source must agree, directive for directive, apart from the host
    one. A mismatch means the local rehearsal has stopped matching production."""
    sources = {rel: extract_csp(ROOT / rel) for rel in CSP_SOURCES}
    missing = [f"{rel}: no Content-Security-Policy found" for rel, csp in sources.items() if csp is None]
    if missing:
        return missing

    parsed = {rel: parse_directives(csp) for rel, csp in sources.items() if csp is not None}
    baseline_rel = CSP_SOURCES[0]
    baseline = parsed[baseline_rel]

    findings: list[str] = []
    for rel, directives in parsed.items():
        if rel != baseline_rel:
            for name in sorted(set(baseline) | set(directives)):
                if name == CSP_HOST_DIRECTIVE:
                    continue
                if baseline.get(name) != directives.get(name):
                    findings.append(
                        f"{rel}: CSP {name} is {directives.get(name)!r}, "
                        f"but {baseline_rel} has {baseline.get(name)!r}"
                    )
        host = directives.get(CSP_HOST_DIRECTIVE)
        if host is None or not host.startswith("'self'"):
            findings.append(
                f"{rel}: CSP {CSP_HOST_DIRECTIVE} must start with 'self', got {host!r}"
            )
    return findings


# The request-body cap is written in both edge configs, and it has to admit the
# largest body an honest client sends. It once read 64k, MAX_PAYLOAD_BYTES itself,
# which compared a cap on the HTTP body with a cap on the envelope inside it:
# envelopes travel base64-encoded in JSON, so nginx refused the largest messages,
# and every 50-key prekey batch at registration, before the app saw them.
BODY_CAP_SOURCES: dict[str, str] = {
    "deploy/nginx.conf": r"client_max_body_size\s+(\d+)([km]?);",
    "deploy/Caddyfile": r"max_size\s+(\d+)(KiB|MiB)\b",
}

_BODY_CAP_UNITS = {"": 1, "k": 1024, "m": 1024 * 1024, "KiB": 1024, "MiB": 1024 * 1024}


def largest_valid_body() -> int:
    """The biggest request body an honest client sends to /v1, as compact JSON
    on the wire: a maximum-size envelope addressed to a canonical UID, or a full
    batch of one-time prekeys with its root signature. Derived from the server's
    own constants, so raising either limit moves this with it."""
    consts = runpy.run_path(str(ROOT / "server" / "app" / "constants.py"))

    def b64(n: int) -> int:
        return 4 * ((n + 2) // 3)

    message = (
        len('{"recipient_uid":"') + consts["UID_CHARS"] + len('","envelope":"')
        + b64(consts["MAX_PAYLOAD_BYTES"]) + len('"}')
    )
    batch = consts["OPK_BATCH_MAX"]
    prekeys = (
        len('{"opks":[') + batch * (b64(consts["ML_KEM_768_PUBKEY_BYTES"]) + 2) + (batch - 1)
        + len('],"root_sig":"') + b64(consts["ML_DSA_65_SIG_BYTES"]) + len('"}')
    )
    return max(message, prekeys)


def check_body_caps() -> list[str]:
    """Both edges must declare one body cap, the same one, admitting the
    largest valid body."""
    caps: dict[str, int] = {}
    findings: list[str] = []
    for rel, pattern in BODY_CAP_SOURCES.items():
        found = re.search(pattern, (ROOT / rel).read_text(encoding="utf-8", errors="replace"))
        if found is None:
            findings.append(f"{rel}: no request-body cap found")
            continue
        caps[rel] = int(found.group(1)) * _BODY_CAP_UNITS[found.group(2)]
    if len(set(caps.values())) > 1:
        findings.append(f"request-body caps disagree: {caps}")
    largest = largest_valid_body()
    for rel, cap in caps.items():
        if cap < largest:
            findings.append(
                f"{rel}: request-body cap {cap} bytes refuses a valid {largest}-byte request"
            )
    return findings


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
    src_root = ROOT / "client" / "src"
    # client/src/bench/ holds the classical B1/B2 baselines by design (see the
    # module docstring); exclude it exactly like the top-level bench/ dir.
    client_files = [
        p for p in sorted(src_root.rglob("*.ts")) if p.relative_to(src_root).parts[0] != "bench"
    ]
    client_html = ROOT / "client" / "index.html"
    if client_html.exists():
        client_files.append(client_html)
    server_files = sorted((ROOT / "server" / "app").rglob("*.py"))

    findings: list[str] = []
    findings += scan(client_files + server_files, CLASSICAL_CRYPTO)
    findings += scan(client_files, CLIENT_FORBIDDEN)
    findings += scan(server_files, SERVER_FORBIDDEN)
    findings += check_csp()
    findings += check_body_caps()

    if findings:
        print(f"AUDIT FAILED: {len(findings)} finding(s)")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(
        f"audit clean: {len(client_files)} client file(s), "
        f"{len(server_files)} server file(s) scanned, "
        f"{len(CSP_SOURCES)} CSP source(s) agree, "
        f"edge body caps admit the largest valid request ({largest_valid_body()} bytes)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
