"""A10 SSRF (CLAUDE.md §7.10): the server makes no outbound HTTP requests by
design. Assert it structurally - no HTTP client dependency reachable from
app code at all, so there is no code path left that could construct an
outbound URL from user input.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent / "app"

# Any of these imported anywhere under app/ would give a code path the
# capability to make an outbound network call.
FORBIDDEN_MODULES = {
    "requests",
    "httpx",
    "httpx2",
    "aiohttp",
    "urllib.request",
    "http.client",
}


def _imported_modules(source: str) -> set[str]:
    tree = ast.parse(source)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


def test_no_http_client_dependency_anywhere_in_app() -> None:
    offenders: list[str] = []
    for path in APP_ROOT.rglob("*.py"):
        modules = _imported_modules(path.read_text(encoding="utf-8"))
        hit = modules & FORBIDDEN_MODULES
        if hit:
            offenders.append(f"{path.relative_to(APP_ROOT.parent)}: {sorted(hit)}")
    assert offenders == [], "outbound HTTP client import(s) found:\n" + "\n".join(offenders)
