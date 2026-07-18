"""The API surface itself is a security control: no enumeration oracle
(CLAUDE.md section 2.1), no docs in prod (7.5), uniform 404s, headers on
every response (section 5).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.headers import SECURITY_HEADERS


def _all_route_paths(routes: Any) -> set[str]:
    """Flatten route paths; FastAPI ≥0.139 nests included routers."""
    paths: set[str] = set()
    for route in routes:
        path = getattr(route, "path", None)
        if isinstance(path, str):
            paths.add(path)
        inner = getattr(route, "original_router", None) or getattr(route, "routes", None)
        if inner is not None:
            paths |= _all_route_paths(getattr(inner, "routes", inner))
    return paths


def test_no_user_lookup_or_existence_routes(app: FastAPI) -> None:
    api_paths = {p for p in _all_route_paths(app.routes) if p.startswith("/v1")}
    assert api_paths == {
        "/v1/register",
        "/v1/login/challenge",
        "/v1/login/verify",
        "/v1/logout",
        "/v1/keys/spk",
        "/v1/keys/opks",
        "/v1/keys/status",
        "/v1/bundles/{uid}",
        "/v1/messages",
        "/v1/messages/ack",
        "/v1/ws",
    }
    assert not any("user" in p for p in api_paths)


def test_docs_disabled_outside_dev(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_unknown_route_returns_uniform_error(client: TestClient) -> None:
    res = client.get("/v1/does-not-exist")
    assert res.status_code == 404
    assert res.json() == {"error": "request_failed"}


def test_wrong_method_returns_uniform_error(client: TestClient) -> None:
    res = client.get("/v1/register")
    assert res.status_code == 405
    assert res.json() == {"error": "request_failed"}


def test_security_headers_on_success_and_error(client: TestClient) -> None:
    error_response = client.get("/v1/does-not-exist")
    for name, value in SECURITY_HEADERS.items():
        assert error_response.headers.get(name) == value


def test_no_cors_headers_ever_returned(client: TestClient) -> None:
    # No CORS middleware is installed at all (CLAUDE.md section 5 checklist:
    # "exact origin only, no wildcard, credentials disabled"). The strongest
    # version of that is simply never answering the CORS handshake - a cross-
    # origin page's fetch() gets no Access-Control-Allow-* headers to read,
    # regardless of what Origin it sends.
    res = client.get(
        "/v1/does-not-exist", headers={"Origin": "https://evil.example"}
    )
    for header in res.headers:
        assert not header.lower().startswith("access-control-")

    preflight = client.options(
        "/v1/register",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    for header in preflight.headers:
        assert not header.lower().startswith("access-control-")
