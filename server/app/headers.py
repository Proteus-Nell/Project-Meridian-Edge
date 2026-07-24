"""Security headers on every response.

The API serves JSON only; the strict page-level CSP for the client bundle is
enforced at the reverse proxy in production. These headers are the
API-side baseline and are deliberately deny-everything.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    ),
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    ),
    "Cache-Control": "no-store",
    # Browsers only honor this over HTTPS, so it is harmless to send in plain-
    # HTTP dev; in production it is the belt to the reverse proxy's suspenders
    # (checklist: max-age=63072000; includeSubDomains; preload).
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
}


def install_security_headers(app: FastAPI) -> None:
    @app.middleware("http")
    async def _security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response
