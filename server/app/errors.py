"""Uniform error responses (CLAUDE.md section 0): same shape everywhere,
no stack traces, no distinction between failure causes beyond a coarse code.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# Codes we deliberately expose. Anything else collapses to request_failed.
_KNOWN_CODES = frozenset({"invalid_request", "rate_limited", "internal_error"})


def _response(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": code})


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _response(400, "invalid_request")

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        code = detail if isinstance(detail, str) and detail in _KNOWN_CODES else "request_failed"
        return _response(exc.status_code, code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        return _response(500, "internal_error")
