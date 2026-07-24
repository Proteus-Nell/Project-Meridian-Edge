"""FastAPI application factory and process-wide wiring.

Everything the server needs is assembled in create_app(): security headers,
uniform error handlers, one token-bucket limiter per rate-limited surface, the
WebSocket hub, and the six route modules. Nothing here is a module-level
singleton - each call builds an isolated app with its own engine, hub and
limiters, which is what lets the test suite run many independent servers in a
single process without them sharing rate-limit buckets or sessions.

Two seams exist purely for testability. `clock` makes nonce and session expiry
deterministic without sleeping. `ws_idle_timeout_seconds` is deliberately real
wall-clock time (asyncio.wait_for) rather than `clock`, because it guards a
transport concern rather than business logic, so tests override it directly to
exercise the idle-kill path in milliseconds.

Deployment safety is asserted at boot: _assert_production_safe refuses to start
a dev-shaped configuration (API docs enabled, no WebSocket origin allowlist, a
SQLite database, or drifted Argon2id parameters) whenever the environment
declares itself production.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from .constants import (
    ARGON2ID_ITERATIONS,
    ARGON2ID_MEM_KIB,
    ARGON2ID_PARALLELISM,
    BUNDLE_FETCH_RATE_CAPACITY,
    BUNDLE_FETCH_RATE_WINDOW_SECONDS,
    LOGIN_CHALLENGE_RATE_CAPACITY,
    LOGIN_CHALLENGE_RATE_WINDOW_SECONDS,
    MESSAGE_SEND_RATE_CAPACITY,
    MESSAGE_SEND_RATE_WINDOW_SECONDS,
    RECOVER_RATE_CAPACITY,
    RECOVER_RATE_WINDOW_SECONDS,
    REGISTER_RATE_CAPACITY,
    REGISTER_RATE_WINDOW_SECONDS,
    WS_IDLE_TIMEOUT_SECONDS,
)
from . import security
from .db import Base, make_engine
from .errors import install_error_handlers
from .headers import install_security_headers
from .rate_limit import TokenBucketLimiter
from .routes.bundles import router as bundles_router
from .routes.keys import router as keys_router
from .routes.login import router as login_router
from .routes.messages import router as messages_router
from .routes.recover import router as recover_router
from .routes.register import router as register_router
from .routes.sessions import router as sessions_router
from .ws import WsHub
from .ws import router as ws_router


def _assert_production_safe(
    *, dev: bool, allowed_origins: list[str] | None, database_url: str
) -> None:
    """Refuse to boot with a dev-shaped config in production (
    checklist: "DEBUG=0 asserted at startup"). Only runs when MERIDIAN_EDGE_ENV=
    production is explicitly set - local dev and the test suite never set it,
    so neither ever exercises this path by accident."""
    if os.environ.get("MERIDIAN_EDGE_ENV") != "production":
        return
    problems: list[str] = []
    if dev:
        problems.append("MERIDIAN_EDGE_DEV=1 is set (enables /docs) alongside MERIDIAN_EDGE_ENV=production")
    if not allowed_origins:
        problems.append(
            "no Origin allowlist is set (MERIDIAN_EDGE_ALLOWED_ORIGINS or the legacy "
            "MERIDIAN_EDGE_WS_ORIGINS) - WebSocket and login origin checking would be disabled"
        )
    if database_url.startswith("sqlite"):
        problems.append("MERIDIAN_EDGE_DATABASE_URL is a SQLite dev artifact - never deploy it")
    time_cost, memory_cost, parallelism = security.hasher_params()
    if (
        time_cost != ARGON2ID_ITERATIONS
        or memory_cost != ARGON2ID_MEM_KIB
        or parallelism != ARGON2ID_PARALLELISM
    ):
        problems.append("Argon2id hasher parameters do not match the constants")
    if problems:
        raise RuntimeError(
            "refusing to boot in production mode:\n- " + "\n- ".join(problems)
        )


def create_app(
    database_url: str | None = None,
    clock: Callable[[], float] = time.time,
    allowed_origins: list[str] | None = None,
    ws_idle_timeout_seconds: float = WS_IDLE_TIMEOUT_SECONDS,
) -> FastAPI:
    """App factory. Run with: uvicorn app.main:create_app --factory --reload

    API docs are off unless MERIDIAN_EDGE_DEV=1. `clock` is
    injectable so nonce/session expiry is testable without sleeping.
    `allowed_origins` is the exact Origin allowlist governing BOTH the WebSocket
    upgrade and the login challenge/verify pair (or MERIDIAN_EDGE_ALLOWED_ORIGINS
    as a comma list, falling back to the legacy MERIDIAN_EDGE_WS_ORIGINS). None
    leaves both open for local development - production must set it (asserted at
    boot, see _assert_production_safe). Note an Origin header only constrains
    browsers; it is defence in depth against a hostile page, not against a
    direct HTTP client that can send any header it likes.

    `ws_idle_timeout_seconds` is real wall-clock time (asyncio.wait_for, not
    `clock`) - tests override it directly to exercise the idle-kill path without
    sleeping.
    """
    url = database_url or os.environ.get("MERIDIAN_EDGE_DATABASE_URL", "sqlite:///./meridian_edge_dev.db")
    dev = os.environ.get("MERIDIAN_EDGE_DEV") == "1"
    if allowed_origins is None:
        # MERIDIAN_EDGE_WS_ORIGINS predates the allowlist covering login as well;
        # it stays supported so existing deployments keep working unchanged.
        env_origins = os.environ.get("MERIDIAN_EDGE_ALLOWED_ORIGINS") or os.environ.get(
            "MERIDIAN_EDGE_WS_ORIGINS", ""
        )
        allowed_origins = [o.strip() for o in env_origins.split(",") if o.strip()] or None
    _assert_production_safe(dev=dev, allowed_origins=allowed_origins, database_url=url)

    app = FastAPI(
        title="Meridian Edge",
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )

    engine = make_engine(url)
    # create_all stands in for migrations; revisit when the schema grows.
    Base.metadata.create_all(engine)
    app.state.sessionmaker = sessionmaker(engine)
    app.state.clock = clock
    app.state.ws_hub = WsHub()
    app.state.allowed_origins = allowed_origins
    app.state.ws_idle_timeout_seconds = ws_idle_timeout_seconds
    app.state.register_limiter = TokenBucketLimiter(
        REGISTER_RATE_CAPACITY, REGISTER_RATE_WINDOW_SECONDS
    )
    app.state.login_challenge_limiter = TokenBucketLimiter(
        LOGIN_CHALLENGE_RATE_CAPACITY, LOGIN_CHALLENGE_RATE_WINDOW_SECONDS
    )
    app.state.bundle_fetch_limiter = TokenBucketLimiter(
        BUNDLE_FETCH_RATE_CAPACITY, BUNDLE_FETCH_RATE_WINDOW_SECONDS
    )
    app.state.message_send_limiter = TokenBucketLimiter(
        MESSAGE_SEND_RATE_CAPACITY, MESSAGE_SEND_RATE_WINDOW_SECONDS
    )
    app.state.recover_limiter = TokenBucketLimiter(
        RECOVER_RATE_CAPACITY, RECOVER_RATE_WINDOW_SECONDS
    )

    install_security_headers(app)
    install_error_handlers(app)
    app.include_router(register_router)
    app.include_router(recover_router)
    app.include_router(login_router)
    app.include_router(sessions_router)
    app.include_router(keys_router)
    app.include_router(bundles_router)
    app.include_router(messages_router)
    app.include_router(ws_router)
    return app
