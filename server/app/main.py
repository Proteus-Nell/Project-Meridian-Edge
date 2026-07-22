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
from .ws import WsHub
from .ws import router as ws_router


def _assert_production_safe(
    *, dev: bool, ws_origins: list[str] | None, database_url: str
) -> None:
    """Refuse to boot with a dev-shaped config in production (CLAUDE.md §5
    checklist: "DEBUG=0 asserted at startup"). Only runs when MERIDIAN_EDGE_ENV=
    production is explicitly set - local dev and the test suite never set it,
    so neither ever exercises this path by accident."""
    if os.environ.get("MERIDIAN_EDGE_ENV") != "production":
        return
    problems: list[str] = []
    if dev:
        problems.append("MERIDIAN_EDGE_DEV=1 is set (enables /docs) alongside MERIDIAN_EDGE_ENV=production")
    if not ws_origins:
        problems.append("MERIDIAN_EDGE_WS_ORIGINS is unset - WS origin checking would be disabled")
    if database_url.startswith("sqlite"):
        problems.append("MERIDIAN_EDGE_DATABASE_URL is a SQLite dev artifact - never deploy it (§7.5)")
    time_cost, memory_cost, parallelism = security.hasher_params()
    if (
        time_cost != ARGON2ID_ITERATIONS
        or memory_cost != ARGON2ID_MEM_KIB
        or parallelism != ARGON2ID_PARALLELISM
    ):
        problems.append("Argon2id hasher parameters do not match the §0 constants")
    if problems:
        raise RuntimeError(
            "refusing to boot in production mode:\n- " + "\n- ".join(problems)
        )


def create_app(
    database_url: str | None = None,
    clock: Callable[[], float] = time.time,
    ws_origins: list[str] | None = None,
    ws_idle_timeout_seconds: float = WS_IDLE_TIMEOUT_SECONDS,
) -> FastAPI:
    """App factory. Run with: uvicorn app.main:create_app --factory --reload

    API docs are off unless MERIDIAN_EDGE_DEV=1 (CLAUDE.md section 7.5). `clock` is
    injectable so nonce/session expiry is testable without sleeping.
    `ws_origins` is the exact WS Origin allowlist (or MERIDIAN_EDGE_WS_ORIGINS as a
    comma list); None leaves it open for local development - production must
    set it (asserted at boot, see _assert_production_safe). `ws_idle_timeout_
    seconds` is real wall-clock time (asyncio.wait_for, not `clock`) - tests
    override it directly to exercise the idle-kill path without sleeping.
    """
    url = database_url or os.environ.get("MERIDIAN_EDGE_DATABASE_URL", "sqlite:///./meridian_edge_dev.db")
    dev = os.environ.get("MERIDIAN_EDGE_DEV") == "1"
    if ws_origins is None:
        env_origins = os.environ.get("MERIDIAN_EDGE_WS_ORIGINS", "")
        ws_origins = [o.strip() for o in env_origins.split(",") if o.strip()] or None
    _assert_production_safe(dev=dev, ws_origins=ws_origins, database_url=url)

    app = FastAPI(
        title="Meridian Edge",
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )

    engine = make_engine(url)
    # W1: create_all stands in for migrations; revisit when the schema grows.
    Base.metadata.create_all(engine)
    app.state.sessionmaker = sessionmaker(engine)
    app.state.clock = clock
    app.state.ws_hub = WsHub()
    app.state.ws_origins = ws_origins
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
    app.include_router(keys_router)
    app.include_router(bundles_router)
    app.include_router(messages_router)
    app.include_router(ws_router)
    return app
