from __future__ import annotations

import os
import time
from collections.abc import Callable

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from .constants import (
    BUNDLE_FETCH_RATE_CAPACITY,
    BUNDLE_FETCH_RATE_WINDOW_SECONDS,
    LOGIN_CHALLENGE_RATE_CAPACITY,
    LOGIN_CHALLENGE_RATE_WINDOW_SECONDS,
    MESSAGE_SEND_RATE_CAPACITY,
    MESSAGE_SEND_RATE_WINDOW_SECONDS,
    REGISTER_RATE_CAPACITY,
    REGISTER_RATE_WINDOW_SECONDS,
)
from .db import Base, make_engine
from .errors import install_error_handlers
from .headers import install_security_headers
from .rate_limit import TokenBucketLimiter
from .routes.bundles import router as bundles_router
from .routes.keys import router as keys_router
from .routes.login import router as login_router
from .routes.messages import router as messages_router
from .routes.register import router as register_router
from .ws import WsHub
from .ws import router as ws_router


def create_app(
    database_url: str | None = None,
    clock: Callable[[], float] = time.time,
    ws_origins: list[str] | None = None,
) -> FastAPI:
    """App factory. Run with: uvicorn app.main:create_app --factory --reload

    API docs are off unless PQTERM_DEV=1 (CLAUDE.md section 7.5). `clock` is
    injectable so nonce/session expiry is testable without sleeping.
    `ws_origins` is the exact WS Origin allowlist (or PQTERM_WS_ORIGINS as a
    comma list); None leaves it open for local development - production must
    set it (W5 asserts this at boot).
    """
    url = database_url or os.environ.get("PQTERM_DATABASE_URL", "sqlite:///./pqterm_dev.db")
    dev = os.environ.get("PQTERM_DEV") == "1"
    if ws_origins is None:
        env_origins = os.environ.get("PQTERM_WS_ORIGINS", "")
        ws_origins = [o.strip() for o in env_origins.split(",") if o.strip()] or None

    app = FastAPI(
        title="pqterm",
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

    install_security_headers(app)
    install_error_handlers(app)
    app.include_router(register_router)
    app.include_router(login_router)
    app.include_router(keys_router)
    app.include_router(bundles_router)
    app.include_router(messages_router)
    app.include_router(ws_router)
    return app
