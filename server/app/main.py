from __future__ import annotations

import os
import time
from collections.abc import Callable

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from .constants import (
    LOGIN_CHALLENGE_RATE_CAPACITY,
    LOGIN_CHALLENGE_RATE_WINDOW_SECONDS,
    REGISTER_RATE_CAPACITY,
    REGISTER_RATE_WINDOW_SECONDS,
)
from .db import Base, make_engine
from .errors import install_error_handlers
from .headers import install_security_headers
from .rate_limit import TokenBucketLimiter
from .routes.keys import router as keys_router
from .routes.login import router as login_router
from .routes.register import router as register_router


def create_app(
    database_url: str | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """App factory. Run with: uvicorn app.main:create_app --factory --reload

    API docs are off unless PQTERM_DEV=1 (CLAUDE.md section 7.5). `clock` is
    injectable so nonce/session expiry is testable without sleeping.
    """
    url = database_url or os.environ.get("PQTERM_DATABASE_URL", "sqlite:///./pqterm_dev.db")
    dev = os.environ.get("PQTERM_DEV") == "1"

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
    app.state.register_limiter = TokenBucketLimiter(
        REGISTER_RATE_CAPACITY, REGISTER_RATE_WINDOW_SECONDS
    )
    app.state.login_challenge_limiter = TokenBucketLimiter(
        LOGIN_CHALLENGE_RATE_CAPACITY, LOGIN_CHALLENGE_RATE_WINDOW_SECONDS
    )

    install_security_headers(app)
    install_error_handlers(app)
    app.include_router(register_router)
    app.include_router(login_router)
    app.include_router(keys_router)
    return app
