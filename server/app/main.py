from __future__ import annotations

import os

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from .constants import REGISTER_RATE_CAPACITY, REGISTER_RATE_WINDOW_SECONDS
from .db import Base, make_engine
from .errors import install_error_handlers
from .headers import install_security_headers
from .rate_limit import TokenBucketLimiter
from .routes.register import router as register_router


def create_app(database_url: str | None = None) -> FastAPI:
    """App factory. Run with: uvicorn app.main:create_app --factory --reload

    API docs are off unless PQTERM_DEV=1 (CLAUDE.md section 7.5).
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
    app.state.register_limiter = TokenBucketLimiter(
        REGISTER_RATE_CAPACITY, REGISTER_RATE_WINDOW_SECONDS
    )

    install_security_headers(app)
    install_error_handlers(app)
    app.include_router(register_router)
    return app
