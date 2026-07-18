from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker


def get_session(request: Request) -> Iterator[Session]:
    maker: sessionmaker[Session] = request.app.state.sessionmaker
    with maker() as session:
        yield session
