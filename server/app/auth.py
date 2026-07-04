"""Session authentication dependency (CLAUDE.md section 2.3).

Bearer token -> SHA-512 lookup -> idle-expiry check -> sliding refresh.
Every failure is the same uniform 401; the caller learns nothing about
whether the token was unknown, revoked, or expired.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .constants import SESSION_IDLE_SECONDS
from .deps import get_session
from .models import SessionToken, User
from .security import hash_token


@dataclass
class AuthContext:
    user: User
    session_token: SessionToken


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="auth_failed")


def require_auth(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> AuthContext:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise _unauthorized()
    token_hash = hash_token(header[len("Bearer ") :])

    row = session.execute(
        select(SessionToken).where(SessionToken.token_hash == token_hash)
    ).scalar_one_or_none()
    if row is None or row.revoked:
        raise _unauthorized()

    now: float = request.app.state.clock()
    if now - row.last_used > SESSION_IDLE_SECONDS:
        row.revoked = True
        session.commit()
        raise _unauthorized()

    row.last_used = now
    user = session.get(User, row.user_id)
    if user is None:
        raise _unauthorized()
    session.commit()
    return AuthContext(user=user, session_token=row)
