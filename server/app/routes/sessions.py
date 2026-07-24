"""Session visibility and bulk sign-out (account-security surface).

Two authenticated endpoints let a user manage where they are signed in:

- GET /v1/sessions lists their own live sessions.
- POST /v1/logout/all signs out every OTHER session and keeps the current one,
  the "I left myself logged in on another device" control. The current session
  is deliberately spared - signing out here is what /v1/logout already does.

Sessions are anonymous by design. The server stores no device name or user
agent (a passwordless, metadata-minimal messenger should not fingerprint the
devices you connect from), so a session is described only by how long ago it
started and was last active, plus a flag marking the one making the request.
Idle-expired sessions are filtered out of the listing so it shows only what is
genuinely still usable.
"""

from __future__ import annotations

from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Request
from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..constants import SESSION_IDLE_SECONDS
from ..deps import get_session
from ..models import SessionToken
from ..schemas import LogoutOthersResponse, SessionInfo, SessionsResponse

router = APIRouter(prefix="/v1")


@router.get("/sessions")
def list_sessions(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> SessionsResponse:
    now: float = request.app.state.clock()
    rows = session.execute(
        select(SessionToken)
        .where(
            SessionToken.user_id == ctx.user.id,
            SessionToken.revoked.is_(False),
        )
        .order_by(SessionToken.created_at.desc())
    ).scalars()
    sessions = [
        SessionInfo(
            age_seconds=max(0, int(now - row.created_at)),
            idle_seconds=max(0, int(now - row.last_used)),
            current=row.id == ctx.session_token.id,
        )
        for row in rows
        # An idle-expired row is dead but not yet marked revoked (that happens
        # lazily on its next use); do not present it as a live session.
        if now - row.last_used <= SESSION_IDLE_SECONDS
    ]
    return SessionsResponse(sessions=sessions)


@router.post("/logout/all")
def logout_all(
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> LogoutOthersResponse:
    result = cast(
        "CursorResult[Any]",
        session.execute(
            update(SessionToken)
            .where(
                SessionToken.user_id == ctx.user.id,
                SessionToken.id != ctx.session_token.id,
                SessionToken.revoked.is_(False),
            )
            .values(revoked=True)
        ),
    )
    session.commit()
    return LogoutOthersResponse(revoked=result.rowcount)
