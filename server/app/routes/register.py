from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import uid as uid_module
from ..deps import get_session
from ..models import User
from ..rate_limit import TokenBucketLimiter
from ..schemas import RegisterRequest, RegisterResponse

router = APIRouter(prefix="/v1")

# A UID collision is a ~2^-128 event; hitting this bound means something is
# broken (bad entropy, DB corruption), so failing loudly is correct.
_MAX_UID_RETRIES = 8


def _client_key(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


@router.post("/register", status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> RegisterResponse:
    limiter: TokenBucketLimiter = request.app.state.register_limiter
    if not limiter.allow(_client_key(request)):
        raise HTTPException(status_code=429, detail="rate_limited")

    ik_pub = payload.decoded_ik_pub()
    for _ in range(_MAX_UID_RETRIES):
        candidate = uid_module.generate_uid()
        session.add(User(uid=candidate, ik_pub=ik_pub))
        try:
            session.commit()
        except IntegrityError:
            # UNIQUE constraint hit: silently regenerate (CLAUDE.md section 2.1).
            session.rollback()
            continue
        return RegisterResponse(uid=uid_module.format_uid(candidate))
    raise HTTPException(status_code=500, detail="internal_error")
