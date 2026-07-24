from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import uid as uid_module
from ..deps import get_session
from ..models import RecoveryCode, User
from ..rate_limit import TokenBucketLimiter
from ..schemas import RegisterRequest, RegisterResponse
from ..security import generate_recovery_codes, hash_recovery_code
from ..security_log import record_security_event

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
        record_security_event(
            "rate_limit_exceeded", endpoint=request.url.path, client_ip=_client_key(request)
        )
        raise HTTPException(status_code=429, detail="rate_limited")

    ik_pub = payload.decoded_ik_pub()
    for _ in range(_MAX_UID_RETRIES):
        candidate = uid_module.generate_uid()
        user = User(uid=candidate, ik_pub=ik_pub)
        session.add(user)
        try:
            session.flush()
        except IntegrityError:
            # UNIQUE constraint hit: silently regenerate (CLAUDE.md section 2.1).
            session.rollback()
            continue
        # Recovery codes: shown once in this response, stored only as
        # Argon2id hashes (CLAUDE.md section 2.2 / 7.7).
        codes = generate_recovery_codes()
        for code in codes:
            session.add(RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(code)))
        session.commit()
        return RegisterResponse(uid=uid_module.format_uid(candidate), recovery_codes=codes)
    raise HTTPException(status_code=500, detail="internal_error")
