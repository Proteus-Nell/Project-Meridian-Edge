"""Account recovery by one-time code.

A recovery code is the sole credential: whoever presents a valid unused code
for a UID takes the identity over. Redemption is therefore a full identity
replacement, applied in one transaction:

- the submitted ML-DSA-65 key replaces the stored identity key
- every artifact bound to the old key is destroyed: signed prekeys, one-time
  prekey batches, and the queued ciphertext (undecryptable by the new key)
- all session tokens are deleted, forcing the old device out
- the entire recovery-code set is reissued and returned once, exactly like
  at registration; nothing from the old set remains valid

Anti-enumeration mirrors login: unknown UID, wrong code, and spent code all
return the identical uniform 401, and every attempt performs exactly
RECOVERY_CODE_COUNT Argon2id verifications (real rows first, dummy padding
after), so response time reveals neither whether the UID exists nor how many
codes remain.

Known limitation, deliberately not engineered around: a WebSocket attached
before the recovery keeps its connection until it disconnects or idles out.
Its REST token is already dead, and any envelope pushed to it encapsulates
to the new identity's prekeys, so it cannot read new traffic.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import uid as uid_module
from ..constants import RECOVERY_CODE_COUNT
from ..deps import get_session
from ..models import (
    OneTimePrekey,
    OpkBatch,
    QueuedMessage,
    RecoveryCode,
    SessionToken,
    SignedPrekey,
    User,
)
from ..rate_limit import TokenBucketLimiter
from ..schemas import RecoverRequest, RecoverResponse
from ..security import (
    generate_recovery_codes,
    hash_recovery_code,
    verify_recovery_code,
)
from ..security_log import record_security_event

router = APIRouter(prefix="/v1")

# Dummy hash for burn-time padding. Computed lazily from the live hasher so
# it always carries the hasher's current parameters (a module-load-time hash
# would bake in production cost and defeat the test suite's fast hasher).
_dummy_hash: str | None = None


def _get_dummy_hash() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_recovery_code("0" * 16)
    return _dummy_hash


def _client_key(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


@router.post("/recover")
def recover(
    payload: RecoverRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> RecoverResponse:
    limiter: TokenBucketLimiter = request.app.state.recover_limiter
    if not limiter.allow(_client_key(request)):
        record_security_event(
            "rate_limit_exceeded", endpoint=request.url.path, client_ip=_client_key(request)
        )
        raise HTTPException(status_code=429, detail="rate_limited")

    user = session.execute(
        select(User).where(User.uid == payload.uid)
    ).scalar_one_or_none()
    rows = (
        []
        if user is None
        else list(
            session.execute(
                select(RecoveryCode).where(
                    RecoveryCode.user_id == user.id,
                    RecoveryCode.used.is_(False),
                )
            ).scalars()
        )
    )

    # Constant-work verification: check every real row even after a match, then
    # pad the count up to RECOVERY_CODE_COUNT with dummy rows.
    matched: RecoveryCode | None = None
    for row in rows:
        if verify_recovery_code(row.code_hash, payload.code) and matched is None:
            matched = row
    for _ in range(max(0, RECOVERY_CODE_COUNT - len(rows))):
        verify_recovery_code(_get_dummy_hash(), payload.code)

    if user is None or matched is None:
        # Brute-forcing recovery codes is an attack on the account-takeover path;
        # logged coarsely (unknown UID and wrong code are indistinguishable).
        record_security_event(
            "auth_failure",
            endpoint=request.url.path,
            client_ip=_client_key(request),
            reason="invalid_recovery_code",
        )
        raise HTTPException(status_code=401, detail="auth_failed")

    # Identity replacement, all-or-nothing.
    user.ik_pub = payload.decoded_ik_pub()
    session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = generate_recovery_codes()
    for code in codes:
        session.add(RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(code)))
    session.execute(delete(OneTimePrekey).where(OneTimePrekey.user_id == user.id))
    session.execute(delete(OpkBatch).where(OpkBatch.user_id == user.id))
    session.execute(delete(SignedPrekey).where(SignedPrekey.user_id == user.id))
    session.execute(delete(SessionToken).where(SessionToken.user_id == user.id))
    session.execute(
        delete(QueuedMessage).where(QueuedMessage.recipient_user_id == user.id)
    )
    session.commit()
    return RecoverResponse(uid=uid_module.format_uid(user.uid), recovery_codes=codes)
