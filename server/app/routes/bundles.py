"""Prekey bundle fetch (CLAUDE.md sections 2.1, 3.1, 7.4).

Authenticated and rate-limited per requesting UID. One fetch consumes at
most one OPK, atomically (conditional UPDATE - two racing fetches can never
receive the same OPK). Unknown UID and known-UID-without-prekeys return the
identical uniform 404, so this endpoint is not an existence oracle.

`?opk=0` skips OPK consumption - used for identity-binding checks on
received messages, so verification traffic does not drain the sender's
one-time prekeys (ADR 0002).
"""

from __future__ import annotations

import base64
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..deps import get_session
from ..models import OneTimePrekey, OpkBatch, SignedPrekey, User
from ..rate_limit import TokenBucketLimiter
from ..schemas import BundleOpk, BundleResponse
from ..security_log import record_security_event
from ..uid import canonicalize_uid

router = APIRouter(prefix="/v1")

_LEAF_BYTES = 64
_CLAIM_RETRIES = 4


def _client_ip(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="request_failed")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@router.get("/bundles/{uid}")
def fetch_bundle(
    uid: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
    opk: bool = True,
) -> BundleResponse:
    limiter: TokenBucketLimiter = request.app.state.bundle_fetch_limiter
    if not limiter.allow(ctx.user.uid):
        # The limiter keys on the UID; the log deliberately does not - endpoint
        # and source IP only, no account identifier.
        record_security_event(
            "rate_limit_exceeded", endpoint=request.url.path, client_ip=_client_ip(request)
        )
        raise HTTPException(status_code=429, detail="rate_limited")

    canonical = canonicalize_uid(uid)
    if canonical is None:
        raise HTTPException(status_code=400, detail="invalid_request")

    target = session.execute(select(User).where(User.uid == canonical)).scalar_one_or_none()
    latest_spk = (
        None
        if target is None
        else session.execute(
            select(SignedPrekey)
            .where(SignedPrekey.user_id == target.id)
            .order_by(SignedPrekey.uploaded_at.desc())
            .limit(1)
        ).scalar_one_or_none()
    )
    if target is None or latest_spk is None:
        # Same shape for "no such user" and "user without prekeys".
        # Full timing uniformity is part of the W5 hardening pass.
        raise _not_found()

    bundle_opk: BundleOpk | None = None
    if opk:
        claimed = _claim_opk(session, target.id)
        if claimed is not None:
            batch = session.get(OpkBatch, claimed.batch_id)
            if batch is not None:
                leaves = [
                    _b64(batch.leaf_hashes[i : i + _LEAF_BYTES])
                    for i in range(0, len(batch.leaf_hashes), _LEAF_BYTES)
                ]
                bundle_opk = BundleOpk(
                    pub=_b64(claimed.pub),
                    index=claimed.batch_index,
                    leaf_hashes=leaves,
                    root_sig=_b64(batch.root_sig),
                )
    return BundleResponse(
        ik_pub=_b64(target.ik_pub),
        spk_pub=_b64(latest_spk.pub),
        spk_sig=_b64(latest_spk.sig),
        opk=bundle_opk,
    )


def _claim_opk(session: Session, user_id: int) -> OneTimePrekey | None:
    """Atomically mark one unconsumed OPK consumed (one fetch = one OPK).

    The conditional UPDATE only wins if `consumed` is still false, so a
    concurrent claim of the same row loses and retries on the next one.
    Depletion degrades to an SPK-only bundle instead of failing (§7.4).
    """
    for _ in range(_CLAIM_RETRIES):
        candidate = session.execute(
            select(OneTimePrekey)
            .where(OneTimePrekey.user_id == user_id, OneTimePrekey.consumed.is_(False))
            .order_by(OneTimePrekey.id)
            .limit(1)
        ).scalar_one_or_none()
        if candidate is None:
            return None
        won = cast(
            "CursorResult[Any]",
            session.execute(
                update(OneTimePrekey)
                .where(OneTimePrekey.id == candidate.id, OneTimePrekey.consumed.is_(False))
                .values(consumed=True)
            ),
        )
        if won.rowcount == 1:
            session.commit()
            return candidate
        session.rollback()
    return None
