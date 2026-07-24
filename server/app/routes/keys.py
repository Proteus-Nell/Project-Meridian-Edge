"""Prekey upload and status.

The server stores public halves only and treats them as opaque sized blobs;
signature verification is the *fetching client's* job, so a
malicious server gains nothing by skipping it. Per-OPK leaf hashes are
retained so one OPK remains verifiable against the batch root signature
after its siblings are consumed.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..constants import OPK_UNCONSUMED_CAP
from ..deps import get_session
from ..models import OneTimePrekey, OpkBatch, SignedPrekey
from ..rate_limit import TokenBucketLimiter
from ..schemas import KeysStatusResponse, OpkUploadRequest, SpkUploadRequest
from ..security_log import record_security_event

router = APIRouter(prefix="/v1/keys")


def _client_ip(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


def _check_upload_budget(request: Request, uid: str) -> None:
    """Bound prekey uploads per account.

    Both upload endpoints append rows, and the signed-prekey table has no other
    cap, so without this an authenticated client could grow it without limit.
    Keyed on the UID (the account doing the writing); the log records only the
    endpoint and source IP, never the key the limiter buckets on.
    """
    limiter: TokenBucketLimiter = request.app.state.keys_upload_limiter
    if not limiter.allow(uid):
        record_security_event(
            "rate_limit_exceeded", endpoint=request.url.path, client_ip=_client_ip(request)
        )
        raise HTTPException(status_code=429, detail="rate_limited")


@router.post("/spk", status_code=204)
def upload_spk(
    payload: SpkUploadRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    _check_upload_budget(request, ctx.user.uid)
    session.add(
        SignedPrekey(
            user_id=ctx.user.id,
            pub=base64.b64decode(payload.spk_pub, validate=True),
            sig=base64.b64decode(payload.spk_sig, validate=True),
            uploaded_at=ctx.session_token.last_used,
        )
    )
    session.commit()


@router.post("/opks", status_code=204)
def upload_opks(
    payload: OpkUploadRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    _check_upload_budget(request, ctx.user.uid)
    unconsumed = session.execute(
        select(func.count())
        .select_from(OneTimePrekey)
        .where(OneTimePrekey.user_id == ctx.user.id, OneTimePrekey.consumed.is_(False))
    ).scalar_one()
    if unconsumed + len(payload.opks) > OPK_UNCONSUMED_CAP:
        raise HTTPException(status_code=400, detail="invalid_request")

    pubs = [base64.b64decode(item, validate=True) for item in payload.opks]
    leaf_hashes = b"".join(hashlib.sha512(pub).digest() for pub in pubs)
    batch = OpkBatch(
        user_id=ctx.user.id,
        root_sig=base64.b64decode(payload.root_sig, validate=True),
        leaf_hashes=leaf_hashes,
        created_at=ctx.session_token.last_used,
    )
    session.add(batch)
    session.flush()  # batch.id
    for index, pub in enumerate(pubs):
        session.add(
            OneTimePrekey(
                user_id=ctx.user.id,
                batch_id=batch.id,
                batch_index=index,
                pub=pub,
            )
        )
    session.commit()


@router.get("/status")
def status(
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> KeysStatusResponse:
    latest_spk = session.execute(
        select(SignedPrekey.uploaded_at)
        .where(SignedPrekey.user_id == ctx.user.id)
        .order_by(SignedPrekey.uploaded_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    opk_count = session.execute(
        select(func.count())
        .select_from(OneTimePrekey)
        .where(OneTimePrekey.user_id == ctx.user.id, OneTimePrekey.consumed.is_(False))
    ).scalar_one()
    return KeysStatusResponse(spk_uploaded_at=latest_spk, opk_count=opk_count)
