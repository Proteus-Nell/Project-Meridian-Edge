"""Prekey upload and status (CLAUDE.md section 2.6).

The server stores public halves only and treats them as opaque sized blobs;
signature verification is the *fetching client's* job (section 3.1), so a
malicious server gains nothing by skipping it. Per-OPK leaf hashes are
retained so one OPK remains verifiable against the batch root signature
after its siblings are consumed.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..constants import OPK_UNCONSUMED_CAP
from ..deps import get_session
from ..models import OneTimePrekey, OpkBatch, SignedPrekey
from ..schemas import KeysStatusResponse, OpkUploadRequest, SpkUploadRequest

router = APIRouter(prefix="/v1/keys")


@router.post("/spk", status_code=204)
def upload_spk(
    payload: SpkUploadRequest,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
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
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
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
