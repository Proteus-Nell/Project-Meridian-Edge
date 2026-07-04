"""Message queue (CLAUDE.md sections 3, 5): enqueue, fetch, delete-on-ack.

Envelopes are opaque ciphertext blobs; the server never parses them. Acks
delete in the same transaction and only for the authenticated recipient's
own ids (§7.1, §7.4 ack forgery). Expired rows (14-day TTL) are swept on
every touch of a recipient's queue; the scheduled job lands with W5.
"""

from __future__ import annotations

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..constants import MAX_PAYLOAD_BYTES, MESSAGE_TTL_SECONDS
from ..deps import get_session
from ..models import QueuedMessage, User
from ..rate_limit import TokenBucketLimiter
from ..schemas import AckRequest, MessagesResponse, QueuedMessageOut, SendMessageRequest
from ..ws import WsHub

router = APIRouter(prefix="/v1")


def _sweep_expired(session: Session, recipient_id: int, now: float) -> None:
    session.execute(
        delete(QueuedMessage).where(
            QueuedMessage.recipient_user_id == recipient_id,
            QueuedMessage.created_at < now - MESSAGE_TTL_SECONDS,
        )
    )


@router.post("/messages", status_code=204)
async def send_message(
    payload: SendMessageRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    limiter: TokenBucketLimiter = request.app.state.message_send_limiter
    if not limiter.allow(ctx.user.uid):
        raise HTTPException(status_code=429, detail="rate_limited")

    envelope = payload.decoded_envelope()
    if len(envelope) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="invalid_request")

    recipient = session.execute(
        select(User).where(User.uid == payload.recipient_uid)
    ).scalar_one_or_none()
    if recipient is None:
        # Accept-and-drop: a distinguishable error here would be a UID
        # existence oracle (§2.1). Honest senders always fetched the
        # recipient's bundle first, so they already know.
        return

    now: float = request.app.state.clock()
    _sweep_expired(session, recipient.id, now)
    row = QueuedMessage(recipient_user_id=recipient.id, envelope=envelope, created_at=now)
    session.add(row)
    session.commit()

    hub: WsHub = request.app.state.ws_hub
    await hub.push(
        recipient.id,
        {"type": "message", "id": row.id, "envelope": base64.b64encode(envelope).decode()},
    )


@router.get("/messages")
def fetch_messages(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> MessagesResponse:
    now: float = request.app.state.clock()
    _sweep_expired(session, ctx.user.id, now)
    session.commit()
    rows = (
        session.execute(
            select(QueuedMessage)
            .where(QueuedMessage.recipient_user_id == ctx.user.id)
            .order_by(QueuedMessage.id)
        )
        .scalars()
        .all()
    )
    return MessagesResponse(
        messages=[
            QueuedMessageOut(id=row.id, envelope=base64.b64encode(row.envelope).decode())
            for row in rows
        ]
    )


@router.post("/messages/ack", status_code=204)
def ack_messages(
    payload: AckRequest,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    # Delete-on-ack in one transaction, scoped to the caller's own queue:
    # acking someone else's ids silently deletes nothing.
    session.execute(
        delete(QueuedMessage).where(
            QueuedMessage.id.in_(payload.ids),
            QueuedMessage.recipient_user_id == ctx.user.id,
        )
    )
    session.commit()
