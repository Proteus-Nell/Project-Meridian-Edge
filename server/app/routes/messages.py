"""Message queue: enqueue, fetch, delete-on-ack.

Envelopes are opaque ciphertext blobs; the server never parses them. Acks
delete in the same transaction and only for the authenticated recipient's
own ids (ack forgery). Expired rows (14-day TTL) are swept on
every touch of a recipient's queue; a periodic sweep job is a future addition.
Each recipient's queue is capped in bytes (MAX_QUEUED_BYTES_PER_RECIPIENT), so
an account that never collects cannot be made to hold unbounded ciphertext.
"""

from __future__ import annotations

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..constants import MAX_PAYLOAD_BYTES, MAX_QUEUED_BYTES_PER_RECIPIENT, MESSAGE_TTL_SECONDS
from ..deps import get_session
from ..models import QueuedMessage, User
from ..rate_limit import TokenBucketLimiter
from ..schemas import AckRequest, MessagesResponse, QueuedMessageOut, SendMessageRequest
from ..security_log import record_security_event
from ..ws import WsHub

router = APIRouter(prefix="/v1")


def _client_ip(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


def _sweep_expired(session: Session, recipient_id: int, now: float) -> None:
    session.execute(
        delete(QueuedMessage).where(
            QueuedMessage.recipient_user_id == recipient_id,
            QueuedMessage.created_at < now - MESSAGE_TTL_SECONDS,
        )
    )


def _queued_bytes(session: Session, recipient_id: int) -> int:
    """Ciphertext bytes currently waiting for one recipient. length() of a
    binary column is its size in bytes on both SQLite and Postgres, and Postgres
    answers it from the stored value's header without reading the value."""
    total = session.execute(
        select(func.coalesce(func.sum(func.length(QueuedMessage.envelope)), 0)).where(
            QueuedMessage.recipient_user_id == recipient_id
        )
    ).scalar_one()
    return int(total)


@router.post("/messages", status_code=204)
async def send_message(
    payload: SendMessageRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    limiter: TokenBucketLimiter = request.app.state.message_send_limiter
    if not limiter.allow(ctx.user.uid):
        record_security_event(
            "rate_limit_exceeded", endpoint=request.url.path, client_ip=_client_ip(request)
        )
        raise HTTPException(status_code=429, detail="rate_limited")

    envelope = payload.decoded_envelope()
    if len(envelope) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="invalid_request")

    # Deliberately no row lock (FOR UPDATE) for the cap check below. This route
    # does its database work on the event loop, and a lock still held when the
    # request unwinds is released only by the session teardown, which needs the
    # very event loop that a second send, blocked on that lock, is holding. That
    # deadlock froze the whole process under concurrent sends. Without a lock,
    # measuring and inserting is still atomic within one server process, since
    # nothing between them awaits; separate processes racing on one recipient can
    # each slip one envelope past the cap, at most one payload per extra worker.
    recipient = session.execute(
        select(User).where(User.uid == payload.recipient_uid)
    ).scalar_one_or_none()
    if recipient is None:
        # Accept-and-drop: a distinguishable error here would be a UID
        # existence oracle. Honest senders always fetched the
        # recipient's bundle first, so they already know.
        return

    now: float = request.app.state.clock()
    _sweep_expired(session, recipient.id, now)
    if _queued_bytes(session, recipient.id) + len(envelope) > MAX_QUEUED_BYTES_PER_RECIPIENT:
        # Refused, not dropped: a dropped message would look delivered to the
        # sender, who can only try again later if told it did not go. Only an
        # account that exists can have a full queue, but that is no new oracle:
        # reaching the cap takes tens of megabytes sent to a UID the sender
        # already confirmed by fetching its bundle.
        #
        # Committed first, for the reason above: the sweep's deletes hold row
        # locks until the transaction ends, and they must not still be held
        # while the refusal unwinds through an await.
        session.commit()
        record_security_event(
            "queue_full", endpoint=request.url.path, client_ip=_client_ip(request)
        )
        raise HTTPException(status_code=507, detail="queue_full")
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
