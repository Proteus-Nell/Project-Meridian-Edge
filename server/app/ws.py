"""WebSocket delivery (CLAUDE.md sections 3, 5, 7.11).

Order of operations is the security property: origin check before accept,
authentication before the socket is attached to any queue, session-token
rotation on every connect (§2.3). Frames over 64 KiB close the connection.
Ack handling matches the REST path: delete own rows only.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from .auth import authenticate_token
from .constants import (
    ACK_MAX_IDS,
    MESSAGE_TTL_SECONDS,
    WS_AUTH_TIMEOUT_SECONDS,
    WS_MAX_FRAME_BYTES,
)
from .models import QueuedMessage, SessionToken
from .security import hash_token, new_session_token

router = APIRouter()

# Close codes (4000-4999 = application-defined).
WS_CLOSE_BAD_ORIGIN = 4403
WS_CLOSE_AUTH_FAILED = 4401
WS_CLOSE_PROTOCOL = 4400


class WsHub:
    """Live connections per user id. Single-event-loop; no locking needed."""

    def __init__(self) -> None:
        self._connections: dict[int, set[WebSocket]] = {}

    def register(self, user_id: int, ws: WebSocket) -> None:
        self._connections.setdefault(user_id, set()).add(ws)

    def unregister(self, user_id: int, ws: WebSocket) -> None:
        conns = self._connections.get(user_id)
        if conns is not None:
            conns.discard(ws)
            if not conns:
                del self._connections[user_id]

    async def push(self, user_id: int, payload: dict[str, object]) -> None:
        for ws in list(self._connections.get(user_id, ())):
            try:
                await ws.send_json(payload)
            except Exception:
                self.unregister(user_id, ws)


def _parse_frame(raw: str) -> dict[str, Any] | None:
    if len(raw) > WS_MAX_FRAME_BYTES:
        return None
    try:
        parsed: Any = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


@router.websocket("/v1/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    # Accept first so the rejection is a proper close frame with an
    # application code (a pre-accept close surfaces as an opaque HTTP 403).
    # Nothing is attached to any queue until origin AND auth both pass.
    await websocket.accept()
    allowed_origins: list[str] | None = websocket.app.state.ws_origins
    if allowed_origins is not None:
        origin = websocket.headers.get("origin", "")
        if origin not in allowed_origins:
            await websocket.close(code=WS_CLOSE_BAD_ORIGIN)
            return
    maker: sessionmaker[Session] = websocket.app.state.sessionmaker
    clock = websocket.app.state.clock

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=WS_AUTH_TIMEOUT_SECONDS)
    except (TimeoutError, WebSocketDisconnect):
        await websocket.close(code=WS_CLOSE_AUTH_FAILED)
        return
    frame = _parse_frame(raw)
    token = frame.get("token") if frame is not None and frame.get("type") == "auth" else None
    if not isinstance(token, str):
        await websocket.close(code=WS_CLOSE_AUTH_FAILED)
        return

    now: float = clock()
    with maker() as db:
        row = authenticate_token(db, token, now)
        if row is None:
            db.commit()
            await websocket.close(code=WS_CLOSE_AUTH_FAILED)
            return
        user_id = row.user_id
        # Token rotation on every WS connect (§2.3): the presented token is
        # retired and a fresh one is issued over the socket.
        row.revoked = True
        rotated = new_session_token()
        db.add(SessionToken(token_hash=hash_token(rotated), user_id=user_id, last_used=now))
        db.commit()

    await websocket.send_json({"type": "token", "token": rotated})

    hub = websocket.app.state.ws_hub
    hub.register(user_id, websocket)
    try:
        await _push_pending(websocket, maker, user_id, clock())
        while True:
            raw = await websocket.receive_text()
            frame = _parse_frame(raw)
            if frame is None:
                await websocket.close(code=WS_CLOSE_PROTOCOL)
                return
            kind = frame.get("type")
            if kind == "ping":
                await websocket.send_json({"type": "pong"})
            elif kind == "ack":
                ids = frame.get("ids")
                if isinstance(ids, list) and 0 < len(ids) <= ACK_MAX_IDS:
                    int_ids = [i for i in ids if isinstance(i, int)]
                    with maker() as db:
                        db.execute(
                            delete(QueuedMessage).where(
                                QueuedMessage.id.in_(int_ids),
                                QueuedMessage.recipient_user_id == user_id,
                            )
                        )
                        db.commit()
    except WebSocketDisconnect:
        pass
    finally:
        hub.unregister(user_id, websocket)


async def _push_pending(
    websocket: WebSocket,
    maker: sessionmaker[Session],
    user_id: int,
    now: float,
) -> None:
    with maker() as db:
        db.execute(
            delete(QueuedMessage).where(
                QueuedMessage.recipient_user_id == user_id,
                QueuedMessage.created_at < now - MESSAGE_TTL_SECONDS,
            )
        )
        db.commit()
        rows = (
            db.execute(
                select(QueuedMessage)
                .where(QueuedMessage.recipient_user_id == user_id)
                .order_by(QueuedMessage.id)
            )
            .scalars()
            .all()
        )
        pending = [(row.id, base64.b64encode(row.envelope).decode()) for row in rows]
    for message_id, envelope in pending:
        await websocket.send_json({"type": "message", "id": message_id, "envelope": envelope})
