from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import create_app

from .conftest import FakeClock
from .helpers import auth, register_and_login

ENVELOPE = base64.b64encode(b"opaque-envelope").decode()


def test_ws_rejects_bad_token(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/v1/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": "f" * 64}))
            ws.receive_json()
    assert exc.value.code == 4401


def test_ws_rejects_non_auth_first_frame(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/v1/ws") as ws:
            ws.send_text(json.dumps({"type": "ping"}))
            ws.receive_json()
    assert exc.value.code == 4401


def test_ws_auth_rotates_the_token(client: TestClient) -> None:
    _, token = register_and_login(client)
    with client.websocket_connect("/v1/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        frame = ws.receive_json()
        assert frame["type"] == "token"
        rotated = frame["token"]
        assert rotated != token
        # Old token is dead; the rotated one works.
        assert client.get("/v1/keys/status", headers=auth(token)).status_code == 401
        assert client.get("/v1/keys/status", headers=auth(rotated)).status_code == 200


def test_ws_pushes_pending_messages_and_ack_deletes(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    assert (
        client.post(
            "/v1/messages",
            json={"recipient_uid": bob.uid, "envelope": ENVELOPE},
            headers=auth(token_a),
        ).status_code
        == 204
    )

    with client.websocket_connect("/v1/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token_b}))
        rotated = ws.receive_json()["token"]
        pushed = ws.receive_json()
        assert pushed["type"] == "message"
        assert pushed["envelope"] == ENVELOPE

        ws.send_text(json.dumps({"type": "ack", "ids": [pushed["id"]]}))
        # ping/pong round-trip guarantees the ack frame was processed.
        ws.send_text(json.dumps({"type": "ping"}))
        assert ws.receive_json() == {"type": "pong"}
        assert client.get("/v1/messages", headers=auth(rotated)).json()["messages"] == []


def test_ws_delivers_live_messages(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)

    with client.websocket_connect("/v1/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token_b}))
        ws.receive_json()  # rotated token
        assert (
            client.post(
                "/v1/messages",
                json={"recipient_uid": bob.uid, "envelope": ENVELOPE},
                headers=auth(token_a),
            ).status_code
            == 204
        )
        live = ws.receive_json()
        assert live["type"] == "message"
        assert live["envelope"] == ENVELOPE


def test_ws_origin_allowlist(clock: FakeClock) -> None:
    app = create_app("sqlite://", clock=clock, ws_origins=["https://meridian-edge.example"])
    with TestClient(app) as restricted:
        with pytest.raises(WebSocketDisconnect) as exc:
            with restricted.websocket_connect(
                "/v1/ws", headers={"origin": "https://evil.example"}
            ) as ws:
                ws.receive_json()
        assert exc.value.code == 4403


def test_ws_idle_connection_is_closed(clock: FakeClock) -> None:
    # The idle-kill window is real wall-clock time (asyncio.wait_for), not the
    # injectable business-logic `clock` - override it directly to a tiny value
    # so the test doesn't sleep for the real 90s default.
    app = create_app("sqlite://", clock=clock, ws_idle_timeout_seconds=0.05)
    with TestClient(app) as fast_idle_client:
        _, token = register_and_login(fast_idle_client)
        with pytest.raises(WebSocketDisconnect) as exc:
            with fast_idle_client.websocket_connect("/v1/ws") as ws:
                ws.send_text(json.dumps({"type": "auth", "token": token}))
                ws.receive_json()  # rotated token
                ws.receive_json()  # nothing else arrives - idle-kill fires
        assert exc.value.code == 4408


def test_ws_heartbeat_ping_keeps_a_quiet_connection_alive(client: TestClient) -> None:
    _, token = register_and_login(client)
    with client.websocket_connect("/v1/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        ws.receive_json()
        # A ping (the client's periodic heartbeat) is ordinary traffic, not a
        # special case - repeated pings keep an otherwise-quiet connection open.
        for _ in range(3):
            ws.send_text(json.dumps({"type": "ping"}))
            assert ws.receive_json() == {"type": "pong"}


def test_ws_per_connection_frame_rate_limited(client: TestClient, clock: FakeClock) -> None:
    _, token = register_and_login(client)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/v1/ws") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": token}))
            ws.receive_json()
            # Burst well past the per-connection budget without letting the
            # clock refill it.
            for _ in range(50):
                ws.send_text(json.dumps({"type": "ping"}))
            for _ in range(50):
                ws.receive_json()
    assert exc.value.code == 4429
