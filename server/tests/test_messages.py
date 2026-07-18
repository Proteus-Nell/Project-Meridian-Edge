from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.constants import MESSAGE_SEND_RATE_CAPACITY

from .conftest import FakeClock
from .helpers import auth, register_and_login

ENVELOPE = base64.b64encode(b"opaque-kx-envelope-bytes").decode()
GHOST_UID = "7Q3KM2VD9XWP4RTBA6HJEZ0123"


def send(client: TestClient, token: str, recipient_uid: str, envelope: str = ENVELOPE) -> int:
    res = client.post(
        "/v1/messages",
        json={"recipient_uid": recipient_uid, "envelope": envelope},
        headers=auth(token),
    )
    return res.status_code


def test_enqueue_fetch_ack_lifecycle(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)

    assert send(client, token_a, bob.uid) == 204
    inbox = client.get("/v1/messages", headers=auth(token_b)).json()["messages"]
    assert len(inbox) == 1
    assert inbox[0]["envelope"] == ENVELOPE

    ack = client.post(
        "/v1/messages/ack", json={"ids": [inbox[0]["id"]]}, headers=auth(token_b)
    )
    assert ack.status_code == 204
    # Delete-on-ack: the row is gone, not archived.
    assert client.get("/v1/messages", headers=auth(token_b)).json()["messages"] == []


def test_ack_cannot_delete_someone_elses_messages(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    mallory, token_m = register_and_login(client)

    assert send(client, token_a, bob.uid) == 204
    message_id = client.get("/v1/messages", headers=auth(token_b)).json()["messages"][0]["id"]

    # Mallory acks Bob's id: uniform 204, nothing deleted (§7.1, §7.4).
    assert (
        client.post("/v1/messages/ack", json={"ids": [message_id]}, headers=auth(token_m)).status_code
        == 204
    )
    assert len(client.get("/v1/messages", headers=auth(token_b)).json()["messages"]) == 1


def test_oversized_envelope_uniform_413(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    big = base64.b64encode(bytes(65537)).decode()
    res = client.post(
        "/v1/messages",
        json={"recipient_uid": bob.uid, "envelope": big},
        headers=auth(token_a),
    )
    assert res.status_code == 413
    assert res.json() == {"error": "invalid_request"}


def test_unknown_recipient_is_not_an_oracle(client: TestClient) -> None:
    _, token = register_and_login(client)
    # Accept-and-drop: same 204 as a real enqueue.
    assert send(client, token, GHOST_UID) == 204


def test_ttl_evicts_after_14_days(client: TestClient, clock: FakeClock) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    assert send(client, token_a, bob.uid) == 204

    clock.advance(14 * 86400 + 1)
    # Sessions have idle-expired; log Bob in again to look.
    from .helpers import login

    token_b2 = login(client, bob)
    assert client.get("/v1/messages", headers=auth(token_b2)).json()["messages"] == []


def test_send_rate_limited(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    for _ in range(MESSAGE_SEND_RATE_CAPACITY):
        assert send(client, token_a, bob.uid) == 204
    res = client.post(
        "/v1/messages",
        json={"recipient_uid": bob.uid, "envelope": ENVELOPE},
        headers=auth(token_a),
    )
    assert res.status_code == 429
