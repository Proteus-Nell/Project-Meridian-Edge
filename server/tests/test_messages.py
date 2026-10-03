from __future__ import annotations

import base64
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.constants import (
    MAX_PAYLOAD_BYTES,
    MAX_QUEUED_BYTES_PER_RECIPIENT,
    MESSAGE_SEND_RATE_CAPACITY,
)
from app.models import QueuedMessage
from app.rate_limit import TokenBucketLimiter
from app.routes import messages as messages_route

from .conftest import FakeClock
from .helpers import auth, login, register_and_login

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

    # Mallory acks Bob's id: uniform 204, nothing deleted.
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


# ----- per-recipient queue cap ------------------------------------------------

ENVELOPE_BYTES = base64.b64decode(ENVELOPE)


def envelope_of(size: int) -> str:
    return base64.b64encode(bytes(size)).decode()


def unlimited_sends(app: FastAPI) -> None:
    """Lift the per-sender rate limit, which is not what these tests are about."""
    app.state.message_send_limiter = TokenBucketLimiter(10**9, 1.0)


@pytest.fixture()
def small_cap(monkeypatch: pytest.MonkeyPatch) -> int:
    """A cap of three test envelopes, so filling a queue takes three sends."""
    cap = 3 * len(ENVELOPE_BYTES)
    monkeypatch.setattr(messages_route, "MAX_QUEUED_BYTES_PER_RECIPIENT", cap)
    return cap


def inbox(client: TestClient, token: str) -> list[dict[str, object]]:
    messages: list[dict[str, object]] = client.get("/v1/messages", headers=auth(token)).json()[
        "messages"
    ]
    return messages


def test_full_queue_refuses_with_507(client: TestClient, small_cap: int) -> None:
    _, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    # The third send lands exactly on the cap, which is still within it.
    for _ in range(3):
        assert send(client, token_a, bob.uid) == 204
    res = client.post(
        "/v1/messages",
        json={"recipient_uid": bob.uid, "envelope": ENVELOPE},
        headers=auth(token_a),
    )
    assert res.status_code == 507
    assert res.json() == {"error": "queue_full"}
    # Refused, not dropped: nothing past the cap was stored.
    assert len(inbox(client, token_b)) == 3


def test_cap_counts_bytes_not_messages(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(messages_route, "MAX_QUEUED_BYTES_PER_RECIPIENT", 100)
    _, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    assert send(client, token_a, bob.uid, envelope_of(95)) == 204
    assert send(client, token_a, bob.uid, envelope_of(6)) == 507
    assert send(client, token_a, bob.uid, envelope_of(5)) == 204


def test_ack_frees_room(client: TestClient, small_cap: int) -> None:
    _, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    for _ in range(3):
        assert send(client, token_a, bob.uid) == 204
    assert send(client, token_a, bob.uid) == 507

    first = inbox(client, token_b)[0]["id"]
    assert (
        client.post("/v1/messages/ack", json={"ids": [first]}, headers=auth(token_b)).status_code
        == 204
    )
    assert send(client, token_a, bob.uid) == 204


def test_expired_messages_free_room(
    client: TestClient, clock: FakeClock, small_cap: int
) -> None:
    alice, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    for _ in range(3):
        assert send(client, token_a, bob.uid) == 204
    assert send(client, token_a, bob.uid) == 507

    clock.advance(14 * 86400 + 1)
    # The TTL sweep runs inside the send, before the queue is measured.
    assert send(client, login(client, alice), bob.uid) == 204


def test_refusal_still_commits_the_ttl_sweep(
    app: FastAPI, client: TestClient, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The refusal ends its transaction before it unwinds, so the expired rows
    # the sweep deleted stay deleted, and no row lock is left held across the
    # await (see the route). Two envelopes fill the cap; the older expires.
    monkeypatch.setattr(messages_route, "MAX_QUEUED_BYTES_PER_RECIPIENT", 20)
    alice, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    assert send(client, token_a, bob.uid, envelope_of(10)) == 204
    clock.advance(86400)
    assert send(client, login(client, alice), bob.uid, envelope_of(10)) == 204
    clock.advance(13 * 86400 + 1)

    # 10 live bytes + 11 is over the cap even after the sweep: refused.
    assert send(client, login(client, alice), bob.uid, envelope_of(11)) == 507
    with app.state.sessionmaker() as session:
        rows = session.execute(select(func.count()).select_from(QueuedMessage)).scalar_one()
    assert rows == 1


def test_cap_is_per_recipient(client: TestClient, small_cap: int) -> None:
    _, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    carol, _ = register_and_login(client)
    for _ in range(3):
        assert send(client, token_a, bob.uid) == 204
    assert send(client, token_a, bob.uid) == 507
    assert send(client, token_a, carol.uid) == 204


def test_cap_applies_across_senders(client: TestClient, small_cap: int) -> None:
    _, token_a = register_and_login(client)
    _, token_c = register_and_login(client)
    bob, _ = register_and_login(client)
    for _ in range(3):
        assert send(client, token_a, bob.uid) == 204
    # A fresh sender has spent none of its own budget, and is refused anyway:
    # the cap is the recipient's, which is the point.
    assert send(client, token_c, bob.uid) == 507


def test_unknown_recipient_is_not_an_oracle_at_any_volume(
    client: TestClient, small_cap: int
) -> None:
    _, token = register_and_login(client)
    for _ in range(5):
        assert send(client, token, GHOST_UID) == 204


def test_full_queue_is_logged_without_either_uid(
    client: TestClient, small_cap: int, caplog: pytest.LogCaptureFixture
) -> None:
    alice, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    for _ in range(3):
        assert send(client, token_a, bob.uid) == 204
    with caplog.at_level(logging.WARNING, logger="meridian_edge.security"):
        assert send(client, token_a, bob.uid) == 507
    assert "security_event=queue_full endpoint=/v1/messages" in caplog.text
    assert alice.uid not in caplog.text
    assert bob.uid not in caplog.text


def test_default_cap_holds_512_maximum_size_envelopes(app: FastAPI, client: TestClient) -> None:
    # The real constant, at full size: room for exactly 512 envelopes at the
    # payload cap, the headroom left for attachments small enough to travel
    # inside one, and not a byte more.
    assert MAX_QUEUED_BYTES_PER_RECIPIENT == 512 * MAX_PAYLOAD_BYTES
    unlimited_sends(app)
    _, token_a = register_and_login(client)
    bob, _ = register_and_login(client)
    biggest = envelope_of(MAX_PAYLOAD_BYTES)
    for _ in range(512):
        assert send(client, token_a, bob.uid, biggest) == 204
    assert send(client, token_a, bob.uid, envelope_of(1)) == 507
