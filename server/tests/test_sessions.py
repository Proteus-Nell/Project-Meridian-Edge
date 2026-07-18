from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import FakeClock
from .helpers import auth, register_and_login


def test_missing_and_garbage_tokens_rejected(client: TestClient) -> None:
    assert client.get("/v1/keys/status").status_code == 401
    assert client.get("/v1/keys/status", headers=auth("f" * 64)).status_code == 401
    assert (
        client.get("/v1/keys/status", headers={"authorization": "Basic abc"}).status_code == 401
    )


def test_idle_expiry_after_15_minutes(client: TestClient, clock: FakeClock) -> None:
    _, token = register_and_login(client)
    clock.advance(901.0)
    res = client.get("/v1/keys/status", headers=auth(token))
    assert res.status_code == 401
    assert res.json() == {"error": "auth_failed"}


def test_activity_slides_the_idle_window(client: TestClient, clock: FakeClock) -> None:
    _, token = register_and_login(client)
    for _ in range(3):
        clock.advance(800.0)
        assert client.get("/v1/keys/status", headers=auth(token)).status_code == 200
    clock.advance(901.0)
    assert client.get("/v1/keys/status", headers=auth(token)).status_code == 401


def test_logout_revokes_server_side(client: TestClient) -> None:
    _, token = register_and_login(client)
    assert client.post("/v1/logout", headers=auth(token)).status_code == 204
    assert client.get("/v1/keys/status", headers=auth(token)).status_code == 401


def test_logout_requires_auth(client: TestClient) -> None:
    assert client.post("/v1/logout").status_code == 401


def test_tokens_are_distinct_per_login(client: TestClient) -> None:
    account, first = register_and_login(client)
    from .helpers import login

    second = login(client, account)
    assert first != second
    # Both valid until revoked/expired; revoking one leaves the other alive.
    assert client.post("/v1/logout", headers=auth(first)).status_code == 204
    assert client.get("/v1/keys/status", headers=auth(first)).status_code == 401
    assert client.get("/v1/keys/status", headers=auth(second)).status_code == 200
