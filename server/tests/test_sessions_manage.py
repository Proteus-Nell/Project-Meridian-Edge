"""Session listing and bulk sign-out (routes/sessions.py).

Complements test_sessions.py, which covers token lifecycle (idle expiry,
per-login distinctness, single logout). Here the focus is the account-security
surface: enumerating live sessions and signing out every other one.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from .conftest import FakeClock
from .helpers import Account, auth, login, register, register_and_login


def test_sessions_requires_auth(client: TestClient) -> None:
    assert client.get("/v1/sessions").status_code == 401


def test_logout_all_requires_auth(client: TestClient) -> None:
    assert client.post("/v1/logout/all").status_code == 401


def test_lists_one_session_marked_current(client: TestClient) -> None:
    _, token = register_and_login(client)
    body = client.get("/v1/sessions", headers=auth(token)).json()
    assert len(body["sessions"]) == 1
    assert body["sessions"][0]["current"] is True


def test_lists_each_login_and_marks_only_the_caller_current(client: TestClient) -> None:
    account = Account()
    register(client, account)
    first = login(client, account)
    second = login(client, account)
    third = login(client, account)

    body = client.get("/v1/sessions", headers=auth(second)).json()
    assert len(body["sessions"]) == 3
    currents = [s["current"] for s in body["sessions"]]
    assert currents.count(True) == 1

    # Each token sees itself as the current one, never another.
    for token in (first, second, third):
        seen = client.get("/v1/sessions", headers=auth(token)).json()["sessions"]
        assert sum(s["current"] for s in seen) == 1


def test_age_and_idle_seconds_reflect_the_clock(client: TestClient, clock: FakeClock) -> None:
    _, token = register_and_login(client)
    clock.advance(120.0)
    body = client.get("/v1/sessions", headers=auth(token)).json()
    session = body["sessions"][0]
    # The GET itself refreshes last_used, so idle resets while age keeps growing.
    assert session["age_seconds"] >= 120
    assert session["idle_seconds"] == 0


def test_idle_expired_sessions_are_omitted(client: TestClient, clock: FakeClock) -> None:
    account = Account()
    register(client, account)
    stale = login(client, account)
    clock.advance(800.0)  # `stale` now within the 900s window but aging
    fresh = login(client, account)
    clock.advance(200.0)  # stale: 1000s idle (expired); fresh: 200s idle (live)

    body = client.get("/v1/sessions", headers=auth(fresh)).json()
    assert len(body["sessions"]) == 1
    assert body["sessions"][0]["current"] is True
    # The expired one is also refused as a credential.
    assert client.get("/v1/sessions", headers=auth(stale)).status_code == 401


def test_logout_all_revokes_others_and_keeps_current(client: TestClient) -> None:
    account = Account()
    register(client, account)
    keep = login(client, account)
    other_a = login(client, account)
    other_b = login(client, account)

    res = client.post("/v1/logout/all", headers=auth(keep))
    assert res.status_code == 200
    assert res.json() == {"revoked": 2}

    # The caller's session still works; the others are dead.
    assert client.get("/v1/keys/status", headers=auth(keep)).status_code == 200
    assert client.get("/v1/keys/status", headers=auth(other_a)).status_code == 401
    assert client.get("/v1/keys/status", headers=auth(other_b)).status_code == 401

    # Only the caller remains in the listing.
    body = client.get("/v1/sessions", headers=auth(keep)).json()
    assert len(body["sessions"]) == 1


def test_logout_all_with_only_one_session_revokes_nothing(client: TestClient) -> None:
    _, token = register_and_login(client)
    res = client.post("/v1/logout/all", headers=auth(token))
    assert res.json() == {"revoked": 0}
    assert client.get("/v1/keys/status", headers=auth(token)).status_code == 200


def test_logout_all_is_scoped_to_the_caller(client: TestClient) -> None:
    # One user's bulk sign-out must never touch another user's sessions.
    _, victim = register_and_login(client)
    _, attacker = register_and_login(client)
    assert client.post("/v1/logout/all", headers=auth(attacker)).json() == {"revoked": 0}
    assert client.get("/v1/keys/status", headers=auth(victim)).status_code == 200
