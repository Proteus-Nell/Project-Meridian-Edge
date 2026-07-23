from __future__ import annotations

import base64
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.constants import LOGIN_CHALLENGE_RATE_CAPACITY
from app.main import create_app

from .conftest import FakeClock
from .helpers import Account, auth, login, register, sign_challenge


def test_login_happy_path(client: TestClient) -> None:
    account = Account()
    assert register(client, account).status_code == 201
    token = login(client, account)
    res = client.get("/v1/keys/status", headers=auth(token))
    assert res.status_code == 200


def test_nonce_replay_rejected(client: TestClient) -> None:
    account = Account()
    register(client, account)
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}).json()
    signature = sign_challenge(account, challenge["nonce"], "", challenge["timestamp"])
    body = {"uid": account.uid, "nonce": challenge["nonce"], "signature": signature}
    assert client.post("/v1/login/verify", json=body).status_code == 200
    replay = client.post("/v1/login/verify", json=body)
    assert replay.status_code == 401
    assert replay.json() == {"error": "auth_failed"}


def test_failed_attempt_burns_nonce(client: TestClient) -> None:
    account = Account()
    intruder = Account()  # different key, same uid claim
    register(client, account)
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}).json()
    bad_sig = sign_challenge(intruder, challenge["nonce"], "", challenge["timestamp"])
    body = {"uid": account.uid, "nonce": challenge["nonce"], "signature": bad_sig}
    assert client.post("/v1/login/verify", json=body).status_code == 401
    # The legitimate key cannot reuse the burned nonce either: single-use.
    good_sig = sign_challenge(account, challenge["nonce"], "", challenge["timestamp"])
    body["signature"] = good_sig
    assert client.post("/v1/login/verify", json=body).status_code == 401


def test_nonce_expires_after_60s(client: TestClient, clock: FakeClock) -> None:
    account = Account()
    register(client, account)
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}).json()
    signature = sign_challenge(account, challenge["nonce"], "", challenge["timestamp"])
    body = {"uid": account.uid, "nonce": challenge["nonce"], "signature": signature}
    clock.advance(61.0)
    assert client.post("/v1/login/verify", json=body).status_code == 401


def test_nonce_valid_within_ttl(client: TestClient, clock: FakeClock) -> None:
    account = Account()
    register(client, account)
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}).json()
    signature = sign_challenge(account, challenge["nonce"], "", challenge["timestamp"])
    body = {"uid": account.uid, "nonce": challenge["nonce"], "signature": signature}
    clock.advance(59.0)
    assert client.post("/v1/login/verify", json=body).status_code == 200


def test_origin_binding(client: TestClient) -> None:
    account = Account()
    register(client, account)
    origin_a = {"origin": "https://meridian-edge.example"}
    challenge = client.post(
        "/v1/login/challenge", json={"uid": account.uid}, headers=origin_a
    ).json()
    # Signed for origin A but presented from origin B: rejected.
    signature = sign_challenge(
        account, challenge["nonce"], "https://meridian-edge.example", challenge["timestamp"]
    )
    body = {"uid": account.uid, "nonce": challenge["nonce"], "signature": signature}
    res = client.post(
        "/v1/login/verify", json=body, headers={"origin": "https://evil.example"}
    )
    assert res.status_code == 401


def test_origin_binding_happy_path(client: TestClient) -> None:
    account = Account()
    register(client, account)
    token = login(client, account, origin="https://meridian-edge.example")
    assert len(token) == 64  # 32 bytes hex


def test_unknown_uid_is_not_an_oracle(client: TestClient) -> None:
    """Challenge succeeds for any well-formed UID; verify fails uniformly."""
    ghost = Account()
    ghost.uid_display = "7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ01-23"
    challenge = client.post("/v1/login/challenge", json={"uid": ghost.uid})
    assert challenge.status_code == 200
    body = challenge.json()
    assert set(body.keys()) == {"nonce", "timestamp", "origin"}

    signature = sign_challenge(ghost, body["nonce"], "", body["timestamp"])
    res = client.post(
        "/v1/login/verify",
        json={"uid": ghost.uid, "nonce": body["nonce"], "signature": signature},
    )
    assert res.status_code == 401
    assert res.json() == {"error": "auth_failed"}  # identical to wrong-signature case


def test_malformed_uid_rejected(client: TestClient) -> None:
    res = client.post("/v1/login/challenge", json={"uid": "not-a-uid"})
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request"}


def test_garbage_signature_rejected(client: TestClient) -> None:
    account = Account()
    register(client, account)
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}).json()
    garbage = base64.b64encode(bytes(3309)).decode()
    res = client.post(
        "/v1/login/verify",
        json={"uid": account.uid, "nonce": challenge["nonce"], "signature": garbage},
    )
    assert res.status_code == 401


def test_challenge_rate_limited(client: TestClient) -> None:
    account = Account()
    register(client, account)
    for _ in range(LOGIN_CHALLENGE_RATE_CAPACITY):
        assert client.post("/v1/login/challenge", json={"uid": account.uid}).status_code == 200
    res = client.post("/v1/login/challenge", json={"uid": account.uid})
    assert res.status_code == 429
    assert res.json() == {"error": "rate_limited"}


# --- Origin allowlist -------------------------------------------------------
#
# Distinct from the origin *binding* above: binding stops a signature made for
# one origin being replayed at another and always applies, whereas the
# allowlist restricts which origins the deployment serves at all. The default
# `client` fixture leaves the allowlist unset (the local-development shape), so
# these use their own app.

ALLOWED_ORIGIN = "https://meridian-edge.example"


@pytest.fixture()
def restricted_client(clock: FakeClock) -> Iterator[TestClient]:
    app = create_app("sqlite://", clock=clock, allowed_origins=[ALLOWED_ORIGIN])
    with TestClient(app) as test_client:
        yield test_client


def test_challenge_allowed_from_listed_origin(restricted_client: TestClient) -> None:
    account = Account()
    register(restricted_client, account)
    res = restricted_client.post(
        "/v1/login/challenge", json={"uid": account.uid}, headers={"origin": ALLOWED_ORIGIN}
    )
    assert res.status_code == 200


def test_challenge_refused_from_unlisted_origin(restricted_client: TestClient) -> None:
    account = Account()
    register(restricted_client, account)
    res = restricted_client.post(
        "/v1/login/challenge",
        json={"uid": account.uid},
        headers={"origin": "https://evil.example"},
    )
    assert res.status_code == 403
    # Collapses to the generic body: the allowlist is not an oracle either.
    assert res.json() == {"error": "request_failed"}


def test_challenge_refused_without_an_origin_header(restricted_client: TestClient) -> None:
    account = Account()
    register(restricted_client, account)
    assert restricted_client.post("/v1/login/challenge", json={"uid": account.uid}).status_code == 403


def test_verify_refused_from_unlisted_origin(restricted_client: TestClient) -> None:
    # A nonce legitimately issued to the served origin must not be redeemable
    # from anywhere else, so the check is repeated at verify.
    account = Account()
    register(restricted_client, account)
    challenge = restricted_client.post(
        "/v1/login/challenge", json={"uid": account.uid}, headers={"origin": ALLOWED_ORIGIN}
    ).json()
    signature = sign_challenge(account, challenge["nonce"], ALLOWED_ORIGIN, challenge["timestamp"])
    body = {"uid": account.uid, "nonce": challenge["nonce"], "signature": signature}
    res = restricted_client.post(
        "/v1/login/verify", json=body, headers={"origin": "https://evil.example"}
    )
    assert res.status_code == 403


def test_full_login_succeeds_through_the_allowlist(restricted_client: TestClient) -> None:
    account = Account()
    register(restricted_client, account)
    token = login(restricted_client, account, origin=ALLOWED_ORIGIN)
    assert len(token) == 64


def test_allowlist_unset_leaves_any_origin_usable(client: TestClient) -> None:
    # Local development must keep working with no configuration at all.
    account = Account()
    register(client, account)
    res = client.post(
        "/v1/login/challenge",
        json={"uid": account.uid},
        headers={"origin": "http://localhost:5174"},
    )
    assert res.status_code == 200
