from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.constants import KEYS_UPLOAD_RATE_CAPACITY

from .helpers import auth, register_and_login

SPK_PUB = base64.b64encode(bytes(1184)).decode()
SIG = base64.b64encode(bytes(3309)).decode()


def _opks(count: int) -> list[str]:
    return [base64.b64encode(bytes([i % 256]) + bytes(1183)).decode() for i in range(count)]


def test_keys_endpoints_require_auth(client: TestClient) -> None:
    assert client.post("/v1/keys/spk", json={"spk_pub": SPK_PUB, "spk_sig": SIG}).status_code == 401
    assert (
        client.post("/v1/keys/opks", json={"opks": _opks(1), "root_sig": SIG}).status_code == 401
    )
    assert client.get("/v1/keys/status").status_code == 401


def test_upload_and_status(client: TestClient) -> None:
    _, token = register_and_login(client)
    assert (
        client.post(
            "/v1/keys/spk", json={"spk_pub": SPK_PUB, "spk_sig": SIG}, headers=auth(token)
        ).status_code
        == 204
    )
    assert (
        client.post(
            "/v1/keys/opks", json={"opks": _opks(50), "root_sig": SIG}, headers=auth(token)
        ).status_code
        == 204
    )
    status = client.get("/v1/keys/status", headers=auth(token)).json()
    assert status["opk_count"] == 50
    assert status["spk_uploaded_at"] is not None


def test_wrong_sizes_rejected(client: TestClient) -> None:
    _, token = register_and_login(client)
    short_pub = base64.b64encode(bytes(100)).decode()
    res = client.post(
        "/v1/keys/spk", json={"spk_pub": short_pub, "spk_sig": SIG}, headers=auth(token)
    )
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request"}


def test_oversized_batch_rejected(client: TestClient) -> None:
    _, token = register_and_login(client)
    res = client.post(
        "/v1/keys/opks", json={"opks": _opks(51), "root_sig": SIG}, headers=auth(token)
    )
    assert res.status_code == 400


def test_unconsumed_cap_enforced(client: TestClient) -> None:
    _, token = register_and_login(client)
    for _ in range(4):
        assert (
            client.post(
                "/v1/keys/opks", json={"opks": _opks(50), "root_sig": SIG}, headers=auth(token)
            ).status_code
            == 204
        )
    res = client.post(
        "/v1/keys/opks", json={"opks": _opks(1), "root_sig": SIG}, headers=auth(token)
    )
    assert res.status_code == 400


def test_status_is_scoped_to_own_user(client: TestClient) -> None:
    _, token_a = register_and_login(client)
    _, token_b = register_and_login(client)
    client.post("/v1/keys/opks", json={"opks": _opks(10), "root_sig": SIG}, headers=auth(token_a))
    assert client.get("/v1/keys/status", headers=auth(token_a)).json()["opk_count"] == 10
    assert client.get("/v1/keys/status", headers=auth(token_b)).json()["opk_count"] == 0


# --- Upload rate limit -------------------------------------------------------
#
# Signed-prekey rows have no other cap, so without a limit an authenticated
# client could grow that table without bound. Exercised through /spk because
# /opks would hit its own unconsumed cap first.


def _upload_spk(client: TestClient, token: str) -> int:
    res = client.post(
        "/v1/keys/spk", json={"spk_pub": SPK_PUB, "spk_sig": SIG}, headers=auth(token)
    )
    return res.status_code


def test_prekey_uploads_are_rate_limited(client: TestClient) -> None:
    _, token = register_and_login(client)
    for _ in range(KEYS_UPLOAD_RATE_CAPACITY):
        assert _upload_spk(client, token) == 204
    res = client.post(
        "/v1/keys/spk", json={"spk_pub": SPK_PUB, "spk_sig": SIG}, headers=auth(token)
    )
    assert res.status_code == 429
    assert res.json() == {"error": "rate_limited"}


def test_upload_budget_is_per_account(client: TestClient) -> None:
    _, token_a = register_and_login(client)
    _, token_b = register_and_login(client)
    for _ in range(KEYS_UPLOAD_RATE_CAPACITY):
        assert _upload_spk(client, token_a) == 204
    assert _upload_spk(client, token_a) == 429
    # One account exhausting its budget must not spend another's.
    assert _upload_spk(client, token_b) == 204


def test_spk_and_opk_uploads_share_one_budget(client: TestClient) -> None:
    # Both endpoints append rows for the same account, so they draw on the same
    # bucket rather than each getting a full allowance.
    _, token = register_and_login(client)
    for _ in range(KEYS_UPLOAD_RATE_CAPACITY):
        assert _upload_spk(client, token) == 204
    res = client.post(
        "/v1/keys/opks", json={"opks": _opks(1), "root_sig": SIG}, headers=auth(token)
    )
    assert res.status_code == 429


def test_reads_are_not_rate_limited(client: TestClient) -> None:
    # /keys/status is a cheap read that writes nothing; only the writes are capped.
    _, token = register_and_login(client)
    for _ in range(KEYS_UPLOAD_RATE_CAPACITY + 5):
        assert client.get("/v1/keys/status", headers=auth(token)).status_code == 200
