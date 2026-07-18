from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.constants import BUNDLE_FETCH_RATE_CAPACITY

from .helpers import auth, register_and_login

SIG = base64.b64encode(bytes(3309)).decode()
GHOST_UID = "7Q3KM2VD9XWP4RTBA6HJEZ0123"


def upload_prekeys(client: TestClient, token: str, opk_count: int) -> None:
    spk = base64.b64encode(bytes(1184)).decode()
    assert (
        client.post(
            "/v1/keys/spk", json={"spk_pub": spk, "spk_sig": SIG}, headers=auth(token)
        ).status_code
        == 204
    )
    if opk_count > 0:
        opks = [
            base64.b64encode(bytes([i]) + bytes(1183)).decode() for i in range(opk_count)
        ]
        assert (
            client.post(
                "/v1/keys/opks", json={"opks": opks, "root_sig": SIG}, headers=auth(token)
            ).status_code
            == 204
        )


def test_bundle_requires_auth(client: TestClient) -> None:
    assert client.get(f"/v1/bundles/{GHOST_UID}").status_code == 401


def test_unknown_uid_and_missing_prekeys_are_uniform(client: TestClient) -> None:
    _, token = register_and_login(client)
    ghost = client.get(f"/v1/bundles/{GHOST_UID}", headers=auth(token))
    assert ghost.status_code == 404
    assert ghost.json() == {"error": "request_failed"}

    # A real user who has uploaded no prekeys yet looks identical.
    bob, _ = register_and_login(client)
    real = client.get(f"/v1/bundles/{bob.uid}", headers=auth(token))
    assert real.status_code == 404
    assert real.json() == ghost.json()


def test_malformed_uid_rejected(client: TestClient) -> None:
    _, token = register_and_login(client)
    res = client.get("/v1/bundles/not-a-uid", headers=auth(token))
    assert res.status_code == 400


def test_bundle_returns_keys_and_consumes_one_opk(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    upload_prekeys(client, token_b, opk_count=3)

    first = client.get(f"/v1/bundles/{bob.uid}", headers=auth(token_a)).json()
    assert base64.b64decode(first["ik_pub"]) == bob.ik_pub
    assert len(base64.b64decode(first["spk_pub"])) == 1184
    assert first["opk"] is not None
    assert len(first["opk"]["leaf_hashes"]) == 3

    second = client.get(f"/v1/bundles/{bob.uid}", headers=auth(token_a)).json()
    assert second["opk"]["index"] != first["opk"]["index"]

    status = client.get("/v1/keys/status", headers=auth(token_b)).json()
    assert status["opk_count"] == 1


def test_depletion_degrades_to_spk_only(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    upload_prekeys(client, token_b, opk_count=1)

    assert client.get(f"/v1/bundles/{bob.uid}", headers=auth(token_a)).json()["opk"] is not None
    depleted = client.get(f"/v1/bundles/{bob.uid}", headers=auth(token_a))
    assert depleted.status_code == 200
    assert depleted.json()["opk"] is None  # reduced-fs, not failure (§7.4)


def test_opk_query_flag_skips_consumption(client: TestClient) -> None:
    alice, token_a = register_and_login(client)
    bob, token_b = register_and_login(client)
    upload_prekeys(client, token_b, opk_count=2)

    res = client.get(f"/v1/bundles/{bob.uid}?opk=0", headers=auth(token_a)).json()
    assert res["opk"] is None
    status = client.get("/v1/keys/status", headers=auth(token_b)).json()
    assert status["opk_count"] == 2


def test_bundle_fetch_rate_limited_per_requester(client: TestClient) -> None:
    _, token = register_and_login(client)
    for _ in range(BUNDLE_FETCH_RATE_CAPACITY):
        assert client.get(f"/v1/bundles/{GHOST_UID}", headers=auth(token)).status_code == 404
    res = client.get(f"/v1/bundles/{GHOST_UID}", headers=auth(token))
    assert res.status_code == 429
    assert res.json() == {"error": "rate_limited"}
