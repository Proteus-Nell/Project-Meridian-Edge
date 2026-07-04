from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app import uid as uid_module
from app.constants import CROCKFORD_ALPHABET, ML_DSA_65_PUBKEY_BYTES

VALID_KEY = base64.b64encode(bytes(ML_DSA_65_PUBKEY_BYTES)).decode()


def register(client: TestClient, key: str = VALID_KEY) -> Response:
    return client.post("/v1/register", json={"ik_pub": key})


def test_register_returns_formatted_uid(client: TestClient) -> None:
    res = register(client)
    assert res.status_code == 201
    uid = res.json()["uid"]
    assert [len(part) for part in uid.split("-")] == [4, 4, 4, 4, 4, 4, 2]
    assert all(ch in CROCKFORD_ALPHABET for ch in uid.replace("-", ""))


def test_register_uids_are_unique(client: TestClient) -> None:
    first = register(client).json()["uid"]
    second = register(client).json()["uid"]
    assert first != second


def test_invalid_base64_gets_uniform_error(client: TestClient) -> None:
    res = register(client, key="!!!not-base64!!!")
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request"}


def test_wrong_key_length_rejected(client: TestClient) -> None:
    res = register(client, key=base64.b64encode(bytes(100)).decode())
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request"}


def test_missing_field_rejected_with_same_shape(client: TestClient) -> None:
    res = client.post("/v1/register", json={})
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request"}


def test_extra_fields_rejected(client: TestClient) -> None:
    res = client.post("/v1/register", json={"ik_pub": VALID_KEY, "admin": True})
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request"}


def test_uid_collision_regenerates_silently(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_generate = uid_module.generate_uid
    fixed = real_generate()
    calls = {"count": 0}

    def collide_once() -> str:
        calls["count"] += 1
        # Calls 1 and 2 return the same UID: the first register consumes it,
        # the second register collides and must retry (call 3+).
        return fixed if calls["count"] <= 2 else real_generate()

    monkeypatch.setattr(uid_module, "generate_uid", collide_once)

    first = register(client)
    second = register(client)
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["uid"] != second.json()["uid"]
    assert calls["count"] >= 3
