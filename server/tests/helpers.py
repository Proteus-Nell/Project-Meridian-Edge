"""Test-side client: a real ML-DSA-65 keypair driving the login protocol."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from fastapi.testclient import TestClient
from httpx import Response


class Account:
    def __init__(self) -> None:
        self.key = MLDSA65PrivateKey.generate()
        self.ik_pub = self.key.public_key().public_bytes_raw()
        self.uid_display = ""
        self.recovery_codes: list[str] = []

    @property
    def uid(self) -> str:
        return self.uid_display.replace("-", "")


def register(client: TestClient, account: Account) -> Response:
    res = client.post(
        "/v1/register",
        json={"ik_pub": base64.b64encode(account.ik_pub).decode()},
    )
    if res.status_code == 201:
        body = res.json()
        account.uid_display = body["uid"]
        account.recovery_codes = body["recovery_codes"]
    return res


def login_message(nonce_hex: str, origin: str, timestamp: int) -> bytes:
    return bytes.fromhex(nonce_hex) + origin.encode("utf-8") + timestamp.to_bytes(8, "big")


def sign_challenge(account: Account, nonce_hex: str, origin: str, timestamp: int) -> str:
    sig = account.key.sign(login_message(nonce_hex, origin, timestamp))
    return base64.b64encode(sig).decode()


def login(client: TestClient, account: Account, origin: str | None = None) -> str:
    headers = {"origin": origin} if origin is not None else {}
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}, headers=headers)
    assert challenge.status_code == 200, challenge.text
    body = challenge.json()
    signature = sign_challenge(account, body["nonce"], origin or "", body["timestamp"])
    verified = client.post(
        "/v1/login/verify",
        json={"uid": account.uid, "nonce": body["nonce"], "signature": signature},
        headers=headers,
    )
    assert verified.status_code == 200, verified.text
    token: str = verified.json()["token"]
    return token


def auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def register_and_login(client: TestClient, origin: str | None = None) -> tuple[Account, str]:
    account = Account()
    assert register(client, account).status_code == 201
    return account, login(client, account, origin)
