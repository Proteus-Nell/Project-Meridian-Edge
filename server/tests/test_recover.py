"""Recovery-code redemption.

Covers the identity takeover (new key in, old key dead), the scorched-earth
cleanup (prekeys, sessions, queue), full code-set reissue, anti-enumeration
uniformity, Crockford input tolerance, and the rate limit.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from fastapi.testclient import TestClient
from httpx import Response

from app.constants import (
    ML_DSA_65_SIG_BYTES,
    ML_KEM_768_PUBKEY_BYTES,
    RECOVERY_CODE_COUNT,
    RECOVER_RATE_CAPACITY,
)

from .helpers import Account, auth, login, register_and_login, sign_challenge


def recover(
    client: TestClient, account: Account, code: str, new_key: MLDSA65PrivateKey
) -> Response:
    res = client.post(
        "/v1/recover",
        json={
            "uid": account.uid,
            "code": code,
            "ik_pub": base64.b64encode(new_key.public_key().public_bytes_raw()).decode(),
        },
    )
    if res.status_code == 200:
        body = res.json()
        account.key = new_key
        account.ik_pub = new_key.public_key().public_bytes_raw()
        account.recovery_codes = body["recovery_codes"]
    return res


def upload_prekeys(client: TestClient, token: str) -> None:
    spk = base64.b64encode(b"\x01" * ML_KEM_768_PUBKEY_BYTES).decode()
    sig = base64.b64encode(b"\x02" * ML_DSA_65_SIG_BYTES).decode()
    assert (
        client.post(
            "/v1/keys/spk", json={"spk_pub": spk, "spk_sig": sig}, headers=auth(token)
        ).status_code
        == 204
    )
    opks = [base64.b64encode(bytes([i]) * ML_KEM_768_PUBKEY_BYTES).decode() for i in range(3)]
    assert (
        client.post(
            "/v1/keys/opks", json={"opks": opks, "root_sig": sig}, headers=auth(token)
        ).status_code
        == 204
    )


def test_recover_takes_over_identity_and_destroys_old_artifacts(client: TestClient) -> None:
    account, token = register_and_login(client)
    upload_prekeys(client, token)
    old_key = account.key
    old_codes = list(account.recovery_codes)

    # Queue a message for the account so the purge is observable.
    sender, sender_token = register_and_login(client)
    envelope = base64.b64encode(b"\xaa" * 64).decode()
    assert (
        client.post(
            "/v1/messages",
            json={"recipient_uid": account.uid, "envelope": envelope},
            headers=auth(sender_token),
        ).status_code
        == 204
    )

    res = recover(client, account, old_codes[0], MLDSA65PrivateKey.generate())
    assert res.status_code == 200
    body = res.json()
    assert body["uid"] == account.uid_display
    assert len(body["recovery_codes"]) == RECOVERY_CODE_COUNT
    assert len(set(body["recovery_codes"])) == RECOVERY_CODE_COUNT
    assert not set(body["recovery_codes"]) & set(old_codes)

    # The pre-recovery session is dead.
    assert client.get("/v1/keys/status", headers=auth(token)).status_code == 401

    # The old identity key can no longer complete the login handshake.
    old_account = Account()
    old_account.key = old_key
    old_account.uid_display = account.uid_display
    challenge = client.post("/v1/login/challenge", json={"uid": old_account.uid}).json()
    verified = client.post(
        "/v1/login/verify",
        json={
            "uid": old_account.uid,
            "nonce": challenge["nonce"],
            "signature": sign_challenge(
                old_account, challenge["nonce"], "", challenge["timestamp"]
            ),
        },
    )
    assert verified.status_code == 401

    # The new identity key logs in, and every old artifact is gone: no signed
    # prekey, no one-time prekeys, an empty queue.
    new_token = login(client, account)
    status = client.get("/v1/keys/status", headers=auth(new_token)).json()
    assert status["spk_uploaded_at"] is None
    assert status["opk_count"] == 0
    inbox = client.get("/v1/messages", headers=auth(new_token)).json()
    assert inbox["messages"] == []


def test_recover_reissues_the_full_set_and_burns_the_old_one(client: TestClient) -> None:
    account, _ = register_and_login(client)
    old_codes = list(account.recovery_codes)

    assert recover(client, account, old_codes[0], MLDSA65PrivateKey.generate()).status_code == 200
    fresh_codes = list(account.recovery_codes)

    # Every code from the old set is dead: the redeemed one and the unused rest.
    for stale in (old_codes[0], old_codes[1], old_codes[-1]):
        res = recover(client, account, stale, MLDSA65PrivateKey.generate())
        assert res.status_code == 401
        assert res.json() == {"error": "auth_failed"}

    # A code from the reissued set redeems.
    assert recover(client, account, fresh_codes[0], MLDSA65PrivateKey.generate()).status_code == 200


def test_recover_failures_are_uniform(client: TestClient) -> None:
    account, _ = register_and_login(client)
    new_key = MLDSA65PrivateKey.generate()

    wrong_code = recover(client, account, "7777-7777-7777-7777", new_key)
    unknown = Account()
    unknown.uid_display = "0000-0000-0000-0000-0000-0000-00"
    unknown_uid = recover(client, unknown, "7777-7777-7777-7777", new_key)

    # Wrong code and unknown UID are indistinguishable: same status, same body.
    assert wrong_code.status_code == unknown_uid.status_code == 401
    assert wrong_code.json() == unknown_uid.json() == {"error": "auth_failed"}


def test_recover_tolerates_crockford_input_variants(client: TestClient) -> None:
    account, _ = register_and_login(client)
    # Lowercase, O for 0, and stripped dashes must all canonicalize back.
    mangled = account.recovery_codes[0].lower().replace("0", "o").replace("-", "")
    assert recover(client, account, mangled, MLDSA65PrivateKey.generate()).status_code == 200


def test_recover_rejects_malformed_input(client: TestClient) -> None:
    account, _ = register_and_login(client)
    ik = base64.b64encode(MLDSA65PrivateKey.generate().public_key().public_bytes_raw()).decode()

    too_short = client.post(
        "/v1/recover", json={"uid": account.uid, "code": "ABCD", "ik_pub": ik}
    )
    assert too_short.status_code == 400
    assert too_short.json() == {"error": "invalid_request"}

    bad_key = client.post(
        "/v1/recover",
        json={
            "uid": account.uid,
            "code": account.recovery_codes[0],
            "ik_pub": base64.b64encode(b"\x00" * 10).decode(),
        },
    )
    assert bad_key.status_code == 400

    # The malformed attempts must not have consumed anything: the code and the
    # original identity both still work.
    assert login(client, account) != ""
    assert recover(client, account, account.recovery_codes[0], MLDSA65PrivateKey.generate()).status_code == 200


def test_recover_rate_limited_per_ip(client: TestClient) -> None:
    account, _ = register_and_login(client)
    new_key = MLDSA65PrivateKey.generate()
    for _ in range(RECOVER_RATE_CAPACITY):
        res = recover(client, account, "7777-7777-7777-7777", new_key)
        assert res.status_code == 401
    res = recover(client, account, "7777-7777-7777-7777", new_key)
    assert res.status_code == 429
    assert res.json() == {"error": "rate_limited"}
