"""Account deletion (routes/account.py).

The endpoint the client's duress passphrase calls. What matters here is that it
leaves nothing behind, that a deleted UID is indistinguishable from one that
never existed, and that it cannot reach anyone else's data.
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    LoginNonce,
    OneTimePrekey,
    OpkBatch,
    QueuedMessage,
    RecoveryCode,
    SessionToken,
    SignedPrekey,
    User,
)

from .helpers import Account, auth, login, register, register_and_login, sign_challenge

# Key material is opaque to the server (it verifies no signature on upload), so
# the shapes below only have to be the right length - same as test_keys.py.
SPK_PUB = base64.b64encode(bytes(1184)).decode()
SIG = base64.b64encode(bytes(3309)).decode()
OPK_COUNT = 4


def _publish_bundle(client: TestClient, token: str) -> None:
    """Give an account its full server-side footprint: an SPK and an OPK batch."""
    opks = [base64.b64encode(bytes([i]) + bytes(1183)).decode() for i in range(OPK_COUNT)]
    assert (
        client.post(
            "/v1/keys/spk", json={"spk_pub": SPK_PUB, "spk_sig": SIG}, headers=auth(token)
        ).status_code
        == 204
    )
    assert (
        client.post(
            "/v1/keys/opks", json={"opks": opks, "root_sig": SIG}, headers=auth(token)
        ).status_code
        == 204
    )


def _count(app: FastAPI, model: Any, column: Any, value: object) -> int:
    session: Session = app.state.sessionmaker()
    try:
        return int(
            session.execute(
                select(func.count()).select_from(model).where(column == value)
            ).scalar_one()
        )
    finally:
        session.close()


def _user_id(app: FastAPI, uid: str) -> int:
    session: Session = app.state.sessionmaker()
    try:
        return int(session.execute(select(User.id).where(User.uid == uid)).scalar_one())
    finally:
        session.close()


def _send(client: TestClient, token: str, recipient_uid: str) -> int:
    res = client.post(
        "/v1/messages",
        json={
            "recipient_uid": recipient_uid,
            "envelope": base64.b64encode(b"opaque").decode(),
        },
        headers=auth(token),
    )
    return res.status_code


def test_requires_auth(client: TestClient) -> None:
    assert client.post("/v1/account/delete").status_code == 401


def test_deletes_the_account_row(client: TestClient, app: FastAPI) -> None:
    account, token = register_and_login(client)
    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204
    assert _count(app, User, User.uid, account.uid) == 0


def test_removes_every_artifact_bound_to_the_account(client: TestClient, app: FastAPI) -> None:
    account, token = register_and_login(client)
    _publish_bundle(client, token)
    user_id = _user_id(app, account.uid)

    sender, sender_token = register_and_login(client)
    assert _send(client, sender_token, account.uid) == 204

    # Everything is really there before the delete, so the assertions after it
    # are testing removal rather than absence.
    assert _count(app, SignedPrekey, SignedPrekey.user_id, user_id) == 1
    assert _count(app, OpkBatch, OpkBatch.user_id, user_id) == 1
    assert _count(app, OneTimePrekey, OneTimePrekey.user_id, user_id) == OPK_COUNT
    assert _count(app, QueuedMessage, QueuedMessage.recipient_user_id, user_id) == 1
    assert _count(app, RecoveryCode, RecoveryCode.user_id, user_id) > 0
    assert _count(app, LoginNonce, LoginNonce.uid, account.uid) > 0

    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204

    assert _count(app, SignedPrekey, SignedPrekey.user_id, user_id) == 0
    assert _count(app, OpkBatch, OpkBatch.user_id, user_id) == 0
    assert _count(app, OneTimePrekey, OneTimePrekey.user_id, user_id) == 0
    assert _count(app, QueuedMessage, QueuedMessage.recipient_user_id, user_id) == 0
    assert _count(app, RecoveryCode, RecoveryCode.user_id, user_id) == 0
    assert _count(app, SessionToken, SessionToken.user_id, user_id) == 0
    assert _count(app, LoginNonce, LoginNonce.uid, account.uid) == 0

    # The sender is untouched: deletion reaches only the caller's own rows.
    assert _count(app, User, User.uid, sender.uid) == 1


def test_leaves_messages_this_account_sent_in_their_recipients_queues(
    client: TestClient, app: FastAPI
) -> None:
    """An honest limitation, asserted so it stays a known one: the queue rows
    belong to the recipients, and reaching into them is not a capability this
    server grants. Two-sided deletion is the client's /delete, over the ratchet."""
    peer, _ = register_and_login(client)
    _, token = register_and_login(client)
    assert _send(client, token, peer.uid) == 204
    peer_id = _user_id(app, peer.uid)

    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204
    assert _count(app, QueuedMessage, QueuedMessage.recipient_user_id, peer_id) == 1


def test_revokes_the_calling_session(client: TestClient) -> None:
    _, token = register_and_login(client)
    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204
    assert client.get("/v1/sessions", headers=auth(token)).status_code == 401


def test_signs_out_every_other_device_too(client: TestClient) -> None:
    account = Account()
    register(client, account)
    first = login(client, account)
    second = login(client, account)
    assert client.post("/v1/account/delete", headers=auth(first)).status_code == 204
    assert client.get("/v1/sessions", headers=auth(second)).status_code == 401


def test_recovery_codes_no_longer_work(client: TestClient) -> None:
    account, token = register_and_login(client)
    code = account.recovery_codes[0]
    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204
    replacement = Account()
    res = client.post(
        "/v1/recover",
        json={
            "uid": account.uid,
            "code": code,
            "ik_pub": base64.b64encode(replacement.ik_pub).decode(),
        },
    )
    assert res.status_code == 401


def test_the_identity_key_is_forgotten_so_login_fails(client: TestClient) -> None:
    account, token = register_and_login(client)
    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204
    # A challenge is still issued for any UID (anti-enumeration), but nothing is
    # left to verify the signature against.
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid})
    assert challenge.status_code == 200
    body = challenge.json()
    verified = client.post(
        "/v1/login/verify",
        json={
            "uid": account.uid,
            "nonce": body["nonce"],
            "signature": sign_challenge(account, body["nonce"], "", body["timestamp"]),
        },
    )
    assert verified.status_code == 401


def test_a_deleted_uid_looks_like_one_that_never_existed(client: TestClient) -> None:
    account, token = register_and_login(client)
    _publish_bundle(client, token)
    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204

    _, peer_token = register_and_login(client)
    deleted = client.get(f"/v1/bundles/{account.uid}", headers=auth(peer_token))
    never_existed = client.get(f"/v1/bundles/{'A' * 26}", headers=auth(peer_token))
    assert deleted.status_code == never_existed.status_code == 404
    assert deleted.json() == never_existed.json()


def test_messages_to_a_deleted_account_are_accepted_and_dropped(
    client: TestClient, app: FastAPI
) -> None:
    """Sending is accept-and-drop for any unknown recipient (routes/messages.py),
    so a deleted UID answers exactly as a UID that never existed: 204, nothing
    queued. The sender learns nothing from the response either way."""
    account, token = register_and_login(client)
    assert client.post("/v1/account/delete", headers=auth(token)).status_code == 204

    _, peer_token = register_and_login(client)
    deleted = _send(client, peer_token, account.uid)
    never_existed = _send(client, peer_token, "A" * 26)
    assert deleted == never_existed == 204

    session: Session = app.state.sessionmaker()
    try:
        assert session.execute(select(func.count()).select_from(QueuedMessage)).scalar_one() == 0
    finally:
        session.close()
