"""Security-event logging (app/security_log.py) and its call sites.

Two things are asserted: that the module emits stable, privacy-minimal lines,
and that the real rejection paths actually reach it. The privacy contract is
load-bearing, so it is tested directly - no UID, token, nonce, or signature may
appear in any emitted line.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.constants import LOGIN_CHALLENGE_RATE_CAPACITY
from app.main import create_app
from app.security_log import record_security_event

from .conftest import FakeClock
from .helpers import Account, auth, register, register_and_login, sign_challenge

SECURITY_LOGGER = "meridian_edge.security"


def test_emits_a_stable_key_value_line(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        record_security_event(
            "rate_limit_exceeded", endpoint="/v1/register", client_ip="203.0.113.7"
        )
    assert (
        "security_event=rate_limit_exceeded endpoint=/v1/register client_ip=203.0.113.7"
        in caplog.text
    )


def test_signature_failure_is_error_level_for_alerting(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        record_security_event("signature_verification_failed", endpoint="/v1/login/verify")
    record = next(r for r in caplog.records if r.name == SECURITY_LOGGER)
    assert record.levelno == logging.ERROR


def test_optional_fields_are_omitted_when_absent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        record_security_event("origin_rejected", endpoint="/v1/ws")
    line = caplog.text
    assert "endpoint=/v1/ws" in line
    assert "client_ip=" not in line
    assert "reason=" not in line


def test_rate_limit_trip_is_logged_without_the_uid(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    account = Account()
    register(client, account)
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        for _ in range(LOGIN_CHALLENGE_RATE_CAPACITY + 1):
            client.post("/v1/login/challenge", json={"uid": account.uid})
    assert "security_event=rate_limit_exceeded" in caplog.text
    assert "endpoint=/v1/login/challenge" in caplog.text
    # The privacy contract: the account identifier never reaches the log.
    assert account.uid not in caplog.text


def test_bad_signature_is_logged_as_the_attack_signal(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    account = Account()
    intruder = Account()  # real UID, wrong identity key
    register(client, account)
    challenge = client.post("/v1/login/challenge", json={"uid": account.uid}).json()
    bad_sig = sign_challenge(intruder, challenge["nonce"], "", challenge["timestamp"])
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        res = client.post(
            "/v1/login/verify",
            json={"uid": account.uid, "nonce": challenge["nonce"], "signature": bad_sig},
        )
    assert res.status_code == 401
    assert "security_event=signature_verification_failed" in caplog.text
    assert account.uid not in caplog.text


def test_origin_rejection_is_logged(caplog: pytest.LogCaptureFixture, clock: FakeClock) -> None:
    app = create_app("sqlite://", clock=clock, allowed_origins=["https://served.example"])
    with TestClient(app) as restricted:
        account = Account()
        register(restricted, account)
        with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
            res = restricted.post(
                "/v1/login/challenge",
                json={"uid": account.uid},
                headers={"origin": "https://evil.example"},
            )
        assert res.status_code == 403
        assert "security_event=origin_rejected" in caplog.text


def test_invalid_token_is_logged_but_a_missing_header_is_not(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        # A bearer token that does not resolve: recorded.
        client.get("/v1/keys/status", headers=auth("f" * 64))
    assert "security_event=auth_failure" in caplog.text
    assert "reason=invalid_token" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        # No Authorization header at all: ordinary unauthenticated traffic, silent.
        client.get("/v1/keys/status")
    assert "security_event" not in caplog.text


def test_successful_login_logs_nothing(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=SECURITY_LOGGER):
        register_and_login(client)
    assert "security_event" not in caplog.text
