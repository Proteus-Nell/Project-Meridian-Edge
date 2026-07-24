"""Login challenge-response (CLAUDE.md section 2.3).

A challenge is issued for ANY well-formed UID - existing or not - so the
endpoint is useless as an existence oracle. All verification failures
(unknown UID, expired/replayed nonce, origin mismatch, bad signature)
return the identical uniform 401, with verification time burned on the
not-found path.

Two distinct origin controls apply, and they do different jobs:

  1. Binding. The origin is recorded with the nonce and signed by the client,
     so a signature produced for one origin cannot be replayed against another.
     This is enforced regardless of configuration.
  2. Allowlist. When app.state.allowed_origins is set (shared with the
     WebSocket upgrade), challenges are only issued to, and only accepted
     from, an approved origin. Unset leaves it open for local development.

The allowlist constrains browsers only - a direct HTTP client can send any
Origin header - so it is defence in depth against a hostile page, not an
authentication control. The ML-DSA signature is what actually authenticates.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import AuthContext, require_auth
from ..constants import NONCE_BYTES, NONCE_TTL_SECONDS
from ..deps import get_session
from ..models import LoginNonce, SessionToken, User
from ..pqc import burn_verification_time, verify_mldsa65
from ..rate_limit import TokenBucketLimiter
from ..schemas import ChallengeRequest, ChallengeResponse, TokenResponse, VerifyRequest
from ..security import hash_token, new_session_token
from ..security_log import record_security_event

router = APIRouter(prefix="/v1")


def _client_key(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"


def _origin(request: Request) -> str:
    return request.headers.get("origin", "")


def _require_allowed_origin(request: Request) -> None:
    """Reject the request unless its Origin is on the configured allowlist.

    None means unconfigured, which leaves the check open so local development
    and the test suite work without ceremony; production is required to set it
    (asserted at boot by _assert_production_safe).
    """
    allowed: list[str] | None = request.app.state.allowed_origins
    if allowed is not None and _origin(request) not in allowed:
        record_security_event(
            "origin_rejected", endpoint=request.url.path, client_ip=_client_key(request)
        )
        raise HTTPException(status_code=403, detail="forbidden_origin")


def login_message(nonce: bytes, origin: str, timestamp: int) -> bytes:
    """The exact bytes the client signs: nonce || origin || ts_be8."""
    return nonce + origin.encode("utf-8") + timestamp.to_bytes(8, "big")


@router.post("/login/challenge")
def challenge(
    payload: ChallengeRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> ChallengeResponse:
    # Cheapest rejection first: a disallowed origin never reaches the rate
    # limiter (so it cannot burn a legitimate client's budget) and never
    # writes a nonce row.
    _require_allowed_origin(request)
    limiter: TokenBucketLimiter = request.app.state.login_challenge_limiter
    if not limiter.allow(_client_key(request)):
        record_security_event(
            "rate_limit_exceeded", endpoint=request.url.path, client_ip=_client_key(request)
        )
        raise HTTPException(status_code=429, detail="rate_limited")

    now: float = request.app.state.clock()
    origin = _origin(request)
    nonce = secrets.token_bytes(NONCE_BYTES).hex()
    session.add(
        LoginNonce(
            nonce=nonce,
            uid=payload.uid,
            origin=origin,
            timestamp=int(now),
            issued_at=now,
        )
    )
    session.commit()
    return ChallengeResponse(nonce=nonce, timestamp=int(now), origin=origin)


@router.post("/login/verify")
def verify(
    payload: VerifyRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    # Checked here too, not just at /challenge: a nonce obtained elsewhere must
    # not be redeemable from an origin the deployment does not serve.
    _require_allowed_origin(request)
    now: float = request.app.state.clock()
    origin = _origin(request)
    signature = payload.decoded_signature()

    row = session.execute(
        select(LoginNonce).where(LoginNonce.nonce == payload.nonce)
    ).scalar_one_or_none()

    nonce_ok = (
        row is not None
        and not row.consumed
        and now - row.issued_at <= NONCE_TTL_SECONDS
        and row.uid == payload.uid
        and row.origin == origin
    )
    if row is not None and not row.consumed:
        # Single-use regardless of outcome: a failed attempt burns the nonce.
        row.consumed = True
        session.commit()

    user = session.execute(
        select(User).where(User.uid == payload.uid)
    ).scalar_one_or_none()

    if row is None or not nonce_ok or user is None:
        burn_verification_time(signature, login_message(bytes(NONCE_BYTES), origin, 0))
        # Unknown UID and bad nonce are indistinguishable to the caller and are
        # logged the same coarse way: a missing/expired/replayed credential.
        record_security_event(
            "auth_failure",
            endpoint=request.url.path,
            client_ip=_client_key(request),
            reason="invalid_nonce_or_uid",
        )
        raise HTTPException(status_code=401, detail="auth_failed")

    message = login_message(bytes.fromhex(row.nonce), origin, row.timestamp)
    if not verify_mldsa65(user.ik_pub, signature, message):
        # A valid nonce for a real UID but a signature that does not verify: the
        # attack-signal case (someone signing with the wrong identity key).
        record_security_event(
            "signature_verification_failed",
            endpoint=request.url.path,
            client_ip=_client_key(request),
        )
        raise HTTPException(status_code=401, detail="auth_failed")

    token = new_session_token()
    session.add(SessionToken(token_hash=hash_token(token), user_id=user.id, last_used=now))
    session.commit()
    return TokenResponse(token=token)


@router.post("/logout", status_code=204)
def logout(
    session: Annotated[Session, Depends(get_session)],
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    ctx.session_token.revoked = True
    session.commit()
