"""Pydantic request and response models - the server's entire input surface.

Every byte a client sends crosses one of these models before a handler sees it,
and each sets extra="forbid" so an unexpected field is a rejection rather than
something quietly ignored. Base64 key material is decoded and length-checked
against the FIPS primitive sizes during validation (_decode_exact), so a
wrong-sized ML-KEM or ML-DSA key is refused at the edge and never reaches the
database or a signature check.

These models draw the boundary; they do not explain themselves to the caller. A
validation failure surfaces as the same uniform error as every other rejection,
so the shape of a malformed request leaks nothing back to whoever sent it.
"""

from __future__ import annotations

import base64
import binascii

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .constants import (
    ACK_MAX_IDS,
    ML_DSA_65_PUBKEY_BYTES,
    ML_DSA_65_SIG_BYTES,
    ML_KEM_768_PUBKEY_BYTES,
    NONCE_BYTES,
    OPK_BATCH_MAX,
)
from .security import canonicalize_recovery_code
from .uid import canonicalize_uid


def _decode_exact(value: str, expected_len: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("invalid encoding") from None
    if len(decoded) != expected_len:
        raise ValueError("invalid length")
    return decoded


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ik_pub: str

    @field_validator("ik_pub")
    @classmethod
    def _check_ik_pub(cls, value: str) -> str:
        _decode_exact(value, ML_DSA_65_PUBKEY_BYTES)
        return value

    def decoded_ik_pub(self) -> bytes:
        return base64.b64decode(self.ik_pub, validate=True)


class RegisterResponse(BaseModel):
    uid: str
    recovery_codes: list[str]


class _UidRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uid: str

    @field_validator("uid")
    @classmethod
    def _check_uid(cls, value: str) -> str:
        canonical = canonicalize_uid(value)
        if canonical is None:
            raise ValueError("invalid uid")
        return canonical


class ChallengeRequest(_UidRequest):
    pass


class ChallengeResponse(BaseModel):
    nonce: str  # hex
    timestamp: int  # unix seconds; client signs nonce || origin || ts_be8
    # Echo of the Origin the server bound this nonce to, so the client signs
    # exactly the bytes the server will verify. Verification still compares
    # this against the verify request's own Origin header - echoing it does
    # not let an attacker pick the binding.
    origin: str


class VerifyRequest(_UidRequest):
    nonce: str
    signature: str

    @field_validator("nonce")
    @classmethod
    def _check_nonce(cls, value: str) -> str:
        if len(value) != NONCE_BYTES * 2:
            raise ValueError("invalid nonce")
        try:
            bytes.fromhex(value)
        except ValueError:
            raise ValueError("invalid nonce") from None
        return value.lower()

    @field_validator("signature")
    @classmethod
    def _check_signature(cls, value: str) -> str:
        _decode_exact(value, ML_DSA_65_SIG_BYTES)
        return value

    def decoded_signature(self) -> bytes:
        return base64.b64decode(self.signature, validate=True)


class TokenResponse(BaseModel):
    token: str


class SessionInfo(BaseModel):
    """One live session, described only by relative timing (no device label or
    user agent is stored) plus a flag for the one making the request. Ages are
    server-computed seconds so the client needs no server clock and no absolute
    timestamp is exposed."""

    age_seconds: int  # since the session was created
    idle_seconds: int  # since it was last used
    current: bool


class SessionsResponse(BaseModel):
    sessions: list[SessionInfo]


class LogoutOthersResponse(BaseModel):
    revoked: int  # how many other sessions were signed out


class RecoverRequest(_UidRequest):
    """Redeem a recovery code and enroll a replacement identity key in one
    step: the code is the credential, so no challenge round-trip is needed."""

    code: str
    ik_pub: str

    @field_validator("code")
    @classmethod
    def _check_code(cls, value: str) -> str:
        canonical = canonicalize_recovery_code(value)
        if canonical is None:
            raise ValueError("invalid code")
        return canonical

    @field_validator("ik_pub")
    @classmethod
    def _check_ik_pub(cls, value: str) -> str:
        _decode_exact(value, ML_DSA_65_PUBKEY_BYTES)
        return value

    def decoded_ik_pub(self) -> bytes:
        return base64.b64decode(self.ik_pub, validate=True)


class RecoverResponse(BaseModel):
    uid: str
    # The full replacement set, shown once like at registration; every code
    # issued before the recovery is invalid from this response onward.
    recovery_codes: list[str]


class SpkUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spk_pub: str
    spk_sig: str

    @field_validator("spk_pub")
    @classmethod
    def _check_pub(cls, value: str) -> str:
        _decode_exact(value, ML_KEM_768_PUBKEY_BYTES)
        return value

    @field_validator("spk_sig")
    @classmethod
    def _check_sig(cls, value: str) -> str:
        _decode_exact(value, ML_DSA_65_SIG_BYTES)
        return value


class OpkUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    opks: list[str]
    root_sig: str

    @field_validator("opks")
    @classmethod
    def _check_opks(cls, value: list[str]) -> list[str]:
        if not 1 <= len(value) <= OPK_BATCH_MAX:
            raise ValueError("invalid batch size")
        for item in value:
            _decode_exact(item, ML_KEM_768_PUBKEY_BYTES)
        return value

    @field_validator("root_sig")
    @classmethod
    def _check_root_sig(cls, value: str) -> str:
        _decode_exact(value, ML_DSA_65_SIG_BYTES)
        return value


class KeysStatusResponse(BaseModel):
    spk_uploaded_at: float | None
    opk_count: int


class BundleOpk(BaseModel):
    pub: str  # base64 ML-KEM-768 encapsulation key
    index: int  # position within its batch
    leaf_hashes: list[str]  # base64 SHA-512 leaves; lets one OPK verify alone
    root_sig: str  # base64 ML-DSA-65 over the batch root


class BundleResponse(BaseModel):
    ik_pub: str
    spk_pub: str
    spk_sig: str
    opk: BundleOpk | None


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient_uid: str
    # Base64 KX envelope; opaque to the server. Length bounded here to cap
    # parse work, exact byte-size cap (64 KiB -> 413) enforced in the route.
    envelope: str = Field(max_length=90000)

    @field_validator("recipient_uid")
    @classmethod
    def _check_uid(cls, value: str) -> str:
        canonical = canonicalize_uid(value)
        if canonical is None:
            raise ValueError("invalid uid")
        return canonical

    @field_validator("envelope")
    @classmethod
    def _check_envelope(cls, value: str) -> str:
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("invalid encoding") from None
        return value

    def decoded_envelope(self) -> bytes:
        return base64.b64decode(self.envelope, validate=True)


class QueuedMessageOut(BaseModel):
    id: int
    envelope: str  # base64


class MessagesResponse(BaseModel):
    messages: list[QueuedMessageOut]


class AckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[int] = Field(min_length=1, max_length=ACK_MAX_IDS)
