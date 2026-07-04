from __future__ import annotations

import base64
import binascii

from pydantic import BaseModel, ConfigDict, field_validator

from .constants import (
    ML_DSA_65_PUBKEY_BYTES,
    ML_DSA_65_SIG_BYTES,
    ML_KEM_768_PUBKEY_BYTES,
    NONCE_BYTES,
    OPK_BATCH_MAX,
)
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
