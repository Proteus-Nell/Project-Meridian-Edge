from __future__ import annotations

import base64
import binascii

from pydantic import BaseModel, ConfigDict, field_validator

from .constants import ML_DSA_65_PUBKEY_BYTES


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ik_pub: str

    @field_validator("ik_pub")
    @classmethod
    def _check_ik_pub(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("invalid key encoding") from None
        if len(decoded) != ML_DSA_65_PUBKEY_BYTES:
            raise ValueError("invalid key length")
        return value

    def decoded_ik_pub(self) -> bytes:
        return base64.b64decode(self.ik_pub, validate=True)


class RegisterResponse(BaseModel):
    uid: str
