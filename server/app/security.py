"""Tokens and recovery codes (CLAUDE.md sections 2.2, 2.3, 7.7).

Session tokens are stored only as SHA-512 digests; recovery codes only as
Argon2id hashes. Nothing in this module persists a secret in plaintext.
"""

from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .constants import (
    ARGON2ID_ITERATIONS,
    ARGON2ID_MEM_KIB,
    ARGON2ID_PARALLELISM,
    CROCKFORD_ALPHABET,
    RECOVERY_CODE_BYTES,
    RECOVERY_CODE_COUNT,
    SESSION_TOKEN_BYTES,
)

# Module-level so tests can substitute weaker parameters; production params
# come from the shared constants (section 0).
_hasher = PasswordHasher(
    time_cost=ARGON2ID_ITERATIONS,
    memory_cost=ARGON2ID_MEM_KIB,
    parallelism=ARGON2ID_PARALLELISM,
)


def new_session_token() -> str:
    return secrets.token_hex(SESSION_TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha512(token.encode("ascii", errors="replace")).hexdigest()


def _encode_code(raw: bytes) -> str:
    value = int.from_bytes(raw, "big")
    chars: list[str] = []
    for _ in range(RECOVERY_CODE_BYTES * 8 // 5):
        chars.append(CROCKFORD_ALPHABET[value & 0x1F])
        value >>= 5
    code = "".join(reversed(chars))
    return "-".join(code[i : i + 4] for i in range(0, len(code), 4))


def generate_recovery_codes() -> list[str]:
    return [
        _encode_code(secrets.token_bytes(RECOVERY_CODE_BYTES))
        for _ in range(RECOVERY_CODE_COUNT)
    ]


def normalize_recovery_code(code: str) -> str:
    return code.upper().replace("-", "")


def hash_recovery_code(code: str) -> str:
    return _hasher.hash(normalize_recovery_code(code))


def verify_recovery_code(code_hash: str, code: str) -> bool:
    try:
        return _hasher.verify(code_hash, normalize_recovery_code(code))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
