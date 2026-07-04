"""Server-authoritative UID generation (CLAUDE.md section 2.1).

128 CSPRNG bits encoded as 26 canonical Crockford Base32 characters. The
canonical (dash-free, uppercase) form is what gets stored; formatting is
display-only.
"""

from __future__ import annotations

import secrets

from .constants import CROCKFORD_ALPHABET, UID_BYTES, UID_CHARS


def generate_uid() -> str:
    return encode_crockford(secrets.token_bytes(UID_BYTES))


def encode_crockford(raw: bytes) -> str:
    if len(raw) != UID_BYTES:
        raise ValueError(f"expected {UID_BYTES} bytes")
    value = int.from_bytes(raw, "big")
    chars: list[str] = []
    for _ in range(UID_CHARS):
        chars.append(CROCKFORD_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def format_uid(uid: str) -> str:
    """Group for display: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX."""
    return "-".join(uid[i : i + 4] for i in range(0, len(uid), 4))
