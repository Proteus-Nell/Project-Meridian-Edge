from __future__ import annotations

import pytest

from app.constants import CROCKFORD_ALPHABET, UID_CHARS
from app.uid import encode_crockford, format_uid, generate_uid


def test_encode_zero_bytes() -> None:
    assert encode_crockford(bytes(16)) == "0" * UID_CHARS


def test_encode_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        encode_crockford(bytes(15))


def test_generated_uid_is_canonical() -> None:
    uid = generate_uid()
    assert len(uid) == UID_CHARS
    assert all(ch in CROCKFORD_ALPHABET for ch in uid)


def test_generated_uids_differ() -> None:
    assert len({generate_uid() for _ in range(64)}) == 64


def test_format_groups_4_4_4_4_4_4_2() -> None:
    uid = "7Q3KM2VD9XWP4RTBA6HJEZ0123"
    formatted = format_uid(uid)
    assert formatted == "7Q3K-M2VD-9XWP-4RTB-A6HJ-EZ01-23"
    assert formatted.replace("-", "") == uid


def test_encode_is_deterministic_and_ordered() -> None:
    raw = bytes(range(16))
    assert encode_crockford(raw) == encode_crockford(raw)
    assert encode_crockford(bytes(15) + b"\x01") == "0" * (UID_CHARS - 1) + "1"
