from __future__ import annotations

import re

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.constants import (
    ARGON2ID_ITERATIONS,
    ARGON2ID_MEM_KIB,
    ARGON2ID_PARALLELISM,
    CROCKFORD_ALPHABET,
    RECOVERY_CODE_COUNT,
)
from app.models import RecoveryCode
from app.security import (
    generate_recovery_codes,
    hash_recovery_code,
    normalize_recovery_code,
    verify_recovery_code,
)

from .helpers import Account, register


def test_recovery_codes_returned_once_at_registration(client: TestClient) -> None:
    account = Account()
    res = register(client, account)
    assert res.status_code == 201
    codes = res.json()["recovery_codes"]
    assert len(codes) == RECOVERY_CODE_COUNT
    for code in codes:
        assert re.fullmatch(r"([0-9A-Z]{4}-){3}[0-9A-Z]{4}", code)
        assert all(ch in CROCKFORD_ALPHABET for ch in code.replace("-", ""))


def test_recovery_codes_stored_only_as_argon2_hashes(client: TestClient, app: FastAPI) -> None:
    account = Account()
    register(client, account)
    with app.state.sessionmaker() as db:
        rows = db.execute(select(RecoveryCode)).scalars().all()
    assert len(rows) == RECOVERY_CODE_COUNT
    for row in rows:
        assert row.code_hash.startswith("$argon2id$")
        assert not row.used
        for code in account.recovery_codes:
            assert normalize_recovery_code(code) not in row.code_hash


def test_recovery_code_verify_round_trip() -> None:
    code = generate_recovery_codes()[0]
    hashed = hash_recovery_code(code)
    assert verify_recovery_code(hashed, code)
    assert verify_recovery_code(hashed, code.lower())  # normalization
    assert not verify_recovery_code(hashed, "AAAA-AAAA-AAAA-AAAA")
    assert not verify_recovery_code("not-a-hash", code)


def test_production_argon2_params_match_constants() -> None:
    # The autouse fixture swaps in weak params for speed; the section-0
    # constants the production hasher is built from must be unchanged.
    assert ARGON2ID_ITERATIONS == 3
    assert ARGON2ID_MEM_KIB == 65536
    assert ARGON2ID_PARALLELISM == 1
