from __future__ import annotations

from collections.abc import Iterator

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import security
from app.main import create_app


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def app(clock: FakeClock) -> FastAPI:
    # Fresh app per test: isolated in-memory DB, rate limiters, and clock.
    return create_app("sqlite://", clock=clock)


@pytest.fixture()
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch: pytest.MonkeyPatch) -> None:
    # Production parameters (m=64 MiB, t=3) are expensive by design and would
    # dominate the runtime of every test that registers a user;
    monkeypatch.setattr(
        security,
        "_hasher",
        PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
    )
