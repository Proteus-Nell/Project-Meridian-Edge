from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app() -> FastAPI:
    # Fresh app per test: isolated in-memory DB and rate-limit buckets.
    return create_app("sqlite://")


@pytest.fixture()
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
