from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.constants import ML_DSA_65_PUBKEY_BYTES, REGISTER_RATE_CAPACITY
from app.rate_limit import TokenBucketLimiter

VALID_KEY = base64.b64encode(bytes(ML_DSA_65_PUBKEY_BYTES)).decode()


def test_register_rate_limited_after_capacity(client: TestClient) -> None:
    for _ in range(REGISTER_RATE_CAPACITY):
        res = client.post("/v1/register", json={"ik_pub": VALID_KEY})
        assert res.status_code == 201
    res = client.post("/v1/register", json={"ik_pub": VALID_KEY})
    assert res.status_code == 429
    assert res.json() == {"error": "rate_limited"}


def test_bucket_refills_over_time() -> None:
    now = {"t": 0.0}
    limiter = TokenBucketLimiter(capacity=3, window_seconds=3600.0, clock=lambda: now["t"])
    for _ in range(3):
        assert limiter.allow("ip")
    assert not limiter.allow("ip")
    now["t"] += 1200.0  # one token refilled at 3/hour
    assert limiter.allow("ip")
    assert not limiter.allow("ip")


def test_buckets_are_per_key() -> None:
    limiter = TokenBucketLimiter(capacity=1, window_seconds=3600.0, clock=lambda: 0.0)
    assert limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")
