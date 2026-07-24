"""Production boot-safety gate (checklist: "DEBUG=0 asserted at
startup (refuse to boot otherwise in prod mode)").

_assert_production_safe is a no-op unless MERIDIAN_EDGE_ENV=production is set, so
these tests exercise it directly rather than through the app/client fixtures
(which never set that env var and must stay unaffected).
"""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from app import security
from app.constants import ARGON2ID_ITERATIONS, ARGON2ID_MEM_KIB, ARGON2ID_PARALLELISM
from app.main import _assert_production_safe, create_app


@pytest.fixture()
def real_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    # The session-wide fast_argon2 autouse fixture (conftest.py) swaps in weak
    # params for test speed; restore the real ones for the "everything is
    # correctly configured" case so it isn't accidentally the thing that fails.
    monkeypatch.setattr(
        security,
        "_hasher",
        PasswordHasher(
            time_cost=ARGON2ID_ITERATIONS,
            memory_cost=ARGON2ID_MEM_KIB,
            parallelism=ARGON2ID_PARALLELISM,
        ),
    )


def test_passes_with_a_fully_production_shaped_config(real_hasher: None) -> None:
    _assert_production_safe(
        dev=False,
        allowed_origins=["https://meridian-edge.example"],
        database_url="postgresql://user:pass@db/meridian_edge",
    )


def test_noop_when_prod_env_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MERIDIAN_EDGE_ENV", raising=False)
    # Every input here is dev-shaped; if the gate ran, it would raise.
    _assert_production_safe(dev=True, allowed_origins=None, database_url="sqlite://")


def test_refuses_when_dev_docs_enabled(monkeypatch: pytest.MonkeyPatch, real_hasher: None) -> None:
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    with pytest.raises(RuntimeError, match="MERIDIAN_EDGE_DEV"):
        _assert_production_safe(
            dev=True,
            allowed_origins=["https://meridian-edge.example"],
            database_url="postgresql://user:pass@db/meridian_edge",
        )


def test_refuses_when_origin_allowlist_unset(
    monkeypatch: pytest.MonkeyPatch, real_hasher: None
) -> None:
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    with pytest.raises(RuntimeError, match="MERIDIAN_EDGE_ALLOWED_ORIGINS"):
        _assert_production_safe(
            dev=False, allowed_origins=None, database_url="postgresql://user:pass@db/meridian_edge"
        )


def test_legacy_ws_origins_env_var_still_configures_the_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Deployments predating the login allowlist set MERIDIAN_EDGE_WS_ORIGINS;
    # they must keep working without an env-var rename.
    monkeypatch.delenv("MERIDIAN_EDGE_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("MERIDIAN_EDGE_WS_ORIGINS", "https://legacy.example")
    app = create_app("sqlite://")
    assert app.state.allowed_origins == ["https://legacy.example"]


def test_allowed_origins_env_var_takes_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MERIDIAN_EDGE_ALLOWED_ORIGINS", "https://new.example")
    monkeypatch.setenv("MERIDIAN_EDGE_WS_ORIGINS", "https://legacy.example")
    app = create_app("sqlite://")
    assert app.state.allowed_origins == ["https://new.example"]


def test_refuses_a_wildcard_forwarded_allow_ips(
    monkeypatch: pytest.MonkeyPatch, real_hasher: None
) -> None:
    # "*" trusts every peer to set X-Forwarded-For, so any client could name its
    # own address and walk past the per-IP limits.
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    with pytest.raises(RuntimeError, match="FORWARDED_ALLOW_IPS"):
        _assert_production_safe(
            dev=False,
            allowed_origins=["https://meridian-edge.example"],
            database_url="postgresql://user:pass@db/meridian_edge",
        )


def test_accepts_a_named_proxy_network(
    monkeypatch: pytest.MonkeyPatch, real_hasher: None
) -> None:
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "172.16.0.0/12")
    _assert_production_safe(
        dev=False,
        allowed_origins=["https://meridian-edge.example"],
        database_url="postgresql://user:pass@db/meridian_edge",
    )


def test_refuses_when_database_is_sqlite(
    monkeypatch: pytest.MonkeyPatch, real_hasher: None
) -> None:
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    with pytest.raises(RuntimeError, match="SQLite"):
        _assert_production_safe(
            dev=False, allowed_origins=["https://meridian-edge.example"], database_url="sqlite:///./x.db"
        )


def test_refuses_when_argon2_params_are_weak(monkeypatch: pytest.MonkeyPatch) -> None:
    # No real_hasher fixture here - the session-wide weak params from
    # fast_argon2 are exactly what should trip this branch.
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    with pytest.raises(RuntimeError, match="Argon2id"):
        _assert_production_safe(
            dev=False,
            allowed_origins=["https://meridian-edge.example"],
            database_url="postgresql://user:pass@db/meridian_edge",
        )


def test_create_app_refuses_to_boot_in_production_with_dev_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MERIDIAN_EDGE_ENV", "production")
    with pytest.raises(RuntimeError):
        create_app("sqlite://")
