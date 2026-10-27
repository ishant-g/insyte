"""Shared pytest fixtures.

The test suite runs against SQLite in-memory by default — see
`database/base.py` for the JSONB/UUID variant handling that makes the same
models work on both SQLite and PostgreSQL. Nothing here is a substitute
for the PostgreSQL-specific integration pass; it is what lets the unit and
API-contract tests run fast and without any external service.

`DATABASE_URL` is assigned, not `setdefault`-ed, and the result is
asserted to be SQLite. The `db` fixture below calls `drop_all()`, so a
test run that resolved to a real database would destroy it. `setdefault`
was not enough protection: inside the api/worker containers `DATABASE_URL`
is already exported by compose, so `setdefault` silently did nothing, the
engine bound to live PostgreSQL, and a `pytest` run wiped the database.
The guard below makes that failure mode impossible rather than silent.
"""

from __future__ import annotations

import os

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["CELERY_TASK_ALWAYS_EAGER"] = "true"
os.environ["LOG_FORMAT"] = "console"
os.environ["CACHE_ENABLED"] = "false"

# Checked after every import below has had a chance to mutate it, and again
# in the `db` fixture: the `db` fixture's `drop_all()` is only safe while
# this holds.
_TEST_URL_PREFIX = "sqlite"
if not os.environ["DATABASE_URL"].startswith(_TEST_URL_PREFIX):  # pragma: no cover
    raise RuntimeError(
        "Refusing to run tests against a non-SQLite database: "
        f"{os.environ['DATABASE_URL']!r}. The test fixtures drop all tables "
        "on teardown, which would destroy it."
    )

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.session import SessionLocal, create_all, drop_all


@pytest.fixture()
def db() -> Session:
    # Re-asserted here, immediately before the destructive `drop_all()`:
    # nothing imported during collection may have rebound the engine onto
    # a real database without the module-level check noticing.
    if not os.environ.get("DATABASE_URL", "").startswith(_TEST_URL_PREFIX):  # pragma: no cover
        raise RuntimeError(
            "Refusing to run the `db` fixture against a non-SQLite database: "
            f"{os.environ.get('DATABASE_URL')!r}. Its teardown calls drop_all()."
        )
    create_all()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        drop_all()


@pytest.fixture()
def client(db: Session):
    from app.api.deps import get_db
    from app.main import app

    def _override_db():
        yield db

    app.dependency_overrides[get_db] = _override_db
    # raise_server_exceptions=False so a route that 500s returns the real
    # HTTP response instead of re-raising in-process — otherwise
    # core/errors.py's own 500 handler is never actually exercised by a
    # test that deliberately provokes one.
    with TestClient(app, raise_server_exceptions=False) as test_client:
        # Insyte requires an account to scan. Register one and attach its
        # bearer token by default so the bulk of the API-contract tests
        # exercise the authenticated path; `anon_client` covers the 401 path.
        resp = test_client.post(
            "/api/auth/register",
            json={"email": "tester@example.com", "password": "password123"},
        )
        token = resp.json()["access_token"]
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def anon_client(db: Session):
    """An unauthenticated client, for asserting the 401 path on protected
    routes."""
    from app.api.deps import get_db
    from app.main import app

    def _override_db():
        yield db

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()
