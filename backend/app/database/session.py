"""Engine and session factory.

Two things matter here for correctness under Celery:

* the engine is created with `pool_pre_ping` so a worker that has been idle
  past PostgreSQL's connection timeout reconnects instead of failing a task;
* `session_scope()` is the only sanctioned way for worker code to get a
  session, because it guarantees commit-or-rollback-and-close. A leaked
  session in a long-lived worker holds a transaction open and blocks
  vacuum on the tables the next scan needs.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.logging import get_logger
from app.database.base import Base

logger = get_logger(__name__)


def _create_engine() -> Engine:
    kwargs: dict[str, object] = {
        "pool_pre_ping": True,
        "echo": settings.DB_ECHO,
        "future": True,
    }
    if settings.is_sqlite:
        # In-memory SQLite needs a shared connection across threads for the
        # test suite; a file-backed SQLite URL behaves normally.
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in settings.DATABASE_URL:
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    else:
        kwargs.update(
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_recycle=settings.DB_POOL_RECYCLE,
        )
    return create_engine(settings.DATABASE_URL, **kwargs)


engine: Engine = _create_engine()

if settings.is_sqlite:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record) -> None:  # noqa: ANN001
        """SQLite ignores foreign keys unless asked not to.

        Without this the cascade-delete behaviour the models declare would
        silently not apply in tests, hiding real bugs.
        """
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    future=True,
)


def get_db() -> Generator[Session]:
    """FastAPI dependency. Read-mostly; the request handler commits."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for worker code."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_all() -> None:
    """Create the schema directly.

    Only for the test suite. Production schema changes go through Alembic;
    see `alembic/versions/`.
    """
    import app.models  # noqa: F401 - register every mapper

    Base.metadata.create_all(bind=engine)


def drop_all() -> None:
    import app.models  # noqa: F401

    Base.metadata.drop_all(bind=engine)
