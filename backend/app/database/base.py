"""Declarative base, shared column types and mixins.

PostgreSQL is the production target and the schema uses `JSONB` and native
`uuid` accordingly. Both are declared through variants so the unit-test
suite can run the same models on SQLite without a server, which keeps the
tests honest about the mapping while not requiring a database to run them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, MetaData, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

#: Explicit naming convention so Alembic autogenerate produces stable,
#: reviewable migration names instead of database-assigned ones.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: JSONB on PostgreSQL, plain JSON on SQLite.
JSONBType = JSONB().with_variant(JSON(), "sqlite")

#: Native uuid on PostgreSQL, CHAR(32) on SQLite.
UUIDType = Uuid(as_uuid=True, native_uuid=True)


def utcnow() -> datetime:
    """Timezone-aware now. Never use naive datetimes in Insyte."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {
        dict[str, Any]: JSONBType,
        list[Any]: JSONBType,
    }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk = getattr(self, "id", None)
        return f"<{self.__class__.__name__} id={pk}>"


class UUIDPrimaryKey:
    """Server-independent UUID primary key."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, primary_key=True, default=uuid.uuid4
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ProvenanceMixin:
    """Columns every piece of intelligence must carry.

    This is the schema-level expression of the brief's evidence model: an
    Insyte result that cannot say where it came from, when it was seen and
    how sure it is has no place in the database.
    """

    #: 0-100. Deliberately *not* severity - see services/correlation/confidence.py.
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    #: Source ids that contributed, e.g. ["crtsh", "urlscan"].
    sources: Mapped[list[Any]] = mapped_column(
        JSONBType, nullable=False, default=list
    )
    #: Free-form supporting detail. Secrets are masked before they land here.
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ScanScoped:
    """Mixin for rows that belong to exactly one scan."""

    @classmethod
    def _scan_fk(cls) -> Any:  # pragma: no cover - declarative helper
        from sqlalchemy import ForeignKey

        return ForeignKey("scans.id", ondelete="CASCADE")


def short_text(length: int = 255) -> String:
    return String(length)
