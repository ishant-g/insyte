"""Target and Project models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import (
    Base,
    JSONBType,
    TimestampMixin,
    UUIDPrimaryKey,
    UUIDType,
)

if TYPE_CHECKING:
    from app.models.scan import Scan


class Target(Base, UUIDPrimaryKey, TimestampMixin):
    """A domain, IPv4 address or IPv6 address that has been scanned.

    Targets are deduplicated on the canonical value produced by
    `core.target.parse_target`, so scanning "EXAMPLE.com", "example.com."
    and "https://example.com/" all attach to one row - which is what makes
    scan-to-scan comparison possible without asking the user to be careful
    about how they type.
    """

    __tablename__ = "targets"

    #: Canonical value: lowercase punycode domain or compressed IP literal.
    value: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    #: Unicode presentation form, for display of IDN targets.
    unicode_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registrable_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    public_suffix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tld: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subdomain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: Exactly what the user typed the first time, for provenance.
    original_input: Mapped[str | None] = mapped_column(String(512), nullable=True)

    scan_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scans: Mapped[list[Scan]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_targets_value_type", "value", "target_type"),
    )


class Project(Base, UUIDPrimaryKey, TimestampMixin):
    """Optional grouping for scans.

    Kept because organising a body of work is genuinely useful, but
    deliberately *optional*: `Scan.project_id` is nullable so the primary
    workflow (type a target, press Run) never requires creating one first.
    """

    __tablename__ = "projects"

    #: Owning account. Nullable for pre-accounts rows; new projects carry
    #: the authenticated user and listings are filtered by it.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    scans: Mapped[list[Scan]] = relationship(back_populates="project")


class ScanTag(Base, UUIDPrimaryKey):
    """Free-form label on a scan, for the user's own organisation."""

    __tablename__ = "scan_tags"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    label: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (Index("uq_scan_tags_scan_label", "scan_id", "label", unique=True),)
