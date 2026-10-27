"""Generated report artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import (
    Base,
    JSONBType,
    UUIDPrimaryKey,
    UUIDType,
    utcnow,
)
from app.models.enums import ReportStatus

if TYPE_CHECKING:
    from app.models.scan import Scan


class Report(Base, UUIDPrimaryKey):
    """One generated report file, in one format, for one scan.

    Three rows per completed scan (PDF, Markdown, JSON). Reports are
    generated once by the worker and served from disk thereafter, rather
    than rebuilt inside every download request as the predecessor did - a
    large scan's PDF takes seconds to render and doing that synchronously
    in a request handler is a self-inflicted denial of service.

    `storage_path` is always derived from the report's own UUID, never from
    the target string, so a target named `../../etc/passwd` cannot steer a
    write.
    """

    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    format: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    #: The name offered to the user, e.g. "insyte-example-com-2026-08-28.pdf".
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ReportStatus.PENDING.value, index=True
    )
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    generation_duration: Mapped[float | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="reports")

    __table_args__ = (
        UniqueConstraint("scan_id", "format", name="uq_reports_scan_format"),
    )
