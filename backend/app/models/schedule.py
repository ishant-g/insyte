"""Scheduled scan model.

ScanSchedule is the only recurring construct in Insyte. The Scan model
itself stays on-demand; a schedule owns the recurrence policy and each
firing creates a normal Scan row owned by the schedule's owner. After a
scheduled scan reaches a terminal state, a diff against the previous
completed scan of the same target is persisted as a compact summary.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import (
    Base,
    JSONBType,
    TimestampMixin,
    UUIDPrimaryKey,
    UUIDType,
)
from app.models.enums import ScanMode


class ScanSchedule(Base, UUIDPrimaryKey, TimestampMixin):
    """One recurring scan policy belonging to one user."""

    __tablename__ = "scan_schedules"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: Denormalised target value, validated at creation like ScanCreate.
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ScanMode.PASSIVE.value
    )
    #: Module ids to run each firing. Empty means the recommended set.
    module_ids: Mapped[list[Any]] = mapped_column(
        JSONBType, nullable=False, default=list
    )
    #: Hours between firings.
    interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)

    #: Next firing time. The Celery beat dispatcher picks up every schedule
    #: with next_run_at in the past.
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    #: Bookkeeping for the last firing and its diff finalisation.
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(UUIDType, nullable=True)
    last_finalized_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, nullable=True
    )
    #: Compact diff summary vs the previous completed scan of the same
    #: target, e.g. {"added": 3, "removed": 1, "changed": 0, ...}.
    last_diff_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
