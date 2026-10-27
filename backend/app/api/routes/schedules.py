"""Scheduled scans: create, list, read, delete, enable/disable.

A schedule is a recurrence policy owned by one user. Each firing creates a
normal on-demand Scan row (via the same service the manual endpoint uses),
so scheduled scans get identical module resolution, warnings and reporting.
Ownership follows the scan convention: another account's schedule reads as
"not found", never "forbidden".
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_db
from app.core.errors import NotFoundError
from app.core.target import TargetError, parse_target
from app.database.base import utcnow
from app.models.enums import ScanMode
from app.models.schedule import ScanSchedule
from app.modules.registry import default_registry
from app.schemas.common import Page

router = APIRouter(prefix="/schedules", tags=["schedules"])


class ScheduleCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    target: str = Field(..., min_length=1, max_length=2048)
    mode: ScanMode = Field(default=ScanMode.PASSIVE)
    #: Module ids to run each firing. Empty means the recommended set.
    modules: list[str] = Field(default_factory=list)
    #: Hours between firings, 1 hour to 30 days.
    interval_hours: int = Field(default=24, ge=1, le=720)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str) -> str:
        try:
            parse_target(value)
        except TargetError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("modules")
    @classmethod
    def _validate_modules(cls, value: list[str]) -> list[str]:
        known = {m.id for m in default_registry.all()}
        unknown = [mid for mid in value if mid not in known]
        if unknown:
            raise ValueError(f"Unknown module ids: {', '.join(sorted(unknown))}")
        return value


class SchedulePatch(BaseModel):
    enabled: bool


class ScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target: str
    mode: str
    module_ids: list[Any] = Field(default_factory=list)
    interval_hours: int
    next_run_at: datetime
    enabled: bool
    last_run_at: datetime | None
    last_scan_id: uuid.UUID | None
    last_diff_summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


def _get_owned(db: Session, schedule_id: uuid.UUID, user_id: uuid.UUID) -> ScanSchedule:
    sched = db.get(ScanSchedule, schedule_id)
    if sched is None or sched.user_id != user_id:
        raise NotFoundError("Schedule not found")
    return sched


@router.post("", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
def create_schedule(
    payload: ScheduleCreate,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> ScheduleRead:
    sched = ScanSchedule(
        user_id=user.id,
        target=payload.target.strip(),
        mode=payload.mode.value,
        module_ids=list(payload.modules),
        interval_hours=payload.interval_hours,
        # First firing happens on the next beat tick (within minutes), then
        # every interval_hours after each firing.
        next_run_at=utcnow(),
        enabled=True,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return ScheduleRead.model_validate(sched)


@router.get("", response_model=Page[ScheduleRead])
def list_schedules(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: CurrentUser = None,
    db: Session = Depends(get_db),
) -> Page[ScheduleRead]:
    query = select(ScanSchedule).where(ScanSchedule.user_id == user.id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(ScanSchedule.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page(
        items=[ScheduleRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{schedule_id}", response_model=ScheduleRead)
def get_schedule(
    schedule_id: uuid.UUID,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> ScheduleRead:
    sched = _get_owned(db, schedule_id, user.id)
    return ScheduleRead.model_validate(sched)


@router.patch("/{schedule_id}", response_model=ScheduleRead)
def patch_schedule(
    schedule_id: uuid.UUID,
    payload: SchedulePatch,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> ScheduleRead:
    sched = _get_owned(db, schedule_id, user.id)
    sched.enabled = payload.enabled
    db.commit()
    db.refresh(sched)
    return ScheduleRead.model_validate(sched)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_schedule(
    schedule_id: uuid.UUID,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> None:
    sched = _get_owned(db, schedule_id, user.id)
    db.delete(sched)
    db.commit()
