"""Core scan lifecycle: create, list, read, cancel, delete, progress, logs."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_db
from app.models.scan import ScanLog
from app.schemas.common import Page
from app.schemas.scan import (
    ScanCreate,
    ScanDetailRead,
    ScanListItem,
    ScanLogRead,
    ScanModuleRead,
    ScanProgressRead,
    ScanRead,
)
from app.services.scan.service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])


def _service(db: Session = Depends(get_db)) -> ScanService:
    return ScanService(db)


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate, user: CurrentUser, svc: ScanService = Depends(_service)
) -> ScanRead:
    scan = svc.create(payload, user_id=user.id)
    return ScanRead.model_validate(scan)


@router.get("", response_model=Page[ScanListItem])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    target: str | None = None,
    project_id: uuid.UUID | None = None,
    user: CurrentUser = None,
    svc: ScanService = Depends(_service),
) -> Page[ScanListItem]:
    rows, total = svc.list(
        limit=limit, offset=offset, status=status_filter, target=target,
        project_id=project_id, user_id=user.id,
    )
    return Page(
        items=[ScanListItem.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanDetailRead)
def get_scan(
    scan_id: uuid.UUID, user: CurrentUser, svc: ScanService = Depends(_service)
) -> ScanDetailRead:
    scan = svc.reap_if_orphaned(svc.get(scan_id, user.id))
    data = ScanRead.model_validate(scan).model_dump()
    data["modules"] = [ScanModuleRead.model_validate(m) for m in scan.modules]
    return ScanDetailRead.model_validate(data)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_scan(
    scan_id: uuid.UUID, user: CurrentUser, svc: ScanService = Depends(_service)
) -> None:
    svc.delete(scan_id, user.id)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(
    scan_id: uuid.UUID, user: CurrentUser, svc: ScanService = Depends(_service)
) -> ScanRead:
    scan = svc.cancel(scan_id, user.id)
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}/progress", response_model=ScanProgressRead)
def scan_progress(
    scan_id: uuid.UUID, user: CurrentUser, svc: ScanService = Depends(_service)
) -> ScanProgressRead:
    scan = svc.reap_if_orphaned(svc.get(scan_id, user.id))
    return ScanProgressRead(
        status=scan.status,
        progress=scan.progress,
        modules=[ScanModuleRead.model_validate(m) for m in scan.modules],
        exposure_score=scan.exposure_score,
        exposure_band=scan.exposure_band,
    )


@router.get("/{scan_id}/logs", response_model=Page[ScanLogRead])
def scan_logs(
    scan_id: uuid.UUID,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    since_sequence: int = Query(default=0, ge=0),
    user: CurrentUser = None,
    svc: ScanService = Depends(_service),
    db: Session = Depends(get_db),
) -> Page[ScanLogRead]:
    svc.get(scan_id, user.id)  # 404s if the scan does not exist or isn't yours
    query = select(ScanLog).where(ScanLog.scan_id == scan_id)
    if since_sequence:
        query = query.where(ScanLog.sequence > since_sequence)
    from sqlalchemy import func

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(ScanLog.sequence).limit(limit).offset(offset)).all()
    return Page(
        items=[ScanLogRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )
