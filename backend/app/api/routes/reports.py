"""Report generation and download.

Reports are generated once (triggered on first request for a format, or
by the worker immediately after a scan completes - see
`workers/tasks.py:generate_reports_task`) and served from disk thereafter.
The predecessor regenerated the PDF synchronously inside every download
request; for a large scan that is a self-inflicted denial of service, and
it also meant Markdown/JSON were never offered at all.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db, verify_scan_owner
from app.models.enums import ReportFormat
from app.services.reports.service import ReportService

router = APIRouter(prefix="/scans", tags=["reports"], dependencies=[Depends(verify_scan_owner)])


def _service(db: Session = Depends(get_db)) -> ReportService:
    return ReportService(db)


@router.get("/{scan_id}/report/pdf")
def download_pdf(scan_id: uuid.UUID, svc: ReportService = Depends(_service)) -> FileResponse:
    report = svc.get_or_generate(scan_id, ReportFormat.PDF)
    return FileResponse(
        path=report.storage_path,
        filename=report.filename,
        media_type=ReportFormat.PDF.media_type,
    )


@router.get("/{scan_id}/report/md")
def download_markdown(scan_id: uuid.UUID, svc: ReportService = Depends(_service)) -> FileResponse:
    report = svc.get_or_generate(scan_id, ReportFormat.MARKDOWN)
    return FileResponse(
        path=report.storage_path,
        filename=report.filename,
        media_type=ReportFormat.MARKDOWN.media_type,
    )


@router.get("/{scan_id}/report/json")
def download_json(scan_id: uuid.UUID, svc: ReportService = Depends(_service)) -> FileResponse:
    report = svc.get_or_generate(scan_id, ReportFormat.JSON)
    return FileResponse(
        path=report.storage_path,
        filename=report.filename,
        media_type=ReportFormat.JSON.media_type,
    )
