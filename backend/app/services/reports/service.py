"""Report service: generate-once, serve-from-disk.

Storage paths are always derived from the report's own UUID plus a
sanitised target slug - never from a raw, request-controlled string - so a
target value containing path-traversal characters cannot influence where a
file is written. See `core/target.Target.slug` for the sanitisation and
`docs/AUDIT.md` section 7 item 11 for the vulnerability this replaces.
"""

from __future__ import annotations

import uuid
from datetime import UTC
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.models.enums import ReportFormat, ReportStatus, ScanStatus
from app.models.report import Report
from app.models.scan import Scan
from app.services.reports.builder import build_report_data
from app.services.reports.json_export import write_json_report
from app.services.reports.markdown_export import write_markdown_report
from app.services.reports.pdf_export import write_pdf_report

logger = get_logger(__name__)

_GENERATORS = {
    ReportFormat.JSON: write_json_report,
    ReportFormat.MARKDOWN: write_markdown_report,
    ReportFormat.PDF: write_pdf_report,
}


class ReportService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.reports_dir = Path(settings.DATA_DIR) / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def get_or_generate(self, scan_id: uuid.UUID, fmt: ReportFormat) -> Report:
        scan = self.db.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError("Scan not found")
        if scan.status not in (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value):
            raise ConflictError(
                f"Scan is {scan.status}; a report can only be generated for a "
                "completed or partially-completed scan."
            )

        existing = self.db.scalar(
            select(Report).where(Report.scan_id == scan_id, Report.format == fmt.value)
        )
        if existing is not None and existing.status == ReportStatus.READY.value:
            path = Path(existing.storage_path or "")
            if path.is_file():
                return existing
            # The row says ready but the file is gone (e.g. an ephemeral
            # container filesystem) - regenerate rather than 404 on a
            # download that should just work.
            logger.warning("report_file_missing", extra={"report_id": str(existing.id)})

        report = existing or Report(scan_id=scan_id, format=fmt.value, filename="")
        if existing is None:
            self.db.add(report)

        report_data = build_report_data(self.db, scan_id)
        # Every report id is a fresh UUID (or the existing row's, on
        # regeneration) - the filesystem name never touches the target
        # string directly.
        if report.id is None:
            self.db.flush()
        storage_name = f"{report.id}.{fmt.extension}"
        storage_path = self.reports_dir / storage_name
        filename = f"{report_data.filename_stub}.{fmt.extension}"

        report.status = ReportStatus.GENERATING.value
        self.db.commit()

        import time

        started = time.perf_counter()
        try:
            size = _GENERATORS[fmt](report_data, storage_path)
        except Exception as exc:  # noqa: BLE001 - record the failure, do not crash the request
            report.status = ReportStatus.FAILED.value
            report.error = f"{exc.__class__.__name__}: {str(exc)[:400]}"
            self.db.commit()
            logger.exception("report_generation_failed", extra={"scan_id": str(scan_id), "format": fmt.value})
            raise

        import hashlib
        from datetime import datetime

        report.filename = filename
        report.storage_path = str(storage_path)
        report.status = ReportStatus.READY.value
        report.size = size
        report.content_sha256 = hashlib.sha256(storage_path.read_bytes()).hexdigest()
        report.generated_at = datetime.now(UTC)
        report.generation_duration = round(time.perf_counter() - started, 3)
        report.stats = {
            "findings": len(report_data.findings),
            "assets": len(report_data.assets),
            "cves": len(report_data.cves),
        }
        self.db.commit()
        self.db.refresh(report)
        return report
