"""Celery tasks.

`run_scan_task` is the only task the API dispatches. Report generation is
chained onto it (rather than triggered lazily on first download) so a
completed scan's PDF/Markdown/JSON are ready before the user clicks
download, which a slow first-download experience would undercut.
"""

from __future__ import annotations

from app.core.logging import get_logger
from app.workers.celery_app import celery

logger = get_logger(__name__)


@celery.task(
    name="insyte.run_scan",
    bind=True,
    max_retries=1,
    default_retry_delay=10,
)
def run_scan_task(self, scan_id: str) -> dict:
    from app.services.scan.orchestrator import run_scan

    logger.info("task_started", extra={"task": "run_scan", "scan_id": scan_id})
    result = run_scan(scan_id)
    generate_reports_task.delay(scan_id)
    return result


@celery.task(name="insyte.generate_reports", bind=True, max_retries=2, default_retry_delay=5)
def generate_reports_task(self, scan_id: str) -> dict:
    from app.database.session import SessionLocal
    from app.models.enums import ReportFormat
    from app.services.reports.service import ReportService

    db = SessionLocal()
    try:
        svc = ReportService(db)
        generated = []
        for fmt in (ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.PDF):
            try:
                svc.get_or_generate(scan_id, fmt)
                generated.append(fmt.value)
            except Exception:  # noqa: BLE001, one format failing must not block the others
                logger.exception(
                    "report_generation_failed", extra={"scan_id": scan_id, "format": fmt.value}
                )
        return {"scan_id": scan_id, "generated": generated}
    finally:
        db.close()


@celery.task(name="insyte.dispatch_due_schedules")
def dispatch_due_schedules_task() -> dict:
    """Celery Beat entrypoint: fire due schedules, finalise finished ones.

    Runs every few minutes (see beat_schedule in celery_app.py). Both halves
    are idempotent: a schedule only fires once per due window because
    next_run_at advances on dispatch, and finalisation is keyed on
    last_finalized_scan_id so a restart never double-counts a diff.
    """
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        dispatched = _dispatch_due_schedules(db)
        finalized = _finalize_finished_schedules(db)
        db.commit()
        return {"dispatched": dispatched, "finalized": finalized}
    finally:
        db.close()


def _dispatch_due_schedules(db) -> int:
    """Create one on-demand scan per due schedule and advance its timer."""
    from datetime import timedelta

    from sqlalchemy import select

    from app.database.base import utcnow
    from app.models.enums import ScanMode
    from app.models.schedule import ScanSchedule
    from app.schemas.scan import ScanCreate
    from app.services.scan.service import ScanService

    now = utcnow()
    due = db.scalars(
        select(ScanSchedule).where(
            ScanSchedule.enabled.is_(True),
            ScanSchedule.next_run_at <= now,
        )
    ).all()
    for sched in due:
        # Reuses the exact manual-scan path: same module resolution,
        # warnings, dispatch and reporting. Nothing scan-specific is
        # duplicated here.
        payload = ScanCreate(
            target=sched.target,
            mode=ScanMode(sched.mode),
            modules=list(sched.module_ids or []),
        )
        scan = ScanService(db).create(payload, user_id=sched.user_id)
        sched.last_scan_id = scan.id
        sched.last_run_at = now
        sched.next_run_at = now + timedelta(hours=sched.interval_hours)
        logger.info(
            "schedule_fired",
            extra={"schedule_id": str(sched.id), "scan_id": str(scan.id)},
        )
    db.flush()
    return len(due)


def _finalize_finished_schedules(db) -> int:
    """Persist a diff summary for scheduled scans that reached a terminal state."""
    from sqlalchemy import or_, select

    from app.models.enums import ScanStatus
    from app.models.scan import Scan
    from app.models.schedule import ScanSchedule

    terminal = {
        ScanStatus.COMPLETED.value,
        ScanStatus.PARTIAL.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }
    pending = db.scalars(
        select(ScanSchedule).where(
            ScanSchedule.last_scan_id.is_not(None),
            or_(
                ScanSchedule.last_finalized_scan_id.is_(None),
                ScanSchedule.last_finalized_scan_id != ScanSchedule.last_scan_id,
            ),
        )
    ).all()
    done = 0
    for sched in pending:
        scan = db.get(Scan, sched.last_scan_id)
        if scan is None or scan.status not in terminal:
            continue
        sched.last_diff_summary = _build_diff_summary(db, sched, scan)
        sched.last_finalized_scan_id = scan.id
        done += 1
    db.flush()
    return done


def _build_diff_summary(db, sched, scan) -> dict:
    """Diff a finished scheduled scan against the previous completed scan
    of the same target by the same owner. Returns a compact JSON summary."""
    from sqlalchemy import select

    from app.models.enums import ScanStatus
    from app.models.scan import Scan
    from app.services.scan.diff import compare_scans

    empty = {
        "scan_id": str(scan.id),
        "compared_to": None,
        "added": 0,
        "removed": 0,
        "changed": 0,
        "new_findings": [],
    }
    previous = (
        db.scalars(
            select(Scan)
            .where(
                Scan.user_id == sched.user_id,
                Scan.target_value == sched.target,
                Scan.id != scan.id,
                Scan.status.in_(
                    [ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value]
                ),
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        ).first()
    )
    if previous is None:
        return empty
    diff = compare_scans(db, previous.id, scan.id)
    return {
        "scan_id": str(scan.id),
        "compared_to": str(previous.id),
        "added": len(diff.added),
        "removed": len(diff.removed),
        "changed": len(diff.changed),
        "new_findings": [e.value for e in diff.added if e.asset_type == "finding"][:10],
    }
