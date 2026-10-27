"""Scan service: the primary workflow - target in, scan queued.

`create()` is the one function that turns "example.com" into a running
scan: find-or-create the `Target` row, create the `Scan` row in `QUEUED`,
dispatch the Celery task, and return immediately. Everything after that is
the orchestrator's job (`services/scan/orchestrator.py`), running in a
worker process.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.target import parse_target
from app.models.enums import ModuleStatus, ScanMode, ScanStatus
from app.models.scan import Scan
from app.models.target import Target
from app.modules.registry import default_registry
from app.schemas.scan import ScanCreate

logger = get_logger(__name__)


class ScanService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, payload: ScanCreate, user_id: uuid.UUID | None = None) -> Scan:
        parsed = parse_target(payload.target)  # re-validated - see ScanCreate docstring

        target = self.db.scalar(select(Target).where(Target.value == parsed.value))
        if target is None:
            target = Target(
                value=parsed.value,
                target_type=parsed.target_type.value,
                unicode_value=parsed.unicode_value,
                registrable_domain=parsed.registrable,
                public_suffix=parsed.suffix,
                tld=parsed.tld,
                subdomain=parsed.subdomain,
                original_input=payload.target[:512],
            )
            self.db.add(target)
            self.db.flush()

        modules, warnings = self._resolve_modules(payload.modules, payload.mode, parsed)

        scan = Scan(
            target_id=target.id,
            project_id=payload.project_id,
            user_id=user_id,
            target_value=parsed.value,
            target_type=parsed.target_type.value,
            mode=payload.mode.value,
            status=ScanStatus.QUEUED.value,
            requested_modules=modules,
            queued_at=datetime.now(UTC),
        )
        self.db.add(scan)
        target.scan_count = (target.scan_count or 0) + 1
        target.last_scanned_at = datetime.now(UTC)
        self.db.commit()
        self.db.refresh(scan)

        # Transient, not a column: picked up by `ScanRead.warnings` via
        # `from_attributes` when the creation endpoint serialises the scan.
        # Other endpoints (get/cancel/...) leave it unset and the schema
        # default (`[]`) applies - warnings are a creation-time concern.
        if not settings.CELERY_TASK_ALWAYS_EAGER:
            from app.workers.liveness import worker_status

            alive, _ = worker_status()
            if not alive:
                warnings.append(
                    "No scan worker is currently reachable, so this scan "
                    "will wait in the queue until a worker comes online. "
                    "Make sure Redis is up and the Celery worker is running: "
                    "celery -A app.workers.celery_app.celery worker -l info"
                )
        scan.warnings = warnings  # type: ignore[attr-defined]

        self._dispatch(scan)
        return scan

    def reap_if_orphaned(self, scan: Scan) -> Scan:
        """Fail a scan its worker abandoned, honestly.

        A scan whose worker died (or was never started) used to sit at
        "scanning" forever: no progress, no error, just a spinner. When a
        scan has been quiet longer than `SCAN_PICKUP_TIMEOUT` *and* no
        worker is reachable, the honest outcome is a failed scan that says
        exactly that - not an eternal spinner.

        Scans are only ever reaped when no worker is alive: with live
        workers a quiet scan may simply be waiting its turn behind a long
        scan, and the workers own its lifecycle (module timeouts and the
        abort path in the orchestrator handle real failures). Never raises.
        """
        try:
            if scan.scan_status.is_terminal:
                return scan
            if settings.CELERY_TASK_ALWAYS_EAGER:
                return scan

            def _aware(dt):
                if dt is not None and dt.tzinfo is None:
                    return dt.replace(tzinfo=UTC)
                return dt

            now = datetime.now(UTC)
            queued_at = _aware(scan.queued_at)
            if queued_at is None or (now - queued_at).total_seconds() < settings.SCAN_PICKUP_TIMEOUT:
                return scan

            from app.workers.liveness import worker_status

            alive, _ = worker_status()
            if alive:
                return scan

            terminal = {ModuleStatus.COMPLETED.value, ModuleStatus.FAILED.value, ModuleStatus.SKIPPED.value}
            rows = list(scan.modules or [])
            if not rows:
                reason = (
                    "The scan worker never picked up this scan: no worker has "
                    "been reachable since it was queued. Check that Redis and "
                    "the Celery worker are running, then start a new scan."
                )
            else:
                open_rows = [r for r in rows if r.status not in terminal]
                if not open_rows:
                    return scan
                latest = queued_at
                for r in open_rows:
                    for dt in (_aware(r.completed_at), _aware(r.started_at)):
                        if dt is not None and dt > latest:
                            latest = dt
                # A live wave always finishes within one module budget, so a
                # scan quiet much longer than that with no worker alive is
                # not slow - its worker is gone.
                quiet_for = (now - latest).total_seconds()
                if quiet_for < settings.SCAN_PICKUP_TIMEOUT + settings.MODULE_TIME_LIMIT:
                    return scan
                reason = (
                    "The scan worker died in the middle of this scan: no "
                    "worker has been reachable and no module has progressed "
                    f"for {int(quiet_for // 60)} minutes. Check that Redis and "
                    "the Celery worker are running, then start a new scan."
                )

            scan.status = ScanStatus.FAILED.value
            scan.error = reason
            scan.completed_at = now
            scan.progress = 100
            self.db.commit()
            logger.warning("scan_reaped_orphan", extra={"scan_id": str(scan.id)})
            return scan
        except Exception:  # noqa: BLE001 - reaping must never break a read
            logger.exception("scan_reap_failed", extra={"scan_id": str(scan.id)})
            self.db.rollback()
            return scan


    def _resolve_modules(
        self, requested: list[str], mode: ScanMode, target
    ) -> tuple[list[str], list[str]]:
        """Intersect the requested modules with what can actually run.

        Returns the resolved module ids plus human-readable warnings for
        everything that was dropped or will run degraded - the caller
        surfaces these in the scan creation response so a request for a
        module that can never run is never silently swallowed.
        """
        from app.core.target import TargetType

        target_type = TargetType(target.target_type.value)
        registry = {m.id: m for m in default_registry.all()}
        available = {
            mid
            for mid, m in registry.items()
            if mode in m.mode_support and target_type in m.input_types
        }
        warnings: list[str] = []
        if not requested:
            selected = set(default_registry.recommended_ids()) & available
        elif requested == ["__all__"]:
            selected = available
        else:
            for mid in requested:
                module = registry.get(mid)
                if module is None:
                    warnings.append(f"Unknown module id '{mid}' was ignored.")
                elif mid not in available:
                    if mode not in module.mode_support:
                        warnings.append(
                            f"Module '{mid}' does not run in {mode.label} mode "
                            "and was skipped."
                        )
                    else:
                        kinds = ", ".join(t.value for t in module.input_types)
                        warnings.append(
                            f"Module '{mid}' does not apply to "
                            f"{target_type.value} targets (supports: {kinds}) "
                            "and was skipped."
                        )
            selected = set(requested) & available
        for mid in sorted(selected):
            missing = [
                dep for dep in registry[mid].dependencies if dep not in selected
            ]
            if missing:
                warnings.append(
                    f"Module '{mid}' runs without its prerequisite "
                    f"module(s) ({', '.join(missing)}), which were not "
                    "selected - it will produce reduced results."
                )
        return sorted(selected), warnings

    def _dispatch(self, scan: Scan) -> None:
        if settings.CELERY_TASK_ALWAYS_EAGER:
            from app.services.scan.orchestrator import run_scan

            run_scan(str(scan.id))
            return
        from app.workers.tasks import run_scan_task

        result = run_scan_task.delay(str(scan.id))
        scan.celery_task_id = result.id
        self.db.commit()

    # -- reads -------------------------------------------------------------

    def get(self, scan_id: uuid.UUID, user_id: uuid.UUID | None = None) -> Scan:
        scan = self.db.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError("Scan not found")
        # Ownership: when a user is supplied, a scan owned by someone else is
        # reported as "not found" rather than "forbidden" so existence of
        # another account's scan is never disclosed. Legacy scans with no
        # owner (user_id IS NULL) remain accessible to any authenticated user.
        if user_id is not None and scan.user_id is not None and scan.user_id != user_id:
            raise NotFoundError("Scan not found")
        return scan

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        target: str | None = None,
        project_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
    ) -> tuple[list[Scan], int]:
        query = select(Scan)
        if user_id is not None:
            query = query.where(Scan.user_id == user_id)
        if status:
            query = query.where(Scan.status == status)
        if target:
            query = query.where(Scan.target_value.ilike(f"%{target.lower()}%"))
        if project_id:
            query = query.where(Scan.project_id == project_id)

        total = self.db.scalar(
            select(__import__("sqlalchemy").func.count()).select_from(query.subquery())
        ) or 0
        rows = self.db.scalars(
            query.order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        ).all()
        return list(rows), total

    # -- mutations -----------------------------------------------------------

    def cancel(self, scan_id: uuid.UUID, user_id: uuid.UUID | None = None) -> Scan:
        scan = self.get(scan_id, user_id)
        if scan.scan_status.is_terminal:
            raise ConflictError(f"Scan is already {scan.status}; nothing to cancel.")
        scan.cancel_requested = True
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def delete(self, scan_id: uuid.UUID, user_id: uuid.UUID | None = None) -> None:
        scan = self.get(scan_id, user_id)
        self.db.delete(scan)
        self.db.commit()
