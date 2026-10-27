"""Scan orchestrator: runs one scan end-to-end.

This is the state machine the brief calls for in section 32 - QUEUED →
RUNNING → (PARTIAL | COMPLETED | FAILED | CANCELLED) - implemented over
real `ScanModule` rows rather than an `index / total` counter, so progress
reflects what actually happened. A module failure never aborts the scan:
`ModuleRegistry.execution_waves` plus `IntelligenceModule.run`'s own
exception handling (see `modules/base.py`) mean the orchestrator's job is
just to record what each module did and keep going.

Designed to be called from a synchronous context (a Celery task - see
`workers/tasks.py`) with no async code, because every collaborator
(`httpx.Client`, `dns.resolver`, SQLAlchemy's ORM session) is synchronous
and thread-based concurrency inside one process is what the wave execution
below actually uses.
"""

from __future__ import annotations

import queue
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.contracts import ModuleOutput
from app.core.logging import get_logger, scan_logger
from app.core.target import parse_target
from app.models.enums import ModuleStatus, ScanStatus
from app.models.scan import Scan, ScanLog, ScanModule
from app.modules.base import CancelledError, CollectionLimits, ModuleContext
from app.modules.registry import default_registry
from app.services.correlation.graph import build_graph
from app.services.cve.correlator import correlate
from app.services.risk.exposure import compute_exposure
from app.services.scan.persist import (
    _jsonable,
    persist_cves,
    persist_findings,
    persist_graph,
    persist_intelligence,
    persist_observations,
    score_and_finalize_findings,
)

logger = get_logger(__name__)

#: Modules run inside a bounded thread pool so an I/O-bound wave (five
#: providers, each blocking on its own HTTP round trip) actually overlaps
#: instead of serialising - the concurrency section 76 of the brief asks
#: for, achieved with threads because every collaborator here is sync.
_WAVE_CONCURRENCY = 6


class ScanOrchestrator:
    def __init__(self, db: Session, registry=None) -> None:
        self.db = db
        self.registry = registry or default_registry
        #: Decrypted per-account provider keys for this scan's owner, loaded
        #: once in `_execute` and installed into each worker thread's context
        #: in `_run_one`. Empty when the scan has no owner or no stored keys.
        self._credentials: dict[str, dict[str, str]] = {}

    def run(self, scan_id: str | uuid.UUID) -> dict:
        scan = self.db.get(Scan, scan_id if isinstance(scan_id, uuid.UUID) else uuid.UUID(str(scan_id)))
        if scan is None:
            logger.error("scan_not_found", extra={"scan_id": str(scan_id)})
            return {"success": False, "error": "scan_not_found"}
        return self._execute(scan)

    # -- execution ---------------------------------------------------------

    def _execute(self, scan: Scan) -> dict:
        log = scan_logger(__name__, scan_id=str(scan.id), target=scan.target_value)
        target = parse_target(scan.target_value)
        limits = CollectionLimits.from_settings()
        scan.limits = limits.as_dict()
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.now(UTC)
        self.db.commit()
        log.info("scan_started", extra={"mode": scan.mode})

        self._credentials = self._load_owner_credentials(scan)

        requested = scan.requested_modules or self.registry.recommended_ids()
        waves = self.registry.execution_waves(requested)

        module_rows: dict[str, ScanModule] = self._create_module_rows(scan, waves)
        self.db.commit()

        outputs: dict[str, ModuleOutput] = {}
        sequence = [0]
        total_modules = sum(len(wave) for wave in waves) or 1
        completed_count = 0
        module_failures = 0
        scan_id = scan.id
        # Wall-clock budget for the whole scan. Per-module budgets bound
        # each wave, but this is the backstop that keeps a scan from
        # running into Celery's hard kill: remaining modules are skipped
        # honestly and the scan finalises as partial instead.
        scan_deadline = time.monotonic() + float(settings.SCAN_SOFT_TIME_LIMIT)

        for wave in waves:
            if self._cancelled_fresh(scan_id):
                for module in wave:
                    self._mark_skipped(module_rows[module.id], "cancelled")
                continue

            if time.monotonic() >= scan_deadline:
                reason = (
                    f"Scan exceeded its {settings.SCAN_SOFT_TIME_LIMIT:.0f}s time "
                    "budget; remaining modules were skipped."
                )
                logger.warning("scan_time_budget_exceeded", extra={"scan_id": str(scan_id)})
                for module in wave:
                    self._mark_skipped(module_rows[module.id], reason)
                module_failures += len(wave)
                completed_count += len(wave)
                continue

            # Mark this wave genuinely running now that it starts.
            wave_started_at = datetime.now(UTC)
            for module in wave:
                row = module_rows[module.id]
                row.status = ModuleStatus.RUNNING.value
                row.started_at = wave_started_at
            try:
                self.db.commit()
            except Exception:  # noqa: BLE001 - progress is best-effort
                self.db.rollback()

            # `ModuleContext` is shared across every thread in this wave, so
            # nothing it exposes to module code may touch `self.db` -
            # SQLAlchemy sessions are not thread-safe, and modules run
            # concurrently by design (see `_run_wave`). Cancellation checks
            # and log events instead go through thread-safe, session-free
            # paths: a short-lived connection for the former, an in-memory
            # queue drained by the main thread for the latter.
            log_queue: queue.Queue = queue.Queue()
            ctx = ModuleContext(
                scan_id=str(scan.id),
                target=target,
                mode=scan.scan_mode,
                limits=limits,
                upstream=dict(outputs),
                cancel_check=lambda: self._cancelled_fresh(scan_id),
                log_sink=lambda q=log_queue, **kw: q.put(kw),
            )

            wave_results = self._run_wave(wave, ctx)
            self._drain_log_queue(scan, sequence, log_queue)

            for module_id, output, duration in wave_results:
                outputs[module_id] = output
                row = module_rows[module_id]
                self._record_module_result(row, output, duration)
                if not output.success:
                    module_failures += 1
                completed_count += 1

            scan.progress = int(round((completed_count / total_modules) * 100))
            try:
                self.db.commit()
            except Exception as exc:  # noqa: BLE001 - progress is best-effort
                # A failed progress commit used to silently roll back the
                # module rows recorded just above, leaving a whole wave of
                # modules stuck at "running" in every report while the scan
                # itself completed. Log loudly and re-record the rows so the
                # failure is visible instead of silent.
                logger.exception(
                    "wave_progress_commit_failed",
                    extra={"scan_id": str(scan.id), "error": str(exc)[:300]},
                )
                self.db.rollback()
                for module_id, output, duration in wave_results:
                    try:
                        self._record_module_result(module_rows[module_id], output, duration)
                    except Exception:
                        logger.exception(
                            "module_row_rerecord_failed",
                            extra={"scan_id": str(scan.id), "module_id": module_id},
                        )
                try:
                    self.db.commit()
                except Exception:
                    logger.exception(
                        "wave_rerecord_commit_failed",
                        extra={"scan_id": str(scan.id)},
                    )
                    self.db.rollback()
            log.info(
                "wave_completed",
                extra={"progress": scan.progress, "wave_size": len(wave)},
            )

        self._finalize(scan, outputs, module_rows, module_failures, total_modules)
        log.info(
            "scan_completed",
            extra={"status": scan.status, "duration": scan.duration},
        )
        return {
            "success": True,
            "scan_id": str(scan.id),
            "status": scan.status,
            "duration": scan.duration,
        }

    def _run_wave(
        self, wave: list, ctx: ModuleContext
    ) -> list[tuple[str, ModuleOutput, float]]:
        """Run one wave, enforcing every module's declared time budget.

        Module `timeout` values used to be advisory: `future.result()` with
        no deadline meant a single wedged module (a DNS lookup with no
        timeout of its own, a provider that never answers) stalled the
        whole wave forever and the scan sat at 0% until someone killed
        the worker. Now an overrunning module is abandoned, recorded as
        failed with the reason, and the wave - and the scan - move on.
        The abandoned thread keeps running in the background (threads
        cannot be killed); its late output is discarded.
        """
        if len(wave) == 1:
            module = wave[0]
            budget = self._module_budget(module)
            started = time.monotonic()
            pool = ThreadPoolExecutor(max_workers=1)
            try:
                future = pool.submit(self._run_one, module, ctx)
                output = self._await_result(future, module, budget, started)
            finally:
                # Never block scan progress on an abandoned thread.
                pool.shutdown(wait=False, cancel_futures=True)
            return [(module.id, output, time.monotonic() - started)]

        results: list[tuple[str, ModuleOutput, float]] = []
        pool = ThreadPoolExecutor(max_workers=min(_WAVE_CONCURRENCY, len(wave)))
        try:
            meta = {pool.submit(self._run_one, module, ctx): (module, time.monotonic()) for module in wave}
            pending = set(meta)
            while pending:
                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                now = time.monotonic()
                for future in done:
                    module, started = meta[future]
                    results.append((module.id, self._await_result(future, module, self._module_budget(module), started), now - started))
                for future in list(pending):
                    module, started = meta[future]
                    budget = self._module_budget(module)
                    if now - started >= budget:
                        pending.discard(future)
                        future.cancel()
                        logger.warning(
                            "module_timeout",
                            extra={"module_id": module.id, "budget": budget, "scan_id": ctx.scan_id},
                        )
                        results.append(
                            (
                                module.id,
                                ModuleOutput(
                                    module_id=module.id,
                                    success=False,
                                    errors=[
                                        f"Module did not finish within its {budget:.0f}s time budget "
                                        "and was abandoned; the scan continued without it."
                                    ],
                                ),
                                now - started,
                            )
                        )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return results

    @staticmethod
    def _module_budget(module) -> float:
        declared = getattr(module, "timeout", None)
        try:
            budget = float(declared) if declared else 0.0
        except (TypeError, ValueError):
            budget = 0.0
        return budget if budget > 0 else float(settings.MODULE_TIME_LIMIT)

    @staticmethod
    def _await_result(future, module, budget: float, started: float) -> ModuleOutput:
        """Collect one module's result, honouring its time budget.

        Only `Exception` is converted to a failed output; `BaseException`
        (worker shutdown, Celery soft time limit) propagates so the task
        can finalise the scan instead of swallowing the signal.
        """
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        remaining = max(0.1, budget - (time.monotonic() - started))
        try:
            return future.result(timeout=remaining)
        except FuturesTimeoutError:
            logger.warning(
                "module_timeout",
                extra={"module_id": module.id, "budget": budget},
            )
            return ModuleOutput(
                module_id=module.id,
                success=False,
                errors=[
                    f"Module did not finish within its {budget:.0f}s time budget "
                    "and was abandoned; the scan continued without it."
                ],
            )
        except Exception as exc:  # noqa: BLE001 - the orchestrator must never die
            logger.exception("module_crashed", extra={"module_id": module.id})
            return ModuleOutput(
                module_id=module.id,
                success=False,
                errors=[f"{exc.__class__.__name__}: {str(exc)[:300]}"],
            )

    def abort_scan(self, scan_id: str | uuid.UUID, reason: str) -> None:
        """Finalise a scan that was interrupted outside the wave loop.

        Celery's soft time limit (or a worker shutdown) raises inside the
        task thread; without this the scan row and its module rows would
        sit at "running" forever. Every non-terminal module is marked
        failed with the reason and the scan closes as failed.

        The session is rolled back first: `abort_scan` is reached from
        `run_scan`'s `except BaseException` handler, so the session is
        usually in a failed state (the most common cause is the flush
        error this method exists to recover from). Any subsequent query on
        such a session raises `PendingRollbackError` and the scan stays
        "running" forever - the exact outcome this method prevents.
        """
        from sqlalchemy import select

        try:
            self.db.rollback()
        except Exception:  # noqa: BLE001 - best effort, keep going
            logger.warning("abort_rollback_failed", extra={"scan_id": str(scan_id)})

        sid = scan_id if isinstance(scan_id, uuid.UUID) else uuid.UUID(str(scan_id))
        scan = self.db.get(Scan, sid)
        if scan is None:
            return
        if scan.status in (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value):
            return
        terminal = {ModuleStatus.COMPLETED.value, ModuleStatus.FAILED.value, ModuleStatus.SKIPPED.value}
        rows = self.db.scalars(select(ScanModule).where(ScanModule.scan_id == sid)).all()
        for row in rows:
            if row.status not in terminal:
                row.status = ModuleStatus.FAILED.value
                row.error = reason[:2000]
                row.completed_at = datetime.now(UTC)
        scan.status = ScanStatus.FAILED.value
        scan.error = reason[:2000]
        scan.completed_at = datetime.now(UTC)
        scan.progress = 100
        self.db.commit()
        logger.warning("scan_aborted", extra={"scan_id": str(sid), "reason": reason[:120]})

    def _load_owner_credentials(self, scan: Scan) -> dict[str, dict[str, str]]:
        """Decrypt the scan owner's stored provider keys, best-effort.

        A failure here (missing table on an un-migrated DB, decryption
        error) must never abort a scan - the platform runs on its
        environment defaults, exactly as it did before accounts existed.
        """
        if getattr(scan, "user_id", None) is None:
            return {}
        try:
            from app.services.accounts import CredentialService

            return CredentialService(self.db).override_mapping(scan.user_id)
        except Exception:  # noqa: BLE001 - scans never depend on stored keys
            logger.warning("owner_credentials_unavailable", extra={"scan_id": str(scan.id)})
            return {}

    def _run_one(self, module, ctx: ModuleContext) -> ModuleOutput:
        # ContextVars do not propagate into ThreadPoolExecutor workers, so
        # the running account's keys are installed here, in the worker
        # thread that actually calls the providers.
        from app.core.credentials import reset_override, set_override

        token = set_override(self._credentials or None)
        try:
            return module.run(ctx)
        except CancelledError:
            return ModuleOutput(module_id=module.id, success=True, skip_reason="Scan cancelled by user.")
        except Exception as exc:  # noqa: BLE001 - the orchestrator must never die
            logger.exception("module_crashed", extra={"module_id": module.id})
            return ModuleOutput(
                module_id=module.id,
                success=False,
                errors=[f"{exc.__class__.__name__}: {str(exc)[:300]}"],
            )
        finally:
            reset_override(token)

    # -- module bookkeeping ------------------------------------------------

    def _create_module_rows(self, scan: Scan, waves: list[list]) -> dict[str, ScanModule]:
        rows: dict[str, ScanModule] = {}
        sequence = 0
        for wave in waves:
            for module in wave:
                sequence += 1
                row = ScanModule(
                    scan_id=scan.id,
                    module_id=module.id,
                    display_name=module.name,
                    category=module.category.value,
                    sequence=sequence,
                    # Queued until its wave actually starts: the UI used to
                    # show every module as RUNNING from second zero, which
                    # is why a stalled scan looked busy instead of stuck.
                    status=ModuleStatus.QUEUED.value,
                )
                self.db.add(row)
                rows[module.id] = row
        self.db.flush()
        return rows

    def _record_module_result(self, row: ScanModule, output: ModuleOutput, duration: float) -> None:
        row.completed_at = datetime.now(UTC)
        row.duration = round(duration, 3)
        row.result_count = output.record_count
        row.finding_count = len(output.findings)
        row.metrics = _jsonable(output.metrics)
        row.data = _jsonable(output.data)
        if output.skip_reason is not None:
            row.status = ModuleStatus.SKIPPED.value
            row.skip_reason = output.skip_reason
        elif output.success:
            row.status = ModuleStatus.COMPLETED.value
        else:
            row.status = ModuleStatus.FAILED.value
            row.error = "; ".join(output.errors)[:2000]

    def _mark_skipped(self, row: ScanModule, reason: str) -> None:
        row.status = ModuleStatus.SKIPPED.value
        row.skip_reason = reason
        row.completed_at = datetime.now(UTC)

    def _drain_log_queue(self, scan: Scan, sequence: list[int], log_queue: queue.Queue) -> None:
        """Write every log line a wave's modules queued, from the main thread.

        Called once the wave's `ThreadPoolExecutor` has fully joined (see
        `_run_wave`), so nothing is still enqueuing - draining here is
        single-threaded and safe to run against `self.db` directly.
        """
        pending: list[ScanLog] = []
        while True:
            try:
                kwargs = log_queue.get_nowait()
            except queue.Empty:
                break
            sequence[0] += 1
            pending.append(
                ScanLog(
                    scan_id=scan.id,
                    sequence=sequence[0],
                    timestamp=datetime.now(UTC),
                    level=kwargs.get("level", "INFO"),
                    module_id=kwargs.get("module_id"),
                    event=kwargs.get("event", ""),
                    message=(kwargs.get("message") or "")[:2000],
                    context={
                        k: v
                        for k, v in (kwargs.get("context") or {}).items()
                        if isinstance(v, (str, int, float, bool)) or v is None
                    },
                )
            )
        if not pending:
            return
        try:
            self.db.add_all(pending)
            self.db.flush()
        except Exception:  # noqa: BLE001 - a logging failure must not fail the scan
            self.db.rollback()

    def _cancelled_fresh(self, scan_id: uuid.UUID) -> bool:
        """Check cancellation on a short-lived connection, off `self.db`.

        Called from worker threads during concurrent module execution
        (via `ModuleContext.cancel_check`), so it must never touch the
        orchestrator's own session. A throwaway session per check is cheap
        relative to the module work it gates.
        """
        from app.database.session import SessionLocal

        probe = SessionLocal()
        try:
            value = probe.scalar(
                __import__("sqlalchemy").select(Scan.cancel_requested).where(Scan.id == scan_id)
            )
            return bool(value)
        except Exception:  # noqa: BLE001 - a failed cancellation check must not abort the scan
            return False
        finally:
            probe.close()

    # -- finalisation --------------------------------------------------------

    def _reconcile_module_rows(
        self,
        scan: Scan,
        outputs: dict[str, ModuleOutput],
        module_rows: dict[str, ScanModule],
    ) -> None:
        """Guarantee no module row is left non-terminal on a finished scan.

        Belt and braces behind the per-wave recording: whatever went wrong
        with persistence mid-scan (a rolled-back commit, a crashed worker
        that was retried), a finalized scan must never show a module as
        "running". Rows with in-memory output are recorded from that
        output; rows with no output at all are marked failed with an
        explicit reason instead of a silent stuck state.
        """
        terminal = {
            ModuleStatus.COMPLETED.value,
            ModuleStatus.FAILED.value,
            ModuleStatus.SKIPPED.value,
        }
        for module_id, row in module_rows.items():
            if row.status in terminal:
                continue
            output = outputs.get(module_id)
            if output is not None:
                self._record_module_result(row, output, 0.0)
                logger.warning(
                    "module_row_reconciled",
                    extra={"scan_id": str(scan.id), "module_id": module_id, "status": row.status},
                )
            else:
                row.status = ModuleStatus.FAILED.value
                row.error = (
                    "Module did not produce a result during the scan; "
                    "it may have been interrupted before it ran."
                )
                row.completed_at = datetime.now(UTC)
                logger.warning(
                    "module_row_missing_output",
                    extra={"scan_id": str(scan.id), "module_id": module_id},
                )

    def _finalize(
        self,
        scan: Scan,
        outputs: dict[str, ModuleOutput],
        module_rows: dict[str, ScanModule],
        module_failures: int,
        total_modules: int,
    ) -> None:
        self._reconcile_module_rows(scan, outputs, module_rows)
        target = parse_target(scan.target_value)
        graph = build_graph(target, outputs)
        id_map = persist_graph(self.db, scan, graph)
        persist_observations(self.db, scan, outputs, id_map)
        extra = persist_intelligence(self.db, scan, outputs, id_map)
        findings = persist_findings(self.db, scan, outputs, id_map)
        scored = score_and_finalize_findings(self.db, scan, findings)

        cve_results = correlate(extra["technologies"])
        persist_cves(self.db, scan, cve_results)

        exposure = compute_exposure(scored)
        scan.exposure_score = exposure.score
        scan.exposure_band = exposure.band

        provider_status: dict[str, dict] = {}
        for output in outputs.values():
            for status in output.providers:
                provider_status[status.provider] = status.as_dict()
        scan.provider_status = provider_status

        scan.summary = _build_summary(graph, findings, exposure, outputs)

        if scan.cancel_requested:
            scan.status = ScanStatus.CANCELLED.value
        elif module_failures == 0:
            scan.status = ScanStatus.COMPLETED.value
        elif module_failures < total_modules:
            scan.status = ScanStatus.PARTIAL.value
        else:
            scan.status = ScanStatus.FAILED.value

        scan.completed_at = datetime.now(UTC)
        if scan.started_at is not None:
            completed = scan.completed_at
            started = scan.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            scan.duration = (completed - started).total_seconds()
        scan.progress = 100
        self.db.commit()


def _build_summary(graph, findings, exposure, outputs: dict[str, ModuleOutput]) -> dict:
    from app.models.enums import AssetType

    asset_counts: dict[str, int] = {}
    for asset in graph.asset_list():
        asset_counts[asset.asset_type.value] = asset_counts.get(asset.asset_type.value, 0) + 1

    in_scope_counts: dict[str, int] = {}
    for asset in graph.asset_list():
        if asset.in_scope:
            in_scope_counts[asset.asset_type.value] = in_scope_counts.get(asset.asset_type.value, 0) + 1
    assets_in_scope = sum(in_scope_counts.values())

    return {
        "assets_total": len(graph.assets),
        "assets_in_scope": assets_in_scope,
        "assets_out_of_scope": len(graph.assets) - assets_in_scope,
        "categories_in_scope": len(in_scope_counts),
        "in_scope_counts": in_scope_counts,
        "relationships_total": len(graph.edges),
        "asset_counts": asset_counts,
        "domains": asset_counts.get(AssetType.DOMAIN.value, 0) + asset_counts.get(AssetType.SUBDOMAIN.value, 0),
        "subdomains": asset_counts.get(AssetType.SUBDOMAIN.value, 0),
        "ips": asset_counts.get(AssetType.IP.value, 0),
        "urls": sum(len(o.urls) for o in outputs.values()),
        "apis": sum(len(o.api_endpoints) for o in outputs.values()),
        "javascript_files": sum(len(o.javascript) for o in outputs.values()),
        "certificates": sum(len(o.certificates) for o in outputs.values()),
        "technologies": len({t.normalized_name for o in outputs.values() for t in o.technologies}),
        "findings_total": len(findings),
        "findings_by_severity": exposure.severity_counts,
        "exposure_score": exposure.score,
        "exposure_band": exposure.band,
        "modules_total": len(outputs),
        "modules_completed": sum(1 for o in outputs.values() if o.success and not o.skip_reason),
        "modules_skipped": sum(1 for o in outputs.values() if o.skip_reason),
        "modules_failed": sum(1 for o in outputs.values() if not o.success and not o.skip_reason),
        "collection_health": _collection_health_text(outputs),
    }


def _collection_health_text(outputs: dict) -> str:
    """One-line plain-English collection health for the JSON summary."""
    skipped = [o for o in outputs.values() if o.skip_reason]
    failed = [o for o in outputs.values() if not o.success and not o.skip_reason]
    if not skipped and not failed:
        return "All requested collection modules completed successfully."
    parts = []
    if skipped:
        parts.append(f"{len(skipped)} skipped")
    if failed:
        parts.append(f"{len(failed)} failed")
    sentence = f"{' and '.join(parts)} during collection"
    reasons: list[str] = []
    for o in failed:
        err = (o.errors[-1] if o.errors else "").strip().split("\n")[0]
        if err:
            reasons.append(f"{o.module_id}: {err[:140]}")
    for o in skipped:
        if o.skip_reason:
            reasons.append(f"{o.module_id}: {o.skip_reason[:140]}")
    seen: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    if seen:
        shown = "; ".join(seen[:4])
        if len(seen) > 4:
            shown += f"; and {len(seen) - 4} more"
        sentence += f" ({shown})"
    return sentence + "."


def run_scan(scan_id: str) -> dict:
    """Celery-callable entry point - opens and owns its own session."""
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        return ScanOrchestrator(db).run(scan_id)
    except BaseException as exc:  # noqa: BLE001 - the scan row must never stay "running"
        # Celery's soft time limit, worker shutdown, KeyboardInterrupt:
        # finalise the scan as failed so the UI shows the truth instead of
        # a scan stuck at 0% forever.
        try:
            ScanOrchestrator(db).abort_scan(scan_id, f"Scan interrupted: {exc.__class__.__name__}: {str(exc)[:300]}")
        except Exception:
            logger.exception("scan_abort_failed", extra={"scan_id": str(scan_id)})
        raise
    finally:
        db.close()
