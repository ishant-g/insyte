"""Scan and ScanModule models - the scan state machine's storage."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import (
    Base,
    JSONBType,
    TimestampMixin,
    UUIDPrimaryKey,
    UUIDType,
)
from app.models.enums import ModuleStatus, ScanMode, ScanStatus

if TYPE_CHECKING:
    from app.models.graph import Asset, AssetRelationship, Observation
    from app.models.intelligence import (
        ApiEndpoint,
        Artifact,
        Certificate,
        DnsRecord,
        HistoricalEvent,
        JavaScriptArtifact,
        Technology,
        Url,
    )
    from app.models.report import Report
    from app.models.risk import Cve, Finding
    from app.models.target import Project, Target


class Scan(Base, UUIDPrimaryKey, TimestampMixin):
    """One on-demand intelligence run against one target.

    There is intentionally no schedule, recurrence or monitoring column
    here. Insyte is an on-demand platform; the historical-comparison
    feature works by diffing two manual scans, not by polling.
    """

    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: Nullable on purpose - a scan does not require a project.
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType,
        ForeignKey("projects.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    #: The account that launched the scan. Nullable so historical/seed
    #: scans created before accounts existed remain valid; new scans always
    #: carry the authenticated user and listings are filtered by it.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    #: Denormalised copy of the target value. Reports, filenames and list
    #: views all need it, and a scan's target must remain readable even if
    #: the Target row is later renormalised.
    target_value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)

    mode: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ScanMode.PASSIVE.value, index=True
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScanStatus.QUEUED.value, index=True
    )
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Module ids the user asked for. Empty list means "full intelligence".
    requested_modules: Mapped[list[Any]] = mapped_column(
        JSONBType, nullable=False, default=list
    )

    #: Cooperative cancellation flag. The orchestrator checks it between
    #: modules; a hard Celery revoke would leave the scan row inconsistent.
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: Insyte prioritisation score, 0-100. Explicitly NOT a CVSS score -
    #: see services/risk/exposure.py for the distinction.
    exposure_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exposure_band: Mapped[str | None] = mapped_column(String(16), nullable=True)

    #: Cached roll-up counts so list views need one query, not fifteen.
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    #: Per-provider availability, e.g. {"shodan": {"available": false, ...}}.
    provider_status: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    #: Effective collection limits for this run, recorded for reproducibility.
    limits: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -- relationships ---------------------------------------------------

    target: Mapped[Target] = relationship(back_populates="scans")
    project: Mapped[Project | None] = relationship(back_populates="scans")

    modules: Mapped[list[ScanModule]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScanModule.sequence",
    )
    logs: Mapped[list[ScanLog]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    relationships: Mapped[list[AssetRelationship]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    observations: Mapped[list[Observation]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    cves: Mapped[list[Cve]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    technologies: Mapped[list[Technology]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    certificates: Mapped[list[Certificate]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    dns_records: Mapped[list[DnsRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    urls: Mapped[list[Url]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    api_endpoints: Mapped[list[ApiEndpoint]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    javascript_artifacts: Mapped[list[JavaScriptArtifact]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    historical_events: Mapped[list[HistoricalEvent]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        Index("ix_scans_target_created", "target_id", "created_at"),
        Index("ix_scans_status_created", "status", "created_at"),
    )

    # -- helpers ---------------------------------------------------------

    @property
    def scan_mode(self) -> ScanMode:
        return ScanMode(self.mode)

    @property
    def scan_status(self) -> ScanStatus:
        return ScanStatus(self.status)

    @property
    def is_terminal(self) -> bool:
        return ScanStatus(self.status).is_terminal

    @property
    def web_surface_enabled(self) -> bool:
        return self.mode == ScanMode.WEB_SURFACE.value


class ScanModule(Base, UUIDPrimaryKey):
    """Per-module execution record - the real source of scan progress.

    The old implementation derived progress from `index / total` inside the
    engine loop, which meant the UI showed motion whether or not anything
    had actually succeeded. Progress is now computed from these rows, so
    "8 of 19 modules completed, 1 skipped" is a fact rather than an
    animation.
    """

    __tablename__ = "scan_modules"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    module_id: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ModuleStatus.QUEUED.value, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: Number of normalized observations the module produced.
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Why the module did not run. Shown verbatim in the UI, so it must be
    #: user-readable: "API key not configured", not a stack trace.
    skip_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Per-module telemetry: provider calls, cache hits, bytes fetched.
    metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    #: The module's own structured summary - RDAP registration detail,
    #: SPF/DMARC posture, robots.txt structure, corporate-intelligence
    #: candidates, harvested-email/breach results, discovered social
    #: profiles, dork hits, and anything else a module puts in
    #: `ModuleOutput.data` that doesn't fit the typed asset/finding/
    #: technology tables. Without this column that data existed only for
    #: the duration of one orchestrator run - computed, used for
    #: `ctx.data_of()` cross-module reads, then thrown away - which meant
    #: it never reached the API, a report, or the UI. This is where it
    #: survives past the scan.
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    scan: Mapped[Scan] = relationship(back_populates="modules")

    __table_args__ = (
        Index("uq_scan_modules_scan_module", "scan_id", "module_id", unique=True),
    )

    @property
    def module_status(self) -> ModuleStatus:
        return ModuleStatus(self.status)


class ScanLog(Base, UUIDPrimaryKey):
    """A structured log line belonging to a scan.

    Persisted in the database rather than scraped from a log file: the
    worker that produces these runs in a different process (and in Docker,
    a different container) from the API that serves them, so a file tail is
    not merely ugly, it does not work.
    """

    __tablename__ = "scan_logs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    level: Mapped[str] = mapped_column(String(10), nullable=False, default="INFO")
    module_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    scan: Mapped[Scan] = relationship(back_populates="logs")

    __table_args__ = (
        Index("ix_scan_logs_scan_sequence", "scan_id", "sequence"),
    )
