"""Scan request/response schemas.

Every schema here is deliberately narrow about what a client can set.
There is no `ScanUpdate` accepting `status`/`progress`/`exposure_score` -
the audit flagged the predecessor's `PUT /scans/{id}` as a mass-assignment
hole (any client could set a scan's own engine-owned state), and the fix is
structural: those fields simply have no writable schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.target import TargetError, parse_target
from app.models.enums import ScanMode


class ScanCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    target: str = Field(..., min_length=1, max_length=2048)
    mode: ScanMode = Field(
        default=ScanMode.PASSIVE,
        description=(
            "Passive Intelligence: third-party and public records, plus a "
            "small number of light, read-only direct requests to the target "
            "itself (homepage, robots.txt, sitemap.xml, .well-known "
            "resources - one GET per resource, never a crawl, no forms, no "
            "brute forcing, no port scanning). Web Surface Collection adds an "
            "opt-in crawl of publicly linked pages and the JavaScript/CSS "
            "they reference."
        ),
    )
    #: Empty = "Recommended" (every recommended module). Explicit module
    #: ids for a custom selection; "__all__" as the sole entry means every
    #: module the target/mode combination supports.
    modules: list[str] = Field(default_factory=list)
    project_id: uuid.UUID | None = None

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str) -> str:
        # Validated here (client-facing shape) AND re-validated in the
        # service layer before the scan is queued - frontend/schema
        # validation is a UX convenience, never the trust boundary.
        try:
            parse_target(value)
        except TargetError as exc:
            raise ValueError(str(exc)) from exc
        return value


class ScanModuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    module_id: str
    display_name: str
    category: str
    sequence: int
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    duration: float | None
    result_count: int
    finding_count: int
    skip_reason: str | None
    error: str | None
    #: The module's own structured summary (RDAP registration, SPF/DMARC
    #: posture, robots.txt structure, corporate/breach/social-footprint
    #: results, dork hits, ...) - see `models.scan.ScanModule.data`.
    data: dict[str, Any] = Field(default_factory=dict)


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_value: str
    target_type: str
    mode: str
    status: str
    progress: int
    project_id: uuid.UUID | None
    queued_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    duration: float | None
    exposure_score: int | None
    exposure_band: str | None
    summary: dict[str, Any]
    provider_status: dict[str, Any]
    limits: dict[str, Any]
    error: str | None
    #: Creation-time notices: unknown module ids that were ignored, modules
    #: skipped for mode/target mismatch, and modules running with degraded
    #: input because a prerequisite was deselected. Empty for scans read
    #: back later - warnings describe the request, not the scan.
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime


class ScanDetailRead(ScanRead):
    modules: list[ScanModuleRead] = Field(default_factory=list)


class ScanListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_value: str
    target_type: str
    mode: str
    status: str
    progress: int
    exposure_score: int | None
    exposure_band: str | None
    created_at: datetime
    completed_at: datetime | None


class ScanLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    timestamp: datetime
    level: str
    module_id: str | None
    event: str
    message: str
    context: dict[str, Any]


class ScanProgressRead(BaseModel):
    status: str
    progress: int
    modules: list[ScanModuleRead]
    exposure_score: int | None
    exposure_band: str | None
