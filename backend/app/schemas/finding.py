"""Finding, technology, CVE and evidence schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID | None
    module_id: str
    category: str
    severity: str
    risk_score: int
    priority: str | None
    confidence: int
    confidence_band: str
    exposure: str
    title: str
    description: str | None
    recommendation: str | None
    location: str | None
    sources: list[Any]
    reference_links: list[Any]
    cve_ids: list[Any]
    status: str
    created_at: datetime


class FindingDetailRead(FindingRead):
    evidence: dict[str, Any]


class TechnologyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: str | None
    version_confidence: int
    category: str | None
    vendor: str | None
    host: str | None
    confidence: int
    sources: list[Any]


class CveRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str
    technology_name: str
    detected_version: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    known_exploited: bool
    match_confidence: int
    definitive: bool
    description: str | None
    reference_links: list[Any]


class ExposureSummary(BaseModel):
    score: int
    band: str
    severity_counts: dict[str, int]
    finding_count: int
