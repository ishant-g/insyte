"""Findings, CVE intelligence and indexed exposures."""

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
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import (
    Base,
    JSONBType,
    UUIDPrimaryKey,
    UUIDType,
    utcnow,
)
from app.models.enums import (
    ConfidenceBand,
    ExposureLevel,
    FindingStatus,
    Severity,
)

if TYPE_CHECKING:
    from app.models.graph import Asset
    from app.models.scan import Scan


class Finding(Base, UUIDPrimaryKey):
    """A security-relevant observation with a severity and a recommendation.

    Two scores live side by side and must never be conflated:

    * `severity` / `risk_score` - how much this matters.
    * `confidence` - how sure Insyte is that it is real.

    A missing security header is high-confidence and low-severity; a
    suspected credential in a minified bundle may be high-severity and only
    medium-confidence. Collapsing them into one number is how recon tools
    end up shouting about nothing.
    """

    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: The asset this finding is about, when it is about one.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    module_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(48), nullable=False, index=True)

    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.INFORMATIONAL.value, index=True
    )
    #: Insyte prioritisation score 0-100. Not CVSS.
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority: Mapped[str | None] = mapped_column(String(4), nullable=True, index=True)

    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    confidence_band: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ConfidenceBand.MEDIUM.value
    )
    #: How reachable the thing described actually is.
    exposure: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ExposureLevel.INFERRED.value
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Where it is: a host, a URL, a JS file, a DNS name.
    location: Mapped[str | None] = mapped_column(Text, nullable=True)

    evidence: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)
    sources: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    #: External references (RFCs, vendor advisories, documentation).
    reference_links: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    cve_ids: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)

    #: Stable hash over (module, category, title, location) so the same
    #: issue found twice in one scan is one row, and so scan-to-scan diff
    #: can match findings across runs.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=FindingStatus.OPEN.value
    )
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    asset: Mapped[Asset | None] = relationship()

    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_category", "scan_id", "category"),
    )

    @property
    def severity_enum(self) -> Severity:
        return Severity(self.severity)


class Cve(Base, UUIDPrimaryKey):
    """A CVE correlated to a detected technology.

    `match_confidence` and `version_evidence` exist so the report can be
    honest. If the detected version was a guess, Insyte records the CVE as
    "potentially affected" rather than asserting the target is vulnerable -
    the alternative is a report full of confident nonsense.
    """

    __tablename__ = "cves"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technology_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("technologies.id", ondelete="SET NULL"), nullable=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    technology_name: Mapped[str] = mapped_column(String(150), nullable=False)
    detected_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_range: Mapped[str | None] = mapped_column(String(255), nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: CVSS is reproduced verbatim from the source and never recomputed.
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)

    #: Exploit Prediction Scoring System, when available.
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)

    #: CISA Known Exploited Vulnerabilities catalogue.
    known_exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: 0-100. Below the configured floor the row is reported as
    #: "potentially affected - version confidence insufficient".
    match_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    #: True when version evidence was too weak to assert the match.
    definitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    source_id: Mapped[str] = mapped_column(String(48), nullable=False, default="nvd")
    reference_links: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="cves")

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "cve_id", "technology_name", "detected_version",
            name="uq_cves_scan_cve_tech",
        ),
        Index("ix_cves_scan_score", "scan_id", "cvss_score"),
    )


class IndexedExposure(Base, UUIDPrimaryKey):
    """A potentially exposed artifact discovered through public indexes.

    This is intelligence discovery, not content discovery. Every row here
    came from a public index, an archive, a certificate, or an explicitly
    linked resource. Insyte does not guess paths and does not brute-force
    directories, so `retrievable` is only ever True when a Web Surface GET
    of an *already-referenced* URL actually returned the artifact.
    """

    __tablename__ = "indexed_exposures"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    #: e.g. "source_map", "env_reference", "backup_archive", "openapi".
    exposure_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: observed | indexed | historical | directly_retrievable
    observation_class: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    retrievable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.INFORMATIONAL.value, index=True
    )
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    sources: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "url_hash", "exposure_type", name="uq_indexed_exposures_scan_url"
        ),
        Index("ix_indexed_exposures_scan_type", "scan_id", "exposure_type"),
    )
