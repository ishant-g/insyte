"""Assembles a `ReportData` snapshot from a completed scan.

This is the single source of truth for "what goes in a report" - the PDF,
Markdown and JSON generators all render the same `ReportData` object, so
the three formats can never drift into disagreeing about a scan's own
numbers. Building it is a read-only, side-effect-free pass over the
database; nothing here mutates a row.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.graph import Asset, AssetRelationship
from app.models.intelligence import (
    ApiEndpoint,
    Certificate,
    DnsRecord,
    HistoricalEvent,
    JavaScriptArtifact,
    Technology,
    Url,
)
from app.models.risk import Cve, Finding, IndexedExposure
from app.models.scan import Scan, ScanModule


def _is_disclaimer(text: str) -> bool:
    """True when a recommendation is a limitation statement, not an action."""
    lowered = text.lower()
    return lowered.startswith("this is informational") or "cannot prove" in lowered


@dataclass(slots=True)
class ReportData:
    scan: Scan
    generated_at: datetime
    assets: list[Asset]
    relationships: list[AssetRelationship]
    findings: list[Finding]
    technologies: list[Technology]
    cves: list[Cve]
    urls: list[Url]
    api_endpoints: list[ApiEndpoint]
    javascript: list[JavaScriptArtifact]
    certificates: list[Certificate]
    dns_records: list[DnsRecord]
    historical_events: list[HistoricalEvent]
    indexed_exposures: list[IndexedExposure]
    modules: list[ScanModule]
    provider_status: dict[str, Any] = field(default_factory=dict)

    @property
    def target(self) -> str:
        return self.scan.target_value

    @property
    def filename_stub(self) -> str:
        from app.core.target import parse_target

        try:
            slug = parse_target(self.scan.target_value).slug
        except Exception:  # noqa: BLE001 - a stored value should always parse, but never fail a report over it
            slug = "target"
        # Stamp target, scan id and timestamp into the name so repeated
        # scans of the same target never collide as `insyte-report.pdf`,
        # `insyte-report (1).pdf`, ... with no way to tell them apart.
        scan_short = str(self.scan.id)[:8] if self.scan.id else "noscan"
        stamp = self.scan.created_at.strftime("%Y%m%d-%H%M") if self.scan.created_at else "undated"
        return f"insyte-{slug}-{scan_short}-{stamp}"

    def findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def severity_order(self) -> list[str]:
        return ["critical", "high", "medium", "low", "informational"]

    @property
    def assets_in_scope(self) -> int:
        return len([a for a in self.assets if a.in_scope])

    @property
    def in_scope_categories(self) -> int:
        return len({a.asset_type for a in self.assets if a.in_scope})

    @property
    def is_passive(self) -> bool:
        """True when the scan ran in passive mode (value or enum)."""
        mode = self.scan.mode
        value = getattr(mode, "value", mode)
        return (value or "") == "passive"

    def scoped_assets(self, types: set[str]) -> tuple[list[Asset], list[str]]:
        """Split assets of the given types into in-scope rows plus one
        collapsed line per out-of-scope group (grouped by asset type and
        primary source). The JSON export still carries every asset; this
        only keeps the PDF/Markdown body readable."""
        in_scope_rows = [a for a in self.assets if a.asset_type in types and a.in_scope]
        groups: dict[tuple[str, str], int] = {}
        for a in self.assets:
            if a.asset_type in types and not a.in_scope:
                primary = str(a.sources[0]) if a.sources else "unknown"
                key = (a.asset_type, primary)
                groups[key] = groups.get(key, 0) + 1
        lines = []
        for (asset_type, source), count in sorted(groups.items(), key=lambda kv: -kv[1]):
            noun = f"{asset_type}s" if count != 1 else asset_type
            lines.append(
                f"{count} unrelated {noun} (discovery via {source}) omitted - "
                "see JSON export for the full list."
            )
        return in_scope_rows, lines

    def cves_by_exploitability(self) -> list[Cve]:
        """CVEs in triage order: exploited in the wild first, then EPSS
        likelihood, then CVSS. Rows with no scores sink to the end."""
        def key(c: Cve):
            epss = c.epss_score if c.epss_score is not None else -1.0
            cvss = c.cvss_score if c.cvss_score is not None else -1.0
            return (not c.known_exploited, -epss, -cvss, c.cve_id)

        return sorted(self.cves, key=key)

    def recommendations(self) -> list[str]:
        """Deduplicated, severity-ordered recommendation list.

        Informational disclaimers ("this is informational...", "cannot
        prove...") describe a limitation, not an action - they stay in the
        Findings section but never enter the numbered action list.
        """
        seen: set[str] = set()
        ordered: list[str] = []
        for severity in self.severity_order:
            for finding in self.findings_by_severity(severity):
                rec = finding.recommendation
                if not rec or rec in seen:
                    continue
                if severity == "informational" and _is_disclaimer(rec):
                    continue
                seen.add(rec)
                ordered.append(rec)
        return ordered

    def module_data(self, module_id: str) -> dict[str, Any]:
        """A module's own structured output - see `ScanModule.data`.

        Returns `{}` for a module that did not run (skipped/failed) or was
        never selected, so callers can do `report.module_data("x").get(...)`
        without a None-check at every call site.
        """
        for module in self.modules:
            if module.module_id == module_id:
                return module.data or {}
        return {}


def build_report_data(db: Session, scan_id: uuid.UUID) -> ReportData:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"scan not found: {scan_id}")

    def rows(model, order_by=None):
        query = select(model).where(model.scan_id == scan_id)
        if order_by is not None:
            query = query.order_by(order_by)
        return list(db.scalars(query).all())

    return ReportData(
        scan=scan,
        generated_at=datetime.now(UTC),
        assets=rows(Asset, Asset.asset_type),
        relationships=rows(AssetRelationship),
        findings=rows(Finding, Finding.risk_score.desc()),
        technologies=rows(Technology, Technology.confidence.desc()),
        cves=rows(Cve, Cve.cvss_score.desc().nullslast()),
        urls=rows(Url, Url.host),
        api_endpoints=rows(ApiEndpoint, ApiEndpoint.confidence.desc()),
        javascript=rows(JavaScriptArtifact, JavaScriptArtifact.url),
        certificates=rows(Certificate),
        dns_records=rows(DnsRecord, DnsRecord.record_type),
        historical_events=rows(HistoricalEvent, HistoricalEvent.first_seen.desc().nullslast()),
        indexed_exposures=rows(IndexedExposure, IndexedExposure.severity.desc()),
        modules=list(scan.modules),
        provider_status=scan.provider_status or {},
    )
