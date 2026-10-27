"""Scan-to-scan comparison.

The brief is explicit: no scheduled monitoring, but historical comparison
between two *manual* scans is a first-class feature. This diffs two
completed scans' asset sets by `(asset_type, normalized_value)` - the same
identity key correlation uses - so an asset that persisted across scans is
recognised as unchanged rather than reported as both removed and re-added.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import ChangeKind
from app.models.graph import Asset
from app.models.intelligence import Technology
from app.models.risk import Finding


@dataclass(slots=True)
class ChangeEntry:
    kind: ChangeKind
    asset_type: str
    value: str
    detail: dict | None = None


@dataclass(slots=True)
class ScanDiff:
    scan_a_id: str
    scan_b_id: str
    added: list[ChangeEntry] = field(default_factory=list)
    removed: list[ChangeEntry] = field(default_factory=list)
    changed: list[ChangeEntry] = field(default_factory=list)

    def as_dict(self) -> dict:
        def render(entries: list[ChangeEntry]) -> list[dict]:
            return [
                {"asset_type": e.asset_type, "value": e.value, "detail": e.detail}
                for e in entries
            ]

        return {
            "scan_a": self.scan_a_id,
            "scan_b": self.scan_b_id,
            "added": render(self.added),
            "removed": render(self.removed),
            "changed": render(self.changed),
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
            },
        }


def compare_scans(db: Session, scan_a_id: uuid.UUID, scan_b_id: uuid.UUID) -> ScanDiff:
    """Compare scan A (earlier) against scan B (later)."""
    assets_a = {
        (a.asset_type, a.normalized_value): a
        for a in db.scalars(select(Asset).where(Asset.scan_id == scan_a_id)).all()
    }
    assets_b = {
        (a.asset_type, a.normalized_value): a
        for a in db.scalars(select(Asset).where(Asset.scan_id == scan_b_id)).all()
    }

    diff = ScanDiff(scan_a_id=str(scan_a_id), scan_b_id=str(scan_b_id))

    for key, asset in assets_b.items():
        if key not in assets_a:
            diff.added.append(ChangeEntry(ChangeKind.ADDED, asset.asset_type, asset.value))
    for key, asset in assets_a.items():
        if key not in assets_b:
            diff.removed.append(ChangeEntry(ChangeKind.REMOVED, asset.asset_type, asset.value))

    tech_a = {(t.normalized_name, t.host): t for t in db.scalars(select(Technology).where(Technology.scan_id == scan_a_id)).all()}
    tech_b = {(t.normalized_name, t.host): t for t in db.scalars(select(Technology).where(Technology.scan_id == scan_b_id)).all()}
    for key, tech in tech_b.items():
        prior = tech_a.get(key)
        if prior is not None and prior.version != tech.version:
            diff.changed.append(
                ChangeEntry(
                    ChangeKind.CHANGED,
                    "technology",
                    tech.name,
                    {"from_version": prior.version, "to_version": tech.version},
                )
            )
    for key, tech in tech_a.items():
        if key not in tech_b:
            diff.removed.append(ChangeEntry(ChangeKind.REMOVED, "technology", tech.name))
    for key, tech in tech_b.items():
        if key not in tech_a:
            diff.added.append(ChangeEntry(ChangeKind.ADDED, "technology", tech.name))

    findings_a = {f.fingerprint for f in db.scalars(select(Finding).where(Finding.scan_id == scan_a_id)).all()}
    findings_b = list(db.scalars(select(Finding).where(Finding.scan_id == scan_b_id)).all())
    for finding in findings_b:
        if finding.fingerprint not in findings_a:
            diff.added.append(ChangeEntry(ChangeKind.ADDED, "finding", finding.title))

    return diff
