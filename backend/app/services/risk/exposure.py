"""The Insyte Exposure Score.

A single 0-100 number that answers "how much should I worry about this
scan?" - built from every finding's severity, confidence, exposure level,
the importance of the asset it sits on, and how many independent sources
corroborate it. This is deliberately **not** CVSS: CVSS scores a single
vulnerability's technical severity in isolation; the exposure score
prioritises an entire scan's worth of findings against each other, using
inputs CVSS was never designed to take (confidence, reachability, asset
role). `Cve.cvss_score` is stored and displayed separately and is never
touched by anything in this file - see `services/cve/correlator.py`.

Per-finding contribution:

    points = severity.base_weight
             * (confidence / 100)
             * exposure.multiplier
             * asset_importance_multiplier
             * corroboration_multiplier

Scan-level score is the sum of finding contributions, run through a
saturating curve so one overwhelming category cannot single-handedly force
every scan to 100 - a target with 40 informational findings and one real
critical should not score the same as one with 40 real criticals.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.models.enums import AssetType, ExposureLevel, Severity

#: How much an asset's role scales a finding sitting on it. A finding on
#: the apex domain or an API endpoint matters more than the same finding on
#: a stylesheet.
_ASSET_IMPORTANCE: dict[AssetType, float] = {
    AssetType.DOMAIN: 1.15,
    AssetType.SUBDOMAIN: 1.0,
    AssetType.API_ENDPOINT: 1.2,
    AssetType.IP: 1.05,
    AssetType.JAVASCRIPT: 1.0,
    AssetType.SOURCE_MAP: 0.95,
    AssetType.URL: 0.9,
    AssetType.STYLESHEET: 0.6,
    AssetType.CERTIFICATE: 1.0,
    AssetType.TECHNOLOGY: 0.85,
    AssetType.CLOUD_RESOURCE: 1.1,
    AssetType.DOCUMENT: 0.8,
    AssetType.EMAIL: 0.75,
}
_DEFAULT_IMPORTANCE = 0.9


@dataclass(frozen=True, slots=True)
class ScoredFinding:
    finding_id: str
    severity: Severity
    confidence: int
    exposure: ExposureLevel
    asset_type: AssetType | None
    source_count: int
    points: float
    band_contribution: str


@dataclass(slots=True)
class ExposureResult:
    score: int
    band: str
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_contributors: list[ScoredFinding] = field(default_factory=list)
    raw_points: float = 0.0
    finding_count: int = 0

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "severity_counts": self.severity_counts,
            "finding_count": self.finding_count,
            "top_contributors": [
                {
                    "finding_id": c.finding_id,
                    "severity": c.severity.value,
                    "confidence": c.confidence,
                    "exposure": c.exposure.value,
                    "points": round(c.points, 2),
                }
                for c in self.top_contributors
            ],
        }


def score_band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "minimal"


def corroboration_multiplier(source_count: int) -> float:
    """More independent sources reporting the same issue raises its weight,
    with the same diminishing-returns shape as the confidence engine -
    a fifth source does not matter as much as the second one did.
    """
    if source_count <= 1:
        return 1.0
    return min(1.35, 1.0 + math.log1p(source_count - 1) * 0.18)


def score_finding(
    *,
    finding_id: str,
    severity: Severity,
    confidence: int,
    exposure: ExposureLevel,
    asset_type: AssetType | None,
    source_count: int = 1,
) -> ScoredFinding:
    importance = _ASSET_IMPORTANCE.get(asset_type, _DEFAULT_IMPORTANCE) if asset_type else _DEFAULT_IMPORTANCE
    points = (
        severity.base_weight
        * (max(0, min(100, confidence)) / 100.0)
        * exposure.multiplier
        * importance
        * corroboration_multiplier(source_count)
    )
    return ScoredFinding(
        finding_id=finding_id,
        severity=severity,
        confidence=confidence,
        exposure=exposure,
        asset_type=asset_type,
        source_count=source_count,
        points=points,
        band_contribution=severity.value,
    )


def compute_exposure(findings: list[ScoredFinding]) -> ExposureResult:
    """Combine per-finding points into the scan-level 0-100 score.

    Saturating sum: `100 * (1 - exp(-total / 60))`. Chosen so a single
    critical (≈40 raw points before multipliers) alone lands in the
    high-50s to mid-60s - serious but not maxed out - while several
    corroborated criticals or a mixed pile of highs push well into the
    80s+, and a scan of only informational findings stays in single digits.
    """
    if not findings:
        return ExposureResult(score=0, band=score_band(0))

    total_points = sum(f.points for f in findings)
    score = round(100 * (1 - math.exp(-total_points / 60.0)))
    score = max(0, min(100, score))

    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

    top = sorted(findings, key=lambda f: -f.points)[:10]

    return ExposureResult(
        score=score,
        band=score_band(score),
        severity_counts=severity_counts,
        top_contributors=top,
        raw_points=total_points,
        finding_count=len(findings),
    )
