"""Confidence and exposure-score engine tests."""

from __future__ import annotations

from app.models.enums import AssetType, ExposureLevel, Severity, SourceKind
from app.services.correlation.confidence import ConfidenceInput, band_for, combine_confidence
from app.services.risk.exposure import compute_exposure, score_band, score_finding


def test_single_high_reliability_source_confidence() -> None:
    score = combine_confidence(
        [ConfidenceInput(base_confidence=90, source_reliability=95, source_kind=SourceKind.PASSIVE)]
    )
    assert 85 <= score <= 96


def test_corroboration_raises_confidence_with_diminishing_returns() -> None:
    single = combine_confidence(
        [ConfidenceInput(base_confidence=70, source_reliability=70, source_kind=SourceKind.PASSIVE)]
    )
    triple = combine_confidence(
        [
            ConfidenceInput(base_confidence=70, source_reliability=70, source_kind=SourceKind.PASSIVE),
            ConfidenceInput(base_confidence=65, source_reliability=65, source_kind=SourceKind.HISTORICAL),
            ConfidenceInput(base_confidence=60, source_reliability=60, source_kind=SourceKind.HISTORICAL),
        ]
    )
    assert triple > single


def test_confidence_never_exceeds_100_or_goes_negative() -> None:
    high = combine_confidence(
        [ConfidenceInput(base_confidence=999, source_reliability=999, source_kind=SourceKind.WEB_SURFACE)]
    )
    assert 0 <= high <= 100
    empty = combine_confidence([])
    assert empty == 0


def test_confidence_bands() -> None:
    assert band_for(96).value == "very_high"
    assert band_for(85).value == "high"
    assert band_for(65).value == "medium"
    assert band_for(45).value == "low"
    assert band_for(10).value == "very_low"


def test_informational_findings_never_move_exposure_score() -> None:
    findings = [
        score_finding(
            finding_id=str(i), severity=Severity.INFORMATIONAL, confidence=95,
            exposure=ExposureLevel.DIRECT, asset_type=AssetType.URL,
        )
        for i in range(50)
    ]
    result = compute_exposure(findings)
    assert result.score == 0
    assert result.band == "minimal"


def test_empty_findings_produce_zero_score() -> None:
    result = compute_exposure([])
    assert result.score == 0


def test_low_confidence_finding_is_discounted() -> None:
    strong = compute_exposure(
        [score_finding(finding_id="a", severity=Severity.HIGH, confidence=95, exposure=ExposureLevel.DIRECT, asset_type=AssetType.API_ENDPOINT)]
    )
    weak = compute_exposure(
        [score_finding(finding_id="a", severity=Severity.HIGH, confidence=15, exposure=ExposureLevel.INFERRED, asset_type=AssetType.URL)]
    )
    assert weak.score < strong.score


def test_exposure_score_never_exceeds_100() -> None:
    findings = [
        score_finding(
            finding_id=str(i), severity=Severity.CRITICAL, confidence=100,
            exposure=ExposureLevel.DIRECT, asset_type=AssetType.API_ENDPOINT, source_count=10,
        )
        for i in range(100)
    ]
    result = compute_exposure(findings)
    assert result.score <= 100


def test_score_band_thresholds() -> None:
    assert score_band(90) == "critical"
    assert score_band(65) == "high"
    assert score_band(40) == "medium"
    assert score_band(20) == "low"
    assert score_band(5) == "minimal"
