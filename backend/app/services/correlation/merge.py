"""Deduplication: folding many observations into one asset per identity.

This is the module-facing half of correlation - used by every module that
aggregates several providers (subdomains today; IP/ASN and technology
follow the same pattern). The full cross-module graph build happens later
in `services/correlation/graph.py`, once every module for a scan has run;
this earlier pass exists so a single module's own output is already
deduplicated before it reaches that stage.
"""

from __future__ import annotations

from app.core.contracts import AssetRecord, ObservationRecord
from app.models.enums import ObservationStatus, SourceKind
from app.services.correlation.confidence import ConfidenceInput, combine_confidence

#: Baseline reliability used when a source is not in the catalogue.
_DEFAULT_RELIABILITY = 65

_SOURCE_KIND_OVERRIDE: dict[str, SourceKind] = {
    "tls": SourceKind.WEB_SURFACE,
    "web_surface": SourceKind.WEB_SURFACE,
    "dns": SourceKind.PASSIVE,
    "rdap": SourceKind.PASSIVE,
    "certificate_transparency": SourceKind.PASSIVE,
}


def _reliability_for(source_id: str) -> int:
    from app.providers import get_provider

    provider = get_provider(source_id)
    if provider is not None:
        return provider.reliability
    return _DEFAULT_RELIABILITY


def _kind_for(source_id: str, observed_kind: SourceKind) -> SourceKind:
    return _SOURCE_KIND_OVERRIDE.get(source_id, observed_kind)


def merge_observations(observations: list[ObservationRecord]) -> list[AssetRecord]:
    """Group observations by (asset_type, normalized value) into assets.

    Deterministic ordering: assets come back sorted by descending combined
    confidence, then by value, so scan output is stable across runs given
    the same underlying evidence.
    """
    groups: dict[tuple[str, str], list[ObservationRecord]] = {}
    for observation in observations:
        if not observation.is_valid:
            continue
        key = (observation.asset_type.value, observation.hash)
        groups.setdefault(key, []).append(observation)

    assets: list[AssetRecord] = []
    for (_asset_type_value, _hash), group in groups.items():
        display_value = _pick_display_value(group)
        sources = sorted({o.source for o in group})

        confidence_inputs = [
            ConfidenceInput(
                base_confidence=o.confidence,
                source_reliability=_reliability_for(o.source),
                source_kind=_kind_for(o.source, o.source_type),
                status=o.status,
                last_seen=o.last_seen,
            )
            for o in group
        ]
        confidence = combine_confidence(confidence_inputs)

        first_seen = _min_dt(o.first_seen for o in group)
        last_seen = _max_dt(o.last_seen for o in group)
        status = _combine_status(group)

        merged_attributes: dict[str, object] = {}
        for observation in sorted(group, key=lambda o: -o.confidence):
            for key, value in observation.attributes.items():
                merged_attributes.setdefault(key, value)
        merged_attributes["source_count"] = len(sources)
        merged_attributes["observation_count"] = len(group)

        evidence = {
            "per_source": [
                {
                    "source": o.source,
                    "confidence": o.confidence,
                    "detail": o.evidence,
                }
                for o in sorted(group, key=lambda o: o.source)[:12]
            ]
        }

        assets.append(
            AssetRecord(
                asset_type=group[0].asset_type,
                value=display_value,
                confidence=confidence,
                sources=sources,
                status=status,
                attributes=merged_attributes,
                evidence=evidence,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    assets.sort(key=lambda a: (-a.confidence, a.value.lower()))
    return assets


def _pick_display_value(group: list[ObservationRecord]) -> str:
    """The most information-preserving spelling among duplicate observations.

    Prefers the value from the highest-confidence source; ties broken by
    the longer (more specific) spelling.
    """
    best = max(group, key=lambda o: (o.confidence, len(o.value)))
    return best.value


def _combine_status(group: list[ObservationRecord]) -> ObservationStatus:
    statuses = {o.status for o in group}
    if ObservationStatus.CURRENT_OBSERVATION in statuses:
        return ObservationStatus.CURRENT_OBSERVATION
    if ObservationStatus.OBSERVED in statuses:
        return ObservationStatus.OBSERVED
    if ObservationStatus.HISTORICAL in statuses:
        return ObservationStatus.HISTORICAL
    return ObservationStatus.UNKNOWN


def _min_dt(values):
    present = [v for v in values if v is not None]
    return min(present) if present else None


def _max_dt(values):
    present = [v for v in values if v is not None]
    return max(present) if present else None
