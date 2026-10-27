"""The confidence engine.

Confidence answers "how sure is Insyte this is real?" - a question that is
independent of severity (see `models.enums.Severity` vs `ConfidenceBand`,
and `services/risk/exposure.py` for how the two combine). A missing
security header is high-confidence and low-severity; a secret-shaped string
in a minified bundle may be high-severity and only medium-confidence.
Collapsing the two into one number is how recon tooling ends up either
crying wolf or missing real findings, and this module exists specifically
to keep them apart.

The combination rule, corroboration-with-diminishing-returns:

    combined = 100 - (100 - base) * Π(1 - r_i / 100)

Each additional independent source narrows the residual uncertainty rather
than adding linearly - the fourth confirming source moves the needle far
less than the second one did, which matches how corroboration actually
works: five sources scraping the same one certificate transparency log are
not five independent opinions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.models.enums import ConfidenceBand, ObservationStatus, SourceKind

#: A source's kind sets a ceiling on how confident Insyte will ever be from
#: that source alone, before corroboration. A single historical archive hit
#: is real evidence but weaker than a live TLS handshake.
_KIND_CEILING: dict[SourceKind, int] = {
    SourceKind.PASSIVE: 96,
    SourceKind.WEB_SURFACE: 98,
    SourceKind.EXTERNAL: 92,
    SourceKind.HISTORICAL: 85,
    SourceKind.DERIVED: 80,
}

#: How much confidence decays per year of staleness for a purely historical
#: observation with no recent corroboration. Recent-only assets are
#: unaffected; this only pulls down evidence nobody has re-confirmed.
_STALENESS_DECAY_PER_YEAR = 4
_STALENESS_FLOOR = 35


@dataclass(frozen=True, slots=True)
class ConfidenceInput:
    """One vote toward a combined confidence score."""

    base_confidence: int
    source_reliability: int = 70
    source_kind: SourceKind = SourceKind.PASSIVE
    status: ObservationStatus = ObservationStatus.OBSERVED
    last_seen: datetime | None = None


def combine_confidence(inputs: list[ConfidenceInput]) -> int:
    """Combine independent pieces of evidence into one 0-100 score.

    An empty list returns 0 - "no evidence" is not "uncertain", it is
    nothing, and callers should not be calling this with nothing.
    """
    if not inputs:
        return 0

    residual = 1.0
    for item in inputs:
        ceiling = _KIND_CEILING.get(item.source_kind, 90)
        # A source's own reliability tempers how much weight its vote gets:
        # a 60%-reliable source asserting "100% confident" is not treated
        # as certain.
        effective = min(
            item.base_confidence,
            ceiling,
            round(item.base_confidence * (item.source_reliability / 100.0) * 1.15),
        )
        effective = _apply_staleness(effective, item)
        effective = max(0, min(100, effective))
        residual *= 1.0 - (effective / 100.0)

    combined = round(100.0 * (1.0 - residual))

    # Reaching absolute certainty from corroboration alone overstates what
    # multiple third-party sources can actually prove; 100 is reserved for
    # something Insyte observed directly and strongly (e.g. a live TLS
    # handshake). Everything else tops out just under it.
    direct_and_strong = any(
        item.source_kind in (SourceKind.WEB_SURFACE, SourceKind.PASSIVE)
        and item.base_confidence >= 95
        and item.source_reliability >= 95
        for item in inputs
    )
    ceiling = 100 if direct_and_strong else 99
    return max(0, min(ceiling, combined))


def _apply_staleness(confidence: int, item: ConfidenceInput) -> int:
    if item.source_kind not in (SourceKind.HISTORICAL,) or item.last_seen is None:
        return confidence
    last_seen = item.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    years = max(0.0, (datetime.now(UTC) - last_seen).days / 365.25)
    decayed = confidence - round(years * _STALENESS_DECAY_PER_YEAR)
    return max(_STALENESS_FLOOR, decayed)


def band_for(score: int) -> ConfidenceBand:
    return ConfidenceBand.from_score(score)


def corroboration_bonus(source_count: int) -> int:
    """Small additive nudge for the UI's "N independent sources" framing.

    Not used inside `combine_confidence` (which already models this via the
    residual-uncertainty product) - this is for callers that want a quick
    display-only adjustment without redoing the full combination, e.g. a
    finding whose confidence needs a light bump because three separate
    modules independently flagged the same location.
    """
    if source_count <= 1:
        return 0
    if source_count == 2:
        return 4
    if source_count == 3:
        return 7
    return 10
