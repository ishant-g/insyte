"""Technology → CVE → CVSS → EPSS → KEV correlation.

The rule that governs everything in this file, stated in the brief and
worth repeating because it is the difference between intelligence and
noise: **never report a CVE against a technology merely because the
product family was detected.** A CVE is only marked `definitive=True` when
version evidence clears `settings.CVE_MIN_VERSION_CONFIDENCE`; below that
floor it is still recorded (so the user can see "this might matter") but
labelled "potentially affected - version confidence insufficient for
definitive mapping" everywhere it is displayed.

Pipeline, per detected technology:

    normalized name + version
            |
            v
    CPE 2.3 (services/cve/cpe.py) --- if unmapped or unversioned --> keyword search
            |
            v
    NVD CVE lookup (providers/vulnerability.py, cached)
            |
            v
    EPSS batch lookup
            |
            v
    KEV catalogue membership
            |
            v
    Cve rows, each carrying match_confidence and definitive
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.core.config import settings
from app.core.contracts import TechnologyRecord
from app.core.logging import get_logger
from app.providers import get_provider
from app.services.cve.cpe import to_cpe, vendor_product

logger = get_logger(__name__)

#: Below this the CVE is recorded but flagged non-definitive, regardless of
#: what NVD's own match implies.
_VERSION_CONFIDENCE_FLOOR = settings.CVE_MIN_VERSION_CONFIDENCE

#: Ceiling on distinct technologies looked up per scan - NVD's unauthenticated
#: rate limit (5 req/30s) makes an unbounded pass impractical, and a scan
#: with hundreds of detected libraries gains little from CVE-checking all
#: of them versus the ones that actually carry version evidence.
_MAX_TECHNOLOGIES_PER_SCAN = 25

#: Cap on NVD keyword results for a technology with no CPE mapping and no
#: version evidence. Keyword matches are weak by construction, so this path
#: is deliberately narrow: enough to show the technology was considered,
#: not enough to flood the CVE list with maybes.
_KEYWORD_FALLBACK_LIMIT = 10


@dataclass(slots=True)
class CorrelatedCve:
    cve_id: str
    technology_name: str
    detected_version: str | None
    cpe: str | None
    affected_range: str | None
    description: str | None
    published_at: datetime | None
    modified_at: datetime | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_score: float | None
    epss_percentile: float | None
    known_exploited: bool
    kev_added_at: str | None
    kev_due_date: str | None
    match_confidence: int
    definitive: bool
    version_evidence: dict = field(default_factory=dict)
    source_id: str = "nvd"
    reference_links: list[str] = field(default_factory=list)


def correlate(technologies: list[TechnologyRecord]) -> list[CorrelatedCve]:
    """Run the full pipeline for a scan's detected technologies."""
    if not settings.CVE_LOOKUP_ENABLED or not technologies:
        return []

    nvd = get_provider("nvd")
    epss = get_provider("epss")
    kev = get_provider("kev")
    if nvd is None:
        return []

    # Prioritise technologies with real version evidence - those are the
    # ones a definitive match is even possible for - then cap the total.
    # Technologies beyond the cap are not silently forgotten: the truncation
    # is logged and reported via `summarize()` so the user can see the CVE
    # pass was bounded.
    deduped = sorted(
        {t.normalized_name: t for t in technologies if t.name}.values(),
        key=lambda t: -t.version_confidence,
    )
    candidates = deduped[:_MAX_TECHNOLOGIES_PER_SCAN]
    truncated = deduped[_MAX_TECHNOLOGIES_PER_SCAN:]
    if truncated:
        logger.warning(
            "cve_technology_truncation",
            extra={
                "checked": len(candidates),
                "skipped": len(truncated),
                "skipped_technologies": [t.name for t in truncated[:10]],
            },
        )

    results: list[CorrelatedCve] = []
    for technology in candidates:
        results.extend(_correlate_one(technology, nvd))

    if epss is not None and results:
        epss_data = epss.lookup([r.cve_id for r in results])
        for row in results:
            entry = epss_data.get(row.cve_id.upper())
            if entry:
                row.epss_score = entry.get("score")
                row.epss_percentile = entry.get("percentile")

    if kev is not None and results:
        catalogue = kev.catalogue()
        for row in results:
            entry = catalogue.get(row.cve_id.upper())
            if entry:
                row.known_exploited = True
                row.kev_added_at = entry.get("date_added")
                row.kev_due_date = entry.get("due_date")

    return results


#: Generic words that carry no identifying power when tokenising a
#: technology name for CVE matching.
_STOPWORD_TOKENS = frozenset({
    "server", "web", "cloud", "services", "service", "software", "library",
    "libraries", "framework", "application", "applications", "system",
    "systems", "labs", "inc", "ltd", "corp", "technologies", "technology",
    "digital", "online", "http", "https", "api", "the", "and",
})


def _name_tokens(name: str | None) -> set[str]:
    import re

    return {
        tok
        for tok in re.split(r"[^a-z0-9]+", (name or "").lower())
        if len(tok) >= 3 and tok not in _STOPWORD_TOKENS
    }


def _cpe_vendor_product(criteria: str) -> str:
    """Vendor and product from a CPE 2.3 criteria string, normalised."""
    parts = str(criteria).split(":")
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    return f"{vendor} {product}".lower().replace("_", " ").replace("-", " ")


def _cpe_names_technology(normalized_name: str, cpe_matches: list) -> bool:
    """Whether any vulnerable configuration names this technology outright."""
    name = (normalized_name or "").lower().replace("_", " ").replace("-", " ")
    if not name:
        return False
    return any(name in _cpe_vendor_product(c) for c in cpe_matches)


def _keyword_hit_plausible(tokens: set[str], record: dict) -> bool:
    """Gate a keyword-search hit against the CVE's own configurations.

    Returns True when at least one vulnerable CPE names a token of the
    technology, i.e. the CVE is plausibly *about* the technology rather
    than merely mentioning it in a reference URL. CVEs with no
    configuration data fall back to requiring the token in the English
    description.
    """
    if not tokens:
        return True
    cpe_matches = record.get("cpe_matches") or []
    for criteria in cpe_matches:
        hay = _cpe_vendor_product(criteria)
        if any(tok in hay for tok in tokens):
            return True
    if not cpe_matches:
        desc = str(record.get("description") or "").lower()
        return any(tok in desc for tok in tokens)
    return False


def _correlate_one(technology: TechnologyRecord, nvd) -> list[CorrelatedCve]:
    has_version = bool(technology.version)
    has_confident_version = (
        has_version and technology.version_confidence >= _VERSION_CONFIDENCE_FLOOR
    )
    mapping = vendor_product(technology.normalized_name)

    if mapping is not None:
        vendor, product = mapping
        raw = nvd.lookup_product(vendor, product)
        match_basis = "cpe_range"
    elif has_version:
        raw = nvd.lookup_keyword(technology.name, version=technology.version if has_confident_version else None)
        match_basis = "keyword"
    else:
        # No CPE mapping and no version evidence. A keyword search here is
        # weak evidence by construction - but silently dropping the
        # technology hides it entirely, which is worse. Record whatever NVD
        # returns as non-definitive (the scorer below guarantees
        # definitive=False for keyword matches), capped so one unmapped
        # library cannot flood the CVE list.
        raw = nvd.lookup_keyword(technology.name, limit=_KEYWORD_FALLBACK_LIMIT)
        match_basis = "keyword"

    keyword_dropped = 0
    if has_version and match_basis == "keyword" and raw:
        # NVD keyword search matches the word anywhere in the CVE record,
        # often just a reference URL. Keep only hits whose own vulnerable
        # configurations actually name this technology's vendor or product,
        # otherwise "Cloudflare" collects CVEs for unrelated projects that
        # merely mention Cloudflare somewhere.
        #
        # The no-version fallback is deliberately exempt: its contract is to
        # record the capped NVD result as non-definitive evidence that the
        # technology was considered, not to silently discard it.
        tokens = _name_tokens(technology.name) | _name_tokens(technology.normalized_name)
        kept = [r for r in raw if _keyword_hit_plausible(tokens, r)]
        keyword_dropped = len(raw) - len(kept)
        if keyword_dropped:
            logger.info(
                "cve_keyword_filter",
                extra={
                    "technology": technology.name,
                    "candidates": len(raw),
                    "dropped": keyword_dropped,
                },
            )
        raw = kept

    cpe = to_cpe(technology.normalized_name, technology.version) if has_confident_version else None

    out: list[CorrelatedCve] = []
    for record in raw:
        keyword_aligned = match_basis == "keyword" and _cpe_names_technology(
            technology.normalized_name, record.get("cpe_matches") or []
        )
        match_confidence, definitive, evidence_note = _score_match(
            match_basis, has_confident_version, technology.version_confidence,
            technology.version, record.get("version_constraints") or [],
            keyword_aligned=keyword_aligned,
        )
        # A product-wide, range-aware search legitimately returns CVEs the
        # detected version does not fall inside - only surface those as
        # "potentially affected" rather than dropping them, so the report
        # still shows the full picture for an unversioned/low-confidence
        # detection while being honest about what is and is not confirmed.
        out.append(
            CorrelatedCve(
                cve_id=record["cve_id"],
                technology_name=technology.name,
                detected_version=technology.version,
                cpe=cpe,
                affected_range=record.get("affected_range"),
                description=record.get("description"),
                published_at=_parse(record.get("published")),
                modified_at=_parse(record.get("modified")),
                cvss_score=record.get("cvss_score"),
                cvss_severity=record.get("cvss_severity"),
                cvss_vector=record.get("cvss_vector"),
                cvss_version=record.get("cvss_version"),
                epss_score=None,
                epss_percentile=None,
                known_exploited=False,
                kev_added_at=None,
                kev_due_date=None,
                match_confidence=match_confidence,
                definitive=definitive,
                version_evidence={
                    "version_confidence": technology.version_confidence,
                    "version_source": technology.version_source,
                    "match_basis": match_basis,
                    "note": evidence_note,
                    "keyword_candidates_dropped": keyword_dropped,
                },
                reference_links=record.get("references", []),
            )
        )
    return out


def _score_match(
    match_basis: str,
    has_confident_version: bool,
    version_confidence: int,
    detected_version: str | None,
    constraints: list[dict],
    *,
    keyword_aligned: bool = False,
) -> tuple[int, bool, str]:
    if match_basis != "cpe_range" or not has_confident_version or not detected_version:
        # Keyword matches, or a product match with no confident version,
        # are evidence the product might be relevant - never that the
        # specific installed version is affected. A keyword hit whose CVE
        # configurations name the technology directly scores slightly
        # higher than one kept on a token match alone.
        if keyword_aligned:
            return 45, False, "keyword match against the CVE's own vulnerable-product list"
        return 35, False, "no confident version evidence for range matching"

    if not constraints:
        # The CVE's configuration names this product with no version
        # constraint at all - every version is affected.
        confidence = min(94, 55 + version_confidence // 3)
        return confidence, confidence >= _VERSION_CONFIDENCE_FLOOR, "applies to all versions"

    in_range = any(_version_in_constraint(detected_version, c) for c in constraints)
    if in_range:
        confidence = min(97, 65 + version_confidence // 3)
        return confidence, confidence >= _VERSION_CONFIDENCE_FLOOR, "detected version falls within the affected range"
    return 30, False, "detected version is outside every affected range NVD recorded for this CVE"


def _version_in_constraint(version: str, constraint: dict) -> bool:
    from packaging.version import InvalidVersion, Version

    try:
        detected = Version(_coerce(version))
    except InvalidVersion:
        return False

    exact = constraint.get("exact_version")
    if exact:
        try:
            return detected == Version(_coerce(exact))
        except InvalidVersion:
            return False

    def parse(value: str | None) -> Version | None:
        if not value:
            return None
        try:
            return Version(_coerce(value))
        except InvalidVersion:
            return None

    start_inc = parse(constraint.get("start_including"))
    start_exc = parse(constraint.get("start_excluding"))
    end_inc = parse(constraint.get("end_including"))
    end_exc = parse(constraint.get("end_excluding"))

    if start_inc is not None and detected < start_inc:
        return False
    if start_exc is not None and detected <= start_exc:
        return False
    if end_inc is not None and detected > end_inc:
        return False
    if end_exc is not None and detected >= end_exc:
        return False
    return any(v is not None for v in (start_inc, start_exc, end_inc, end_exc))


def _coerce(version: str) -> str:
    """Best-effort coercion of a real-world version string to PEP 440.

    Software versioning in the wild ("1.18.0", "4.2p1", "2.4.58-1ubuntu")
    is not uniformly PEP 440, but the numeric-dotted prefix almost always
    is, and that prefix is what range comparison actually needs.
    """
    import re

    match = re.match(r"\d+(?:\.\d+){0,3}", version.strip())
    return match.group(0) if match else version.strip()


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def summarize(results: list[CorrelatedCve]) -> dict:
    definitive = [r for r in results if r.definitive]
    potential = [r for r in results if not r.definitive]
    known_exploited = [r for r in results if r.known_exploited]
    highest = max((r.cvss_score for r in results if r.cvss_score is not None), default=None)
    keyword_only = {
        r.technology_name
        for r in results
        if r.version_evidence.get("match_basis") == "keyword"
        and not r.version_evidence.get("version_confidence")
    }
    dropped_by_tech = {}
    for r in results:
        n = r.version_evidence.get("keyword_candidates_dropped") or 0
        if n:
            dropped_by_tech[r.technology_name] = n
    return {
        "total_cves": len(results),
        "definitive_matches": len(definitive),
        "potential_matches": len(potential),
        "known_exploited_count": len(known_exploited),
        "highest_cvss_score": highest,
        "distinct_technologies_affected": len({r.technology_name for r in results}),
        # Technologies whose CVEs come only from the weak keyword fallback
        # (no CPE mapping, no version evidence) - shown so the user knows
        # these rows are leads, not findings.
        "keyword_fallback_technologies": sorted(keyword_only),
        # Keyword candidates discarded because the CVE's own vulnerable
        # configurations did not name the technology - kept out of the
        # report rather than shown as false positives.
        "keyword_candidates_dropped": sum(dropped_by_tech.values()),
    }
