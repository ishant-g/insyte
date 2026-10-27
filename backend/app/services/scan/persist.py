"""Persistence: turn a scan's collected data into database rows.

This is the only place `ModuleOutput` collections and a `CorrelatedGraph`
become ORM objects. Modules and the correlation stage never touch a
`Session` - see `modules/base.py` and `services/correlation/graph.py` for
why that boundary matters. Everything here runs inside one transaction per
scan (the caller commits), so a scan's stored data is always internally
consistent: there is no window where assets exist but their relationships
do not.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC
from typing import Any

from sqlalchemy.orm import Session

from app.core.contracts import ModuleOutput
from app.models.enums import ConfidenceBand, Severity
from app.models.graph import Asset, AssetRelationship, Observation
from app.models.intelligence import (
    ApiEndpoint,
    Artifact,
    Certificate,
    DnsRecord,
    HistoricalEvent,
    JavaScriptArtifact,
    Technology,
    Url,
)
from app.models.risk import Cve, Finding, IndexedExposure
from app.models.scan import Scan
from app.services.correlation.graph import CorrelatedGraph
from app.services.cve.correlator import CorrelatedCve
from app.services.risk.exposure import ScoredFinding, score_finding

#: NUL and the other C0/C1 control characters, plus unpaired surrogates.
#: PostgreSQL cannot store a NUL in `text`/`jsonb` at all, and psycopg
#: cannot encode a lone surrogate - a decoded binary body contains both.
#: See `_sanitize_text`.
_NEEDS_SANITISING_RE = re.compile(
    "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\x9f"
    "\\ud800-\\udfff\\ufffe\\uffff]"
)


def persist_graph(
    db: Session, scan: Scan, graph: CorrelatedGraph
) -> dict[tuple[str, str], uuid.UUID]:
    """Write every correlated asset, then every edge. Returns the id map.

    The id map (asset_type, value_hash) -> database uuid is what lets the
    caller wire up findings, technologies and every other per-asset row to
    the correct `asset_id` without a second query per row.
    """
    id_map: dict[tuple[str, str], uuid.UUID] = {}

    for merged in graph.asset_list():
        row = Asset(
            scan_id=scan.id,
            asset_type=merged.asset_type.value,
            value=merged.value[:2048],
            normalized_value=merged.value.lower()[:2048],
            value_hash=merged.value_hash,
            status=merged.status.value,
            confidence=merged.confidence,
            sources=merged.sources,
            attributes=_jsonable(merged.attributes),
            evidence=_jsonable(merged.evidence),
            source_count=len(merged.sources),
            observation_count=merged.observation_count,
            is_target=merged.is_target,
            in_scope=merged.in_scope,
            first_seen=merged.first_seen,
            last_seen=merged.last_seen,
        )
        db.add(row)
        db.flush()
        id_map[merged.key] = row.id

    for edge in graph.edge_list():
        source_id = id_map.get(edge.source_key)
        target_id = id_map.get(edge.target_key)
        if source_id is None or target_id is None:
            continue
        db.add(
            AssetRelationship(
                scan_id=scan.id,
                source_asset_id=source_id,
                target_asset_id=target_id,
                relation=edge.relation.value,
                confidence=edge.confidence,
                sources=edge.sources,
                evidence=_jsonable(edge.evidence),
            )
        )

    return id_map


def persist_observations(
    db: Session, scan: Scan, module_outputs: dict[str, ModuleOutput],
    id_map: dict[tuple[str, str], uuid.UUID],
) -> None:
    """Write the raw, append-only observation trail.

    Kept separate from `persist_graph` because observations are evidence,
    not the graph itself - see `models.graph.Observation`'s docstring.
    """
    for module_id, output in module_outputs.items():
        for observation in output.observations:
            if not observation.is_valid:
                continue
            asset_id = id_map.get((observation.asset_type.value, observation.hash))
            db.add(
                Observation(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    source_id=observation.source,
                    source_type=observation.source_type.value,
                    module_id=module_id,
                    asset_type=observation.asset_type.value,
                    value=observation.value[:2048],
                    value_hash=observation.hash,
                    confidence=observation.confidence,
                    status=observation.status.value,
                    observed_at=observation.observed_at,
                    first_seen=observation.first_seen,
                    last_seen=observation.last_seen,
                    evidence=_jsonable(observation.evidence),
                    attributes=_jsonable(observation.attributes),
                )
            )


def persist_intelligence(
    db: Session,
    scan: Scan,
    module_outputs: dict[str, ModuleOutput],
    id_map: dict[tuple[str, str], uuid.UUID],
) -> dict[str, Any]:
    """Write every typed intelligence collection: DNS, certs, tech, URLs...

    Returns the flattened `technologies` list (as `TechnologyRecord`s are
    not enough on their own - the CVE correlator needs the ORM-persisted
    view) so the caller can hand it straight to CVE correlation without a
    re-query.
    """
    technologies: list[Technology] = []
    seen_tech_keys: set[tuple[str, str | None, str | None]] = set()
    seen_dns: set[tuple[str, str, str]] = set()
    seen_cert: set[str] = set()
    seen_url: set[str] = set()
    seen_api: set[tuple[str, str | None]] = set()
    seen_js: set[str] = set()
    seen_artifact: set[str] = set()
    seen_historical: set[tuple[str, str]] = set()
    seen_exposure: set[tuple[str, str]] = set()

    for _module_id, output in module_outputs.items():
        for record in output.technologies:
            key = (record.normalized_name, record.version, record.host)
            if key in seen_tech_keys:
                continue
            seen_tech_keys.add(key)
            row = Technology(
                scan_id=scan.id,
                name=record.name[:150],
                normalized_name=record.normalized_name[:150],
                version=record.version,
                version_confidence=record.version_confidence,
                version_source=record.version_source,
                category=record.category,
                vendor=record.vendor,
                cpe=record.cpe,
                host=record.host,
                confidence=record.confidence,
                sources=record.sources,
                evidence=_jsonable(record.evidence),
                first_seen=record.first_seen,
                last_seen=record.last_seen,
            )
            db.add(row)
            technologies.append(row)

        for record in output.dns_records:
            key = (record.name, record.record_type, record.value)
            if key in seen_dns:
                continue
            seen_dns.add(key)
            db.add(
                DnsRecord(
                    scan_id=scan.id,
                    name=record.name,
                    record_type=record.record_type,
                    value=record.value,
                    ttl=record.ttl,
                    priority=record.priority,
                    parsed=_jsonable(record.parsed),
                    provider_hint=_jsonable(record.provider_hint),
                    resolver=record.resolver,
                )
            )

        for record in output.certificates:
            dedup_key = record.fingerprint_sha256 or f"ct-log:{','.join(sorted(record.sources))}"
            if dedup_key in seen_cert:
                continue
            seen_cert.add(dedup_key)
            db.add(
                Certificate(
                    scan_id=scan.id,
                    fingerprint_sha256=record.fingerprint_sha256,
                    serial_number=record.serial_number,
                    subject_cn=record.subject_cn,
                    subject=_jsonable(record.subject),
                    issuer_cn=record.issuer_cn,
                    issuer_org=record.issuer_org,
                    issuer=_jsonable(record.issuer),
                    sans=record.sans,
                    has_wildcard=any(s.startswith("*.") for s in record.sans),
                    san_count=len(record.sans),
                    not_before=record.not_before,
                    not_after=record.not_after,
                    is_expired=_is_expired(record.not_after),
                    days_until_expiry=_days_until(record.not_after),
                    signature_algorithm=record.signature_algorithm,
                    public_key_algorithm=record.public_key_algorithm,
                    public_key_size=record.public_key_size,
                    tls_version=record.tls_version,
                    chain=record.chain,
                    ct_logged=record.ct_logged,
                    ct_entries=record.ct_entries,
                    from_ct_log=record.from_ct_log,
                    confidence=record.confidence,
                    sources=record.sources,
                    evidence=_jsonable(record.evidence),
                )
            )

        for record in output.urls:
            if record.hash in seen_url:
                continue
            seen_url.add(record.hash)
            db.add(
                Url(
                    scan_id=scan.id,
                    url=record.url[:4000],
                    normalized_url=record.normalized_url[:4000],
                    url_hash=record.hash,
                    scheme=record.scheme,
                    host=record.host[:255],
                    path=record.path,
                    query_keys=record.query_keys,
                    extension=record.extension,
                    classification=record.classification.value,
                    status_code=record.status_code,
                    content_type=record.content_type,
                    retrieved=record.retrieved,
                    in_scope=record.in_scope,
                    confidence=record.confidence,
                    sources=record.sources,
                    evidence=_jsonable(record.evidence),
                    first_seen=record.first_seen,
                    last_seen=record.last_seen,
                )
            )

        for record in output.api_endpoints:
            key = (record.hash, record.method)
            if key in seen_api:
                continue
            seen_api.add(key)
            db.add(
                ApiEndpoint(
                    scan_id=scan.id,
                    url=record.url[:4000],
                    normalized_url=record.normalized_url[:4000],
                    url_hash=record.hash,
                    host=record.host[:255],
                    path=record.path,
                    method=record.method,
                    api_type=record.api_type.value,
                    api_version=record.api_version,
                    auth_hint=record.auth_hint,
                    source_artifact=record.source_artifact,
                    validated=False,
                    in_scope=record.in_scope,
                    parameters=record.parameters,
                    confidence=record.confidence,
                    sources=record.sources,
                    evidence=_jsonable(record.evidence),
                    first_seen=record.first_seen,
                    last_seen=record.last_seen,
                )
            )

        for record in output.javascript:
            if record.hash in seen_js:
                continue
            seen_js.add(record.hash)
            db.add(
                JavaScriptArtifact(
                    scan_id=scan.id,
                    url=record.url[:4000],
                    url_hash=record.hash,
                    content_sha256=record.content_sha256,
                    size=record.size,
                    is_inline=record.is_inline,
                    is_third_party=record.is_third_party,
                    truncated=record.truncated,
                    libraries=record.libraries,
                    endpoints=record.endpoints,
                    domains=record.domains,
                    ip_addresses=record.ip_addresses,
                    emails=record.emails,
                    cloud_references=record.cloud_references,
                    integrations=record.integrations,
                    secret_indicators=record.secret_indicators,
                    comments=record.comments,
                    config_objects=record.config_objects,
                    environment_hints=record.environment_hints,
                    package_names=record.package_names,
                    source_map_url=record.source_map_url,
                    has_source_map=record.has_source_map,
                    source_map_retrieved=record.source_map_retrieved,
                    source_map_detail=_jsonable(record.source_map_detail),
                    confidence=record.confidence,
                    sources=record.sources,
                    evidence=_jsonable(record.evidence),
                )
            )

        for record in output.artifacts:
            if record.hash in seen_artifact:
                continue
            seen_artifact.add(record.hash)
            db.add(
                Artifact(
                    scan_id=scan.id,
                    url=record.url[:4000],
                    url_hash=record.hash,
                    kind=record.kind.value,
                    status_code=record.status_code,
                    content_type=record.content_type,
                    content_sha256=record.content_sha256,
                    size=record.size,
                    truncated=record.truncated,
                    headers=_jsonable(dict(list(record.headers.items())[:30])),
                    redirect_chain=record.redirect_chain,
                    remote_address=record.remote_address,
                    storage_path=record.storage_path,
                    fetched_at=record.fetched_at,
                )
            )

        for historical_record in output.historical:
            key = (historical_record.asset_type.value, historical_record.hash)
            if key in seen_historical:
                continue
            seen_historical.add(key)
            asset_id = id_map.get((historical_record.asset_type.value, historical_record.hash))
            db.add(
                HistoricalEvent(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    asset_type=historical_record.asset_type.value,
                    value=historical_record.value[:2048],
                    value_hash=historical_record.hash,
                    source_id=historical_record.source,
                    status=historical_record.status.value,
                    observed_at=historical_record.observed_at,
                    first_seen=historical_record.first_seen,
                    last_seen=historical_record.last_seen,
                    year=historical_record.first_seen.year if historical_record.first_seen else None,
                    attributes=_jsonable(historical_record.attributes),
                )
            )

        for exposure_record in output.exposures:
            key = (exposure_record.exposure_type, exposure_record.hash)
            if key in seen_exposure:
                continue
            seen_exposure.add(key)
            asset_id = None
            db.add(
                IndexedExposure(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    exposure_type=exposure_record.exposure_type,
                    url=exposure_record.url[:4000],
                    url_hash=exposure_record.hash,
                    host=exposure_record.host,
                    path=exposure_record.path,
                    observation_class=exposure_record.observation_class,
                    retrievable=exposure_record.retrievable,
                    severity=exposure_record.severity.value,
                    confidence=exposure_record.confidence,
                    sources=exposure_record.sources,
                    evidence=_jsonable(exposure_record.evidence),
                    first_seen=exposure_record.first_seen,
                    last_seen=exposure_record.last_seen,
                )
            )

    db.flush()
    return {"technologies": technologies}


def persist_findings(
    db: Session,
    scan: Scan,
    module_outputs: dict[str, ModuleOutput],
    id_map: dict[tuple[str, str], uuid.UUID],
) -> list[Finding]:
    """Write findings and compute each one's Insyte risk score.

    Deduplicated by fingerprint - the same issue surfaced by two modules
    (rare, but e.g. an exposed `.env` seen by both `indexed_exposure` and
    `document_intelligence`) becomes one row with merged sources, not two
    findings inflating the exposure score.
    """
    rows: list[Finding] = []
    by_fingerprint: dict[str, Finding] = {}
    source_counts: dict[str, int] = {}

    for _module_id, output in module_outputs.items():
        for record in output.findings:
            fingerprint = record.fingerprint
            source_counts[fingerprint] = source_counts.get(fingerprint, 0) + 1
            existing = by_fingerprint.get(fingerprint)
            if existing is not None:
                merged_sources = list(dict.fromkeys((existing.sources or []) + record.sources))
                existing.sources = merged_sources
                existing.confidence = max(existing.confidence, record.confidence)
                continue

            asset_id = None
            if record.asset_type is not None and record.asset_value is not None:
                from app.core.canonical import canonical_value, value_hash

                normalized = canonical_value(record.asset_type.value, record.asset_value)
                asset_id = id_map.get((record.asset_type.value, value_hash(normalized)))

            row = Finding(
                scan_id=scan.id,
                asset_id=asset_id,
                module_id=record.module_id,
                category=record.category.value,
                severity=record.severity.value,
                confidence=record.confidence,
                confidence_band=ConfidenceBand.from_score(record.confidence).value,
                exposure=record.exposure.value,
                title=record.title,
                description=record.description,
                recommendation=record.recommendation,
                location=record.location,
                evidence=_jsonable(record.evidence),
                sources=record.sources,
                reference_links=record.references,
                cve_ids=record.cve_ids,
                fingerprint=fingerprint,
                first_seen=None,
                last_seen=None,
            )
            db.add(row)
            by_fingerprint[fingerprint] = row
            rows.append(row)

    db.flush()
    return rows


def score_and_finalize_findings(
    db: Session, scan: Scan, findings: list[Finding], source_counts: dict[str, int] | None = None
) -> list[ScoredFinding]:
    """Compute each finding's risk_score/priority via the exposure engine."""
    scored: list[ScoredFinding] = []
    for finding in findings:
        asset_type = None
        if finding.asset_id is not None:
            asset = db.get(Asset, finding.asset_id)
            if asset is not None:
                from app.models.enums import AssetType

                try:
                    asset_type = AssetType(asset.asset_type)
                except ValueError:
                    asset_type = None

        from app.models.enums import ExposureLevel

        result = score_finding(
            finding_id=str(finding.id),
            severity=Severity(finding.severity),
            confidence=finding.confidence,
            exposure=ExposureLevel(finding.exposure),
            asset_type=asset_type,
            source_count=len(finding.sources or []) or 1,
        )
        finding.risk_score = round(result.points * 2.5)
        finding.priority = _priority_for(Severity(finding.severity), result.points)
        scored.append(result)
    db.flush()
    return scored


def persist_cves(
    db: Session, scan: Scan, correlated: list[CorrelatedCve]
) -> list[Cve]:
    rows: list[Cve] = []
    # One row per CVE ID. The same CVE used to appear once per matched
    # technology (e.g. CVE-2024-51479 listed under both Next.js and Vercel),
    # which read as duplicate rows; the matched technologies are merged into
    # the row's technology field instead.
    merged: dict[str, CorrelatedCve] = {}
    tech_names: dict[str, list[str]] = {}
    for record in correlated:
        cve_id = (record.cve_id or "").upper()
        if not cve_id:
            continue
        existing = merged.get(cve_id)
        if existing is None:
            merged[cve_id] = record
            tech_names[cve_id] = []
        if record.technology_name and record.technology_name not in tech_names[cve_id]:
            tech_names[cve_id].append(record.technology_name)
        # Keep the strongest signal when the same CVE matched twice.
        if existing is not None:
            if (record.match_confidence or 0) > (existing.match_confidence or 0):
                merged[cve_id] = record
            if record.known_exploited and not existing.known_exploited:
                merged[cve_id].known_exploited = True
    for cve_id, record in merged.items():
        technologies = tech_names[cve_id]
        technology_label = (
            record.technology_name
            if len(technologies) <= 1
            else ", ".join(sorted(technologies))
        )
        row = Cve(
            scan_id=scan.id,
            cve_id=record.cve_id,
            technology_name=technology_label,
            detected_version=record.detected_version,
            cpe=record.cpe,
            affected_range=record.affected_range,
            description=record.description,
            published_at=record.published_at,
            modified_at=record.modified_at,
            cvss_score=record.cvss_score,
            cvss_severity=record.cvss_severity,
            cvss_vector=record.cvss_vector,
            cvss_version=record.cvss_version,
            epss_score=record.epss_score,
            epss_percentile=record.epss_percentile,
            known_exploited=record.known_exploited,
            kev_added_at=_parse_date(record.kev_added_at),
            kev_due_date=_parse_date(record.kev_due_date),
            match_confidence=record.match_confidence,
            version_evidence=_jsonable(record.version_evidence),
            definitive=record.definitive,
            source_id=record.source_id,
            reference_links=record.reference_links,
        )
        db.add(row)
        rows.append(row)
    db.flush()
    return rows


def _jsonable(value: Any) -> Any:
    """Render a nested structure into something a JSONB column can hold.

    JSONB columns cannot hold a Python `datetime` directly through the
    driver in every path, and reports/API responses need ISO strings
    anyway - normalising once here means every call site does not have to.

    This function is total: sets become sorted lists, and anything else
    that is not natively JSON-serialisable falls back to `str()`. A single
    unserialisable value must never be able to fail a whole scan's
    persistence (that once left an entire wave of modules stuck at
    "running" after a silent rollback).

    Strings are additionally made storable: PostgreSQL's `jsonb`/`text`
    rejects a NUL byte outright (`UntranslatableCharacter: \\u0000 cannot
    be converted to text`), and any module that decodes a binary response
    into text - a favicon served from `/.well-known/`, an icon font, a
    mislabelled stylesheet - produces exactly that. One such body failed
    the flush, rolled the whole wave back, and left every module row stuck
    at "running" while the scan sat at 0% forever. Control characters and
    lone surrogates are dropped for the same reason; the text stays
    readable and the scan survives.
    """
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        try:
            return sorted((_jsonable(v) for v in value), key=repr)
        except Exception:
            return [_jsonable(v) for v in value]
    if isinstance(value, str):
        return _sanitize_text(value)
    if hasattr(value, "isoformat"):
        try:
            return _sanitize_text(value.isoformat())
        except Exception:
            return str(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _sanitize_text(str(value))


def _sanitize_text(value: str) -> str:
    """Strip characters PostgreSQL cannot store in a text/jsonb column.

    NUL is the one that actually breaks inserts; the other C0/C1 control
    characters and unpaired surrogates are removed alongside it so a
    binary body round-trips as readable text instead of a driver error.
    """
    if not _NEEDS_SANITISING_RE.search(value):
        return value
    return _NEEDS_SANITISING_RE.sub("", value)


def _is_expired(not_after) -> bool:
    if not_after is None:
        return False
    from datetime import datetime

    return not_after < datetime.now(UTC)


def _days_until(not_after) -> int | None:
    if not_after is None:
        return None
    from datetime import datetime

    return (not_after - datetime.now(UTC)).days


def _priority_for(severity: Severity, points: float) -> str:
    if severity is Severity.CRITICAL or points >= 35:
        return "P1"
    if severity is Severity.HIGH or points >= 20:
        return "P2"
    if severity is Severity.MEDIUM or points >= 10:
        return "P3"
    if severity is Severity.LOW or points >= 3:
        return "P4"
    return "P5"


def _parse_date(value: str | None):
    if not value:
        return None
    from datetime import datetime

    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value[: len(fmt) + 2], fmt)
        except ValueError:
            continue
    return None
