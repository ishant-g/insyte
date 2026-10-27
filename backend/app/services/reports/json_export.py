"""JSON report generation - the machine-readable export.

Every field a human-facing report shows also appears here, in a shape
meant for a future integration to consume directly (section 42 of the
brief). Datetimes are ISO-8601; everything else is a direct field mapping
with no lossy summarisation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.services.reports.builder import ReportData


def _iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def build_json_document(report: ReportData) -> dict[str, Any]:
    scan = report.scan
    return {
        "insyte_version": __import__("app.core.config", fromlist=["settings"]).settings.APP_VERSION,
        "generated_at": _iso(report.generated_at),
        "scan": {
            "id": str(scan.id),
            "target": scan.target_value,
            "target_type": scan.target_type,
            "mode": scan.mode,
            "status": scan.status,
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
            "duration_seconds": scan.duration,
            "exposure_score": scan.exposure_score,
            "exposure_band": scan.exposure_band,
            "summary": scan.summary,
            "limits": scan.limits,
        },
        "modules": [
            {
                "module_id": m.module_id,
                "display_name": m.display_name,
                "category": m.category,
                "status": m.status,
                "duration": m.duration,
                "result_count": m.result_count,
                "finding_count": m.finding_count,
                "skip_reason": m.skip_reason,
                "error": m.error,
                # Module-specific structured output that doesn't fit the
                # typed asset/finding/technology tables - RDAP registration
                # detail, SPF/DMARC posture, robots.txt structure, corporate/
                # breach/social-footprint results, dork hits, and so on.
                "data": m.data,
            }
            for m in report.modules
        ],
        "providers": report.provider_status,
        "assets": [
            {
                "id": str(a.id),
                "asset_type": a.asset_type,
                "value": a.value,
                "confidence": a.confidence,
                "sources": a.sources,
                "status": a.status,
                "is_target": a.is_target,
                "in_scope": a.in_scope,
                "attributes": a.attributes,
                "first_seen": _iso(a.first_seen),
                "last_seen": _iso(a.last_seen),
            }
            for a in report.assets
        ],
        "relationships": [
            {
                "source_asset_id": str(r.source_asset_id),
                "target_asset_id": str(r.target_asset_id),
                "relation": r.relation,
                "confidence": r.confidence,
                "sources": r.sources,
            }
            for r in report.relationships
        ],
        "findings": [
            {
                "id": str(f.id),
                "module_id": f.module_id,
                "category": f.category,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "priority": f.priority,
                "confidence": f.confidence,
                "confidence_band": f.confidence_band,
                "exposure": f.exposure,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "location": f.location,
                "evidence": f.evidence,
                "sources": f.sources,
                "cve_ids": f.cve_ids,
            }
            for f in report.findings
        ],
        "technologies": [
            {
                "name": t.name,
                "version": t.version,
                "version_confidence": t.version_confidence,
                "category": t.category,
                "host": t.host,
                "confidence": t.confidence,
                "sources": t.sources,
            }
            for t in report.technologies
        ],
        "cves": [
            {
                "cve_id": c.cve_id,
                "technology_name": c.technology_name,
                "detected_version": c.detected_version,
                "cvss_score": c.cvss_score,
                "cvss_severity": c.cvss_severity,
                "cvss_vector": c.cvss_vector,
                "epss_score": c.epss_score,
                "epss_percentile": c.epss_percentile,
                "known_exploited": c.known_exploited,
                "match_confidence": c.match_confidence,
                "definitive": c.definitive,
                "references": c.reference_links,
            }
            for c in report.cves
        ],
        "urls": [
            {
                "url": u.url,
                "classification": u.classification,
                "status_code": u.status_code,
                "retrieved": u.retrieved,
                "in_scope": u.in_scope,
            }
            for u in report.urls
        ],
        "apis": [
            {
                "url": a.url,
                "api_type": a.api_type,
                "method": a.method,
                "auth_hint": a.auth_hint,
                "validated": a.validated,
            }
            for a in report.api_endpoints
        ],
        "javascript": [
            {
                "url": j.url,
                "is_third_party": j.is_third_party,
                "libraries": j.libraries,
                "endpoints": j.endpoints,
                "has_source_map": j.has_source_map,
                "secret_indicators": j.secret_indicators,
            }
            for j in report.javascript
        ],
        "certificates": [
            {
                "fingerprint_sha256": c.fingerprint_sha256,
                "subject_cn": c.subject_cn,
                "issuer_org": c.issuer_org,
                "sans": c.sans,
                "not_before": _iso(c.not_before),
                "not_after": _iso(c.not_after),
                "is_expired": c.is_expired,
                "from_ct_log": c.from_ct_log,
                "source_label": (
                    "Certificate Transparency log (hostnames only; full certificate not retrieved)"
                    if c.from_ct_log
                    else "live TLS handshake"
                ),
            }
            for c in report.certificates
        ],
        "dns_records": [
            {"name": d.name, "type": d.record_type, "value": d.value}
            for d in report.dns_records
        ],
        "historical_events": [
            {
                "asset_type": h.asset_type,
                "value": h.value,
                "source": h.source_id,
                "status": h.status,
                "first_seen": _iso(h.first_seen),
                "last_seen": _iso(h.last_seen),
            }
            for h in report.historical_events
        ],
        "indexed_exposures": [
            {
                "exposure_type": e.exposure_type,
                "url": e.url,
                "observation_class": e.observation_class,
                "severity": e.severity,
                "retrievable": e.retrievable,
            }
            for e in report.indexed_exposures
        ],
    }


def write_json_report(report: ReportData, output_path: Path) -> int:
    document = build_json_document(report)
    text = json.dumps(document, indent=2, default=str, ensure_ascii=False)
    output_path.write_text(text, encoding="utf-8")
    return len(text.encode("utf-8"))
