"""Markdown report generation - a plain-text mirror of the PDF export.

Renders the same `ReportData` snapshot as `pdf_export.py` and
`json_export.py`, using nothing beyond the standard library: GFM headings,
tables and bullet lists. Simpler than the PDF by design - there is no
pagination to manage, only the same row caps and "...and N more" notes so a
scan with thousands of URLs still produces a readable file.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.models.enums import ScanMode
from app.services.reports.builder import ReportData

_CELL_MAX_LEN = 200


def _mode_label(mode: str | None) -> str:
    try:
        return ScanMode(mode).label
    except ValueError:
        return (mode or "unknown").replace("_", " ").title()


def _fmt_dt(dt: Any) -> str:
    if dt is None:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _fmt_date(dt: Any) -> str:
    if dt is None:
        return "-"
    return dt.strftime("%Y-%m-%d")


def _text(value: Any) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _anchor(title: str) -> str:
    slug = title.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug.strip())
    return slug


def _cap(items: list, limit: int) -> tuple[list, str | None]:
    if len(items) <= limit:
        return items, None
    remaining = len(items) - limit
    return items[:limit], f"… and {remaining} more (see JSON export for the complete list)."


def _md_cell(value: Any) -> str:
    text = _text(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(text) > _CELL_MAX_LEN:
        text = text[: _CELL_MAX_LEN - 1].rstrip() + "…"
    return text


def _md_table(headers: list[str], rows: list[list]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
    return "\n".join(lines)


def _header_block(report: ReportData) -> str:
    scan = report.scan
    lines = [
        f"# {settings.APP_NAME} - {settings.APP_TAGLINE}",
        "",
        f"**Target:** {report.target}  ",
        f"**Scan Mode:** {_mode_label(scan.mode)}  ",
        f"**Scan Status:** {(scan.status or '').title()}  ",
        f"**Scan Date:** {_fmt_dt(scan.created_at)}  ",
        f"**Generated At:** {_fmt_dt(report.generated_at)}  ",
    ]
    return "\n".join(lines)


def _collection_health_sentence(modules) -> str:
    """Plain-English collection health, with reasons, not just counts.

    A reader should not have to dig into the module appendix to learn why
    a report looks thin: "2 skipped (missing API keys), 1 failed (network
    restriction)" belongs in the executive summary itself.
    """
    skipped = [m for m in modules if m.status == "skipped"]
    failed = [m for m in modules if m.status == "failed"]
    incomplete = [m for m in modules if m.status not in ("completed", "skipped", "failed")]
    if not (skipped or failed or incomplete):
        return "All requested collection modules completed successfully."
    parts = []
    if incomplete:
        parts.append(
            f"{len(incomplete)} module{'s' if len(incomplete) != 1 else ''} did not finish cleanly"
        )
    if skipped:
        parts.append(f"{len(skipped)} skipped")
    if failed:
        parts.append(f"{len(failed)} failed")
    sentence = f"{' and '.join(parts)} during collection"
    reasons: list[str] = []
    for m in failed:
        err = (m.error or "").strip().split("\n")[0]
        if err:
            reasons.append(f"{m.display_name}: {err[:140]}")
    for m in skipped:
        reason = (m.skip_reason or "").strip()
        if reason:
            reasons.append(f"{m.display_name}: {reason[:140]}")
    seen: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    if seen:
        shown = "; ".join(seen[:4])
        if len(seen) > 4:
            shown += f"; and {len(seen) - 4} more"
        sentence += f" ({shown})"
    return sentence + "; see the module appendix for details."


def _executive_summary(report: ReportData) -> str:
    scan = report.scan
    summary = scan.summary or {}
    assets_total = summary.get("assets_total", len(report.assets))
    in_scope = summary.get("assets_in_scope", report.assets_in_scope)
    categories = summary.get("categories_in_scope", report.in_scope_categories)
    score = scan.exposure_score if scan.exposure_score is not None else 0
    band = (scan.exposure_band or "minimal").title()

    s1 = (
        f"This {_mode_label(scan.mode).lower()} scan of {report.target} identified "
        f"{in_scope} in-scope asset{'s' if in_scope != 1 else ''} across "
        f"{categories} categor{'ies' if categories != 1 else 'y'}"
    )
    out_of_scope = assets_total - in_scope
    if out_of_scope > 0:
        s1 += (
            f" ({out_of_scope} out-of-scope context item{'s' if out_of_scope != 1 else ''} "
            "excluded from this summary)"
        )
    s1 += f", with an overall exposure score of {score}/100 ({band})."

    total_findings = len(report.findings)
    crit = len(report.findings_by_severity("critical"))
    high = len(report.findings_by_severity("high"))
    if total_findings:
        s2 = (
            f"{total_findings} finding{'s' if total_findings != 1 else ''} were recorded, "
            f"including {crit} critical and {high} high-severity item{'s' if high != 1 else ''} "
            "requiring attention."
        )
    else:
        s2 = "No findings were recorded for this scan."

    cve_count = len(report.cves)
    definitive = len([c for c in report.cves if c.definitive])
    if cve_count:
        s3 = (
            f"Correlated CVE intelligence surfaced {cve_count} potential match"
            f"{'es' if cve_count != 1 else ''} against detected technologies, of which "
            f"{definitive} carr{'y' if definitive != 1 else 'ies'} definitive version confirmation."
        )
    else:
        s3 = "No CVE correlations were produced for the technologies detected in this scan."

    s4 = _collection_health_sentence(report.modules)

    return f"{s1} {s2} {s3} {s4}"


def _exposure_score(report: ReportData) -> str:
    scan = report.scan
    score = scan.exposure_score if scan.exposure_score is not None else 0
    band = (scan.exposure_band or "minimal").title()
    return (
        f"### {score}/100 - {band}\n\n"
        "**This is Insyte's own prioritisation score, not a standardised CVSS score.** "
        "It combines finding severity, confidence, exposure reachability, asset importance "
        "and source corroboration into a single 0-100 view of this scan's overall risk."
    )


def _severity_distribution(report: ReportData) -> str:
    scan = report.scan
    dist = (scan.summary or {}).get("findings_by_severity") or {}
    rows = []
    total = 0
    for sev in report.severity_order:
        count = dist.get(sev, len(report.findings_by_severity(sev)))
        total += count
        rows.append([sev.title(), str(count)])
    if total == 0:
        return "No findings recorded."
    return _md_table(["Severity", "Count"], rows)


def _asset_stats(report: ReportData) -> str:
    scan = report.scan
    summary = scan.summary or {}
    assets = report.assets

    def count_type(*types: str) -> int:
        return len([a for a in assets if a.asset_type in types])

    stats = [
        ("Total Assets", summary.get("assets_total", len(assets))),
        ("In-Scope Assets", summary.get("assets_in_scope", report.assets_in_scope)),
        ("Domains", summary.get("domains", count_type("domain"))),
        ("Subdomains", summary.get("subdomains", count_type("subdomain"))),
        ("IP Addresses", summary.get("ips", count_type("ip"))),
        ("URLs", summary.get("urls", len(report.urls))),
        ("API Endpoints", summary.get("apis", len(report.api_endpoints))),
        ("JavaScript Files", summary.get("javascript_files", len(report.javascript))),
        ("Certificates", summary.get("certificates", len(report.certificates))),
        ("Technologies", summary.get("technologies", len(report.technologies))),
    ]
    return _md_table(["Metric", "Count"], [[label, str(value)] for label, value in stats])


def _attack_surface(report: ReportData) -> str:
    assets = report.assets
    if not assets:
        return "No assets discovered."
    in_scope = len([a for a in assets if a.in_scope])
    out_scope = len(assets) - in_scope
    rel_count = len(report.relationships)
    return (
        f"Insyte mapped {len(assets)} asset{'s' if len(assets) != 1 else ''} in this scan's graph, "
        f"of which {in_scope} sit within the target's registrable scope and {out_scope} were observed "
        f"as related but out-of-scope context. {rel_count} relationship{'s' if rel_count != 1 else ''} "
        "connect these assets across domains, IPs, certificates and technologies."
    )


def _domain_registration(report: ReportData) -> str:
    data = report.module_data("domain_intelligence")
    if not data or not data.get("available"):
        reason = (data or {}).get("reason")
        return f"No RDAP registration record available{f' - {reason}.' if reason else '.'}"

    def iso_date(value: Any) -> str:
        return value[:10] if isinstance(value, str) and len(value) >= 10 else "-"

    rows = [
        ["Registrar", _text(data.get("registrar"))],
        ["Registered", iso_date(data.get("registration_date"))],
        ["Expires", iso_date(data.get("expiration_date"))],
        ["Last changed", iso_date(data.get("last_changed"))],
        ["Nameservers", ", ".join(data.get("nameservers") or []) or "-"],
        ["DNSSEC signed", "Yes" if data.get("dnssec_signed") else "No"],
        [
            "Registrant",
            "Redacted for privacy" if data.get("registrant_redacted") else _text(data.get("registrant")),
        ],
    ]
    return _md_table(["Field", "Value"], rows)


def _asset_table(report: ReportData, types: set[str], empty_text: str) -> str:
    rows, collapsed = report.scoped_assets(types)
    if not rows and not collapsed:
        return empty_text
    parts: list[str] = []
    if rows:
        capped, note = _cap(rows, 100)
        data_rows = [
            [a.value, str(a.confidence), ", ".join(str(s) for s in (a.sources or [])) or "-"]
            for a in capped
        ]
        table = _md_table(["Value", "Confidence", "Sources"], data_rows)
        parts.append(f"{table}\n\n*{note}*" if note else table)
    for line in collapsed:
        parts.append(f"*{line}*")
    return "\n\n".join(parts)


def _dns_records(report: ReportData) -> str:
    rows = report.dns_records
    if not rows:
        return "No DNS records discovered."
    capped, note = _cap(rows, 100)
    table = _md_table(["Name", "Type", "Value"], [[d.name, d.record_type, d.value] for d in capped])
    return f"{table}\n\n*{note}*" if note else table


def _certificates(report: ReportData) -> str:
    certs = report.certificates
    if not certs:
        return "No certificates discovered."
    capped, note = _cap(certs, 100)
    rows = []
    for c in capped:
        if c.from_ct_log:
            validity = "n/a (CT log hostnames only)"
            status = "CT log"
        else:
            validity = f"{_fmt_date(c.not_before)} – {_fmt_date(c.not_after)}"
            status = "**EXPIRED**" if c.is_expired else "Valid"
        rows.append([c.subject_cn or "-", c.issuer_org or "-", validity, status])
    table = _md_table(["Subject CN", "Issuer", "Validity", "Status"], rows)
    return f"{table}\n\n*{note}*" if note else table


def _technologies_table(
    report: ReportData, technologies: list | None = None, empty_text: str = "No technologies detected.",
) -> str:
    techs = report.technologies if technologies is None else technologies
    if not techs:
        return empty_text
    capped, note = _cap(techs, 100)
    rows = [[t.name, t.version or "unknown", t.category or "-", str(t.confidence)] for t in capped]
    table = _md_table(["Name", "Version", "Category", "Confidence"], rows)
    return f"{table}\n\n*{note}*" if note else table


def _no_client_side_data(report: ReportData, empty_text: str) -> str:
    """Passive-mode scans never fetch pages, so they structurally cannot see
    JavaScript or API endpoints - say so instead of leaving the reader to
    assume there is no client-side attack surface."""
    if report.is_passive:
        return (
            f"{empty_text}\n\n"
            "_Passive mode does not collect JavaScript or API endpoint data by design; "
            "run a Web Surface scan for client-side attack surface._"
        )
    return empty_text


def _javascript(report: ReportData) -> str:
    files = report.javascript
    if not files:
        return _no_client_side_data(report, "No JavaScript files analysed.")
    capped, note = _cap(files, 75)
    rows = []
    for j in capped:
        libs = ", ".join(str(lib) for lib in (j.libraries or [])) or "-"
        rows.append([
            j.url,
            "Yes" if j.is_third_party else "No",
            libs,
            str(len(j.endpoints or [])),
            "Yes" if j.has_source_map else "No",
            str(len(j.secret_indicators or [])),
        ])
    table = _md_table(["URL", "3rd Party", "Libraries", "Endpoints", "Source Map", "Secrets"], rows)
    parts = [table]
    if note:
        parts.append(f"*{note}*")

    # secret_indicators is already masked (services/artifacts/masking.py);
    # only the stored type/masked/severity fields are ever rendered here.
    secret_rows = []
    for j in files:
        for indicator in (j.secret_indicators or []):
            if not isinstance(indicator, dict):
                continue
            secret_rows.append([
                j.url, indicator.get("type", "-"), indicator.get("masked", "-"), indicator.get("severity", "-"),
            ])
    if secret_rows:
        capped_secrets, snote = _cap(secret_rows, 100)
        parts.append("#### Secret Indicators (masked)\n")
        parts.append(_md_table(["File", "Type", "Masked Value", "Severity"], capped_secrets))
        if snote:
            parts.append(f"*{snote}*")
    return "\n\n".join(parts)


def _apis(report: ReportData) -> str:
    apis = report.api_endpoints
    if not apis:
        return _no_client_side_data(report, "No API endpoints discovered.")
    capped, note = _cap(apis, 100)
    rows = [[a.url, a.api_type or "-", a.method or "-", a.auth_hint or "-", "Not validated"] for a in capped]
    table = _md_table(["URL", "Type", "Method", "Auth Hint", "Validation"], rows)
    return f"{table}\n\n*{note}*" if note else table


def _urls(report: ReportData) -> str:
    urls = report.urls
    if not urls:
        return "No URLs discovered."
    counts = Counter(u.classification for u in urls)
    by_class: dict[str, list] = defaultdict(list)
    for u in urls:
        by_class[u.classification].append(u)

    parts = [_md_table(
        ["Classification", "Count"],
        [[cls or "unknown", str(n)] for cls, n in sorted(counts.items(), key=lambda kv: -kv[1])],
    )]

    top_n = 10
    for cls, items in sorted(by_class.items(), key=lambda kv: -len(kv[1])):
        parts.append(f"#### {(cls or 'unknown').title()} ({len(items)})\n")
        top, note = _cap(items, top_n)
        rows = [[u.url, str(u.status_code) if u.status_code is not None else "-"] for u in top]
        parts.append(_md_table(["URL", "Status"], rows))
        if note:
            parts.append(f"*{note}*")
    return "\n\n".join(parts)


def _email_security(report: ReportData) -> str:
    posture = report.module_data("email_security").get("posture") or {}
    findings = [f for f in report.findings if f.category == "email_security" or f.module_id == "email_security"]

    parts: list[str] = []
    if posture:
        spf = posture.get("spf") or {}
        dmarc = posture.get("dmarc") or {}

        def yn(value: Any) -> str:
            return "Yes" if value else "No"

        rows = [
            ["Accepts mail", yn(posture.get("accepts_mail"))],
            ["SPF present", yn(spf.get("present"))],
            ["SPF policy", spf.get("all_qualifier") or "-"],
            ["DMARC present", yn(dmarc.get("present"))],
            ["DMARC policy", dmarc.get("policy") or "-"],
            ["DNSSEC signed", yn(posture.get("dnssec_signed"))],
            ["MTA-STS", yn((posture.get("mta_sts") or {}).get("present"))],
            ["TLS-RPT", yn((posture.get("tls_rpt") or {}).get("present"))],
            ["BIMI", yn((posture.get("bimi") or {}).get("present"))],
        ]
        parts.append(_md_table(["Signal", "Status"], rows))

    if not findings:
        parts.append(
            "_No email security posture issues found._" if posture else "_No email security data collected._"
        )
    else:
        rows = [[f.title, f.severity.title(), f.description or "-"] for f in findings]
        parts.append(_md_table(["Title", "Severity", "Description"], rows))
    return "\n\n".join(parts)


def _historical(report: ReportData) -> str:
    events = report.historical_events
    if not events:
        return "No historical events discovered."
    capped, note = _cap(events, 150)
    by_year: dict[Any, list] = defaultdict(list)
    for e in capped:
        year = e.first_seen.year if e.first_seen else "Unknown"
        by_year[year].append(e)

    def _sort_key(year: Any) -> tuple:
        return (year == "Unknown", -(year if isinstance(year, int) else 0))

    parts = []
    for year in sorted(by_year.keys(), key=_sort_key):
        items = by_year[year]
        parts.append(f"#### {year}\n")
        rows = [[h.asset_type, h.value, h.source_id, h.status] for h in items]
        parts.append(_md_table(["Type", "Value", "Source", "Status"], rows))
    if note:
        parts.append(f"*{note}*")
    return "\n\n".join(parts)


def _indexed_exposure(report: ReportData) -> str:
    rows_data = report.indexed_exposures
    if not rows_data:
        return "No indexed exposures discovered."
    capped, note = _cap(rows_data, 100)
    rows = [[e.exposure_type, e.url, e.observation_class, e.severity.title()] for e in capped]
    table = _md_table(["Type", "URL", "Observation", "Severity"], rows)
    return f"{table}\n\n*{note}*" if note else table


def _osint(report: ReportData) -> str:
    parts: list[str] = []
    any_content = False

    corp = report.module_data("corporate_intelligence").get("candidates") or []
    parts.append("### Corporate Intelligence")
    if corp:
        any_content = True
        parts.append(
            "_Best-effort name matching against public registries - a match is not proof of ownership._"
        )
        rows = [[c.get("source", "-"), c.get("name") or "-", str(c.get("confidence", "-"))] for c in corp[:20]]
        parts.append(_md_table(["Source", "Candidate Name", "Confidence"], rows))
    else:
        parts.append("_No corporate-registry candidates found._")

    breaches = report.module_data("email_osint").get("domain_breaches")
    parts.append("### Domain Breach History (Have I Been Pwned)")
    if breaches and breaches.get("breach_names"):
        any_content = True
        names = ", ".join(breaches["breach_names"][:15])
        suffix = " (list truncated)" if len(breaches["breach_names"]) > 15 else ""
        parts.append(f"{len(breaches['breach_names'])} named breach(es) reference this domain: {names}.{suffix}")
    elif breaches is not None:
        parts.append("_No domain-wide breach history found._")
    else:
        parts.append("_Not checked - `HIBP_API_KEY` not configured._")

    profiles = report.module_data("social_footprint").get("social_profiles") or []
    confirmed = [p for p in profiles if p.get("status") == "found"]
    parts.append("### Social & Username Footprint")
    if confirmed:
        any_content = True
        rows = [[p.get("platform", "-"), p.get("url", "-"), p.get("source", "-")] for p in confirmed[:25]]
        parts.append(_md_table(["Platform", "URL", "Source"], rows))
    else:
        parts.append("_No confirmed social profiles discovered._")

    if not any_content:
        parts.append(
            "_None of Corporate Intelligence, HIBP or Social Footprint returned results for this "
            "scan - either nothing was found, or the relevant optional credential is not configured "
            "(see the Scan Module Appendix)._"
        )
    return "\n\n".join(parts)


def _cves(report: ReportData) -> str:
    cves = report.cves_by_exploitability()
    if not cves:
        return "No CVE correlations produced for detected technologies."
    capped, note = _cap(cves, 100)
    rows = []
    for c in capped:
        status = (
            "**Confirmed**"
            if c.definitive
            else "Potentially Affected - version confidence insufficient for definitive mapping"
        )
        kev = "**KNOWN EXPLOITED (CISA KEV)**" if c.known_exploited else "-"
        epss = f"{c.epss_score:.2f}" if c.epss_score is not None else "-"
        rows.append([
            c.cve_id, c.technology_name, c.detected_version or "-",
            str(c.cvss_score) if c.cvss_score is not None else "-", epss, status, kev,
        ])
    table = _md_table(["CVE", "Technology", "Version", "CVSS", "EPSS", "Match Status", "KEV"], rows)
    parts = [table]
    parts.append(
        "_CVEs are matched against detected technology names without confirmed versions "
        "unless marked Confirmed; EPSS estimates real-world exploitation likelihood._"
    )
    if note:
        parts.append(f"*{note}*")
    return "\n\n".join(parts)


def _finding_block(f: Any) -> str:
    lines = [f"#### {f.title} - {f.severity.upper()}", ""]
    lines.append(
        f"- Confidence: {f.confidence} ({(f.confidence_band or '').replace('_', ' ').title()})"
    )
    lines.append(f"- Exposure: {(f.exposure or '').title()}")
    lines.append(f"- Risk score: {f.risk_score}")
    if f.description:
        lines.append(f"- Description: {f.description}")
    if f.recommendation:
        lines.append(f"- **Recommendation:** {f.recommendation}")
    if f.location:
        lines.append(f"- Location: {f.location}")
    if f.sources:
        lines.append(f"- Sources: {', '.join(str(s) for s in f.sources)}")
    if f.cve_ids:
        lines.append(f"- Related CVEs: {', '.join(f.cve_ids)}")
    if f.evidence:
        import json as _json

        ev_text = _json.dumps(f.evidence, default=str, ensure_ascii=False, indent=2)
        if len(ev_text) > 800:
            ev_text = ev_text[:799] + "…"
        lines.append("- Evidence:")
        lines.append("```json")
        lines.append(ev_text)
        lines.append("```")
    return "\n".join(lines)


def _findings(report: ReportData) -> str:
    if not report.findings:
        return "No findings recorded."
    parts = []
    for sev in report.severity_order:
        items = report.findings_by_severity(sev)
        if not items:
            continue
        parts.append(f"### {sev.title()} ({len(items)})")
        parts.extend(_finding_block(f) for f in items)
    return "\n\n".join(parts)


def _recommendations(report: ReportData) -> str:
    recs = report.recommendations()
    if not recs:
        return "No recommendations generated."
    return "\n".join(f"{i}. {rec}" for i, rec in enumerate(recs, start=1))


def _module_appendix(report: ReportData) -> str:
    modules = report.modules
    if not modules:
        return "No module execution data recorded."
    rows = []
    for m in modules:
        if m.status == "skipped" and m.skip_reason:
            detail = m.skip_reason
        elif m.status == "failed" and m.error:
            detail = m.error
        else:
            detail = "-"
        duration = f"{m.duration:.2f}s" if m.duration is not None else "-"
        rows.append([
            m.display_name, m.category, m.status.upper(), duration,
            str(m.result_count), str(m.finding_count), detail,
        ])
    return _md_table(
        ["Module", "Category", "Status", "Duration", "Results", "Findings", "Detail"], rows,
    )


def _build_sections(report: ReportData) -> list[tuple[str, str]]:
    return [
        ("Executive Summary", _executive_summary(report)),
        ("Overall Exposure Score", _exposure_score(report)),
        ("Severity Distribution", _severity_distribution(report)),
        ("Asset Statistics", _asset_stats(report)),
        ("Attack Surface Overview", _attack_surface(report)),
        ("Domain Registration", _domain_registration(report)),
        ("Domains & Subdomains", _asset_table(
            report, {"domain", "subdomain"}, "No domains or subdomains discovered.",
        )),
        ("IPs & ASN", _asset_table(
            report, {"ip", "asn", "netblock"}, "No IP addresses or ASN data discovered.",
        )),
        ("DNS Records", _dns_records(report)),
        ("Certificates", _certificates(report)),
        ("Technologies", _technologies_table(report)),
        ("JavaScript Intelligence", _javascript(report)),
        ("APIs", _apis(report)),
        ("URLs", _urls(report)),
        ("Cloud", _technologies_table(
            report,
            technologies=[t for t in report.technologies if "cloud" in (t.category or "").lower()],
            empty_text="No cloud technologies detected.",
        )),
        ("WAF / CDN", _technologies_table(
            report,
            technologies=[t for t in report.technologies if (t.category or "").lower() in ("waf", "cdn", "edge")],
            empty_text="No WAF or CDN technologies detected.",
        )),
        ("Email Security", _email_security(report)),
        ("Historical Intelligence", _historical(report)),
        ("Indexed Exposure", _indexed_exposure(report)),
        ("CVE Intelligence", _cves(report)),
        ("OSINT & Digital Footprint", _osint(report)),
        ("Findings", _findings(report)),
        ("Recommendations", _recommendations(report)),
        ("Scan Module Appendix", _module_appendix(report)),
    ]


def write_markdown_report(report: ReportData, output_path: Path) -> int:
    sections = _build_sections(report)

    toc_lines = ["## Table of Contents", ""]
    toc_lines.extend(f"- [{title}](#{_anchor(title)})" for title, _ in sections)
    toc = "\n".join(toc_lines)

    body_blocks = [f"## {title}\n\n{content}" for title, content in sections]

    text = "\n\n".join([_header_block(report), toc, *body_blocks]) + "\n"
    output_path.write_text(text, encoding="utf-8")
    return len(text.encode("utf-8"))
