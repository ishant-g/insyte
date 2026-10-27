"""PDF report generation - the polished, human-facing export.

Renders the same `ReportData` snapshot as `json_export.py` and
`markdown_export.py` through `reportlab`'s flowable layer
(`SimpleDocTemplate` + `Table`/`Paragraph`/`Spacer`), which is what buys
automatic pagination: nothing here computes page breaks except a handful of
explicit `PageBreak()` calls between major sections for readability. Every
table cell goes through a `Paragraph` so long values (URLs, descriptions)
wrap instead of overflowing the page, and every collection that could be
unbounded is capped with an honest "...and N more" note rather than
rendered in full.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.config import settings
from app.models.enums import ScanMode
from app.services.reports.builder import ReportData

PAGE_SIZE = A4
MARGIN = 40
USABLE_WIDTH = PAGE_SIZE[0] - 2 * MARGIN

# ---- Insyte's own report palette ------------------------------------------
# Deep slate/indigo primary with amber/red severity accents - deliberately
# not the "#1F4E79 corporate blue" the predecessor project used.
COLOR_PRIMARY = colors.HexColor("#1e1b3a")
COLOR_ACCENT = colors.HexColor("#6366f1")
COLOR_TEXT = colors.HexColor("#1f2330")
COLOR_MUTED = colors.HexColor("#64748b")
COLOR_BORDER = colors.HexColor("#cbd5e1")
COLOR_ROW_ALT = colors.HexColor("#f1f5f9")

SEVERITY_HEX = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "informational": "#6b7280",
}
BAND_HEX = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "minimal": "#16a34a",
}

# ---- Typography -------------------------------------------------------
STYLE_COVER_TITLE = ParagraphStyle(
    "CoverTitle", fontName="Helvetica-Bold", fontSize=40, leading=44,
    textColor=COLOR_PRIMARY, alignment=TA_CENTER,
)
STYLE_COVER_TAGLINE = ParagraphStyle(
    "CoverTagline", fontName="Helvetica-Oblique", fontSize=15, leading=20,
    textColor=COLOR_ACCENT, alignment=TA_CENTER, spaceBefore=6,
)
STYLE_COVER_LABEL = ParagraphStyle(
    "CoverLabel", fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=COLOR_PRIMARY,
)
STYLE_COVER_VALUE = ParagraphStyle(
    "CoverValue", fontName="Helvetica", fontSize=10, leading=13, textColor=COLOR_TEXT,
)
STYLE_H1 = ParagraphStyle(
    "H1", fontName="Helvetica-Bold", fontSize=16, leading=20,
    textColor=COLOR_PRIMARY, spaceBefore=4, spaceAfter=8,
)
STYLE_H2 = ParagraphStyle(
    "H2", fontName="Helvetica-Bold", fontSize=12, leading=15,
    textColor=COLOR_ACCENT, spaceBefore=8, spaceAfter=6,
)
STYLE_BODY = ParagraphStyle(
    "Body", fontName="Helvetica", fontSize=9.5, leading=13, textColor=COLOR_TEXT, spaceAfter=4,
)
STYLE_META = ParagraphStyle(
    "Meta", fontName="Helvetica", fontSize=8, leading=11, textColor=COLOR_MUTED, spaceAfter=2,
)
STYLE_NOTE = ParagraphStyle(
    "Note", fontName="Helvetica-Oblique", fontSize=8, leading=11,
    textColor=COLOR_MUTED, spaceBefore=4, spaceAfter=4,
)
STYLE_EMPTY = ParagraphStyle(
    "Empty", fontName="Helvetica-Oblique", fontSize=9.5, leading=13,
    textColor=COLOR_MUTED, spaceAfter=6,
)
# wordWrap="CJK" breaks on any character, not just whitespace - the only
# reliable way to keep an unbroken URL from overflowing a narrow column.
STYLE_CELL = ParagraphStyle(
    "Cell", fontName="Helvetica", fontSize=8, leading=10, textColor=COLOR_TEXT, wordWrap="CJK",
)
STYLE_TABLE_HEADER = ParagraphStyle(
    "TableHeader", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white,
)
STYLE_FINDING_TITLE = ParagraphStyle(
    "FindingTitle", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
    textColor=COLOR_TEXT, spaceBefore=8, spaceAfter=2,
)
STYLE_RECOMMENDATION = ParagraphStyle(
    "Recommendation", fontName="Helvetica", fontSize=9, leading=12,
    textColor=colors.HexColor("#0f5132"), backColor=colors.HexColor("#e7f6ec"),
    borderPadding=4, spaceBefore=2, spaceAfter=2,
)
STYLE_EVIDENCE = ParagraphStyle(
    "Evidence", fontName="Courier", fontSize=7, leading=9,
    textColor=COLOR_MUTED, backColor=colors.HexColor("#f1f5f9"),
    borderPadding=4, spaceBefore=2, spaceAfter=2,
)
STYLE_SCORE = ParagraphStyle(
    "Score", fontName="Helvetica-Bold", fontSize=14, leading=56, textColor=COLOR_TEXT,
)
STYLE_DISCLAIMER = ParagraphStyle(
    "Disclaimer", fontName="Helvetica", fontSize=9, leading=13,
    textColor=colors.HexColor("#7c2d12"), backColor=colors.HexColor("#fff7ed"),
    borderPadding=6, spaceBefore=6, spaceAfter=6,
)
STYLE_KEV = ParagraphStyle(
    "KEV", fontName="Helvetica-Bold", fontSize=7.5, leading=10,
    textColor=colors.white, backColor=colors.HexColor("#dc2626"),
    borderPadding=3, alignment=TA_CENTER,
)


# ---- small formatting helpers ------------------------------------------

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


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _cell(value: Any, style: ParagraphStyle = STYLE_CELL, max_len: int = 300) -> Paragraph:
    return Paragraph(escape(_truncate(_text(value), max_len)), style)


def _cap(items: list, limit: int) -> tuple[list, str | None]:
    if len(items) <= limit:
        return items, None
    remaining = len(items) - limit
    return items[:limit], f"… and {remaining} more (see JSON export for the complete list)."


def _empty(text: str) -> Paragraph:
    return Paragraph(text, STYLE_EMPTY)


def _h1(text: str) -> Paragraph:
    return Paragraph(text, STYLE_H1)


def _h2(text: str) -> Paragraph:
    return Paragraph(text, STYLE_H2)


def _severity_badge(severity: str | None) -> Paragraph:
    hexv = SEVERITY_HEX.get((severity or "").lower(), SEVERITY_HEX["informational"])
    label = (severity or "unknown").title()
    return Paragraph(f'<font color="{hexv}"><b>{escape(label)}</b></font>', STYLE_CELL)


def _data_table(headers: list[str], rows: list[list], col_widths: list[float]) -> Table:
    data = [[Paragraph(escape(h), STYLE_TABLE_HEADER) for h in headers]]
    for row in rows:
        data.append([c if isinstance(c, Paragraph) else _cell(c) for c in row])
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_ROW_ALT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


# ---- section builders -----------------------------------------------------

def _cover_page(report: ReportData) -> list:
    scan = report.scan
    flow: list = [Spacer(1, 130)]
    flow.append(Paragraph(settings.APP_NAME.upper(), STYLE_COVER_TITLE))
    flow.append(Paragraph(settings.APP_TAGLINE, STYLE_COVER_TAGLINE))
    flow.append(Spacer(1, 30))

    rule = Table([[""]], colWidths=[USABLE_WIDTH], rowHeights=[2])
    rule.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), COLOR_ACCENT)]))
    flow.append(rule)
    flow.append(Spacer(1, 36))

    rows = [
        ("Target", report.target),
        ("Scan Mode", _mode_label(scan.mode)),
        ("Scan Status", (scan.status or "").title()),
        ("Scan Date", _fmt_dt(scan.created_at)),
        ("Generated At", _fmt_dt(report.generated_at)),
    ]
    data = [
        [Paragraph(escape(label), STYLE_COVER_LABEL), Paragraph(escape(str(value)), STYLE_COVER_VALUE)]
        for label, value in rows
    ]
    table = Table(data, colWidths=[USABLE_WIDTH * 0.3, USABLE_WIDTH * 0.7])
    table.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    flow.append(table)
    return flow


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

    def _esc(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    for m in failed:
        err = (m.error or "").strip().split("\n")[0]
        if err:
            reasons.append(f"{_esc(m.display_name)}: {_esc(err[:140])}")
    for m in skipped:
        reason = (m.skip_reason or "").strip()
        if reason:
            reasons.append(f"{_esc(m.display_name)}: {_esc(reason[:140])}")
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


def _executive_summary_section(report: ReportData) -> list:
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

    return [_h1("Executive Summary"), Paragraph(f"{s1} {s2} {s3} {s4}", STYLE_BODY)]


def _exposure_score_section(report: ReportData) -> list:
    scan = report.scan
    score = scan.exposure_score if scan.exposure_score is not None else 0
    band = scan.exposure_band or "minimal"
    hexv = BAND_HEX.get(band.lower(), BAND_HEX["minimal"])
    flow = [_h1("Overall Exposure Score")]
    flow.append(Paragraph(
        f'<font size="46" color="{hexv}"><b>{score}</b></font>'
        f'<font size="14" color="#64748b">/100</font>',
        STYLE_SCORE,
    ))
    flow.append(Paragraph(f"Band: <b>{escape(band.title())}</b>", STYLE_BODY))
    flow.append(Spacer(1, 6))
    flow.append(Paragraph(
        "<b>This is Insyte's own prioritisation score, not a standardised CVSS score.</b> "
        "It combines finding severity, confidence, exposure reachability, asset importance "
        "and source corroboration into a single 0-100 view of this scan's overall risk.",
        STYLE_DISCLAIMER,
    ))
    return flow


def _severity_distribution_section(report: ReportData) -> list:
    scan = report.scan
    dist = (scan.summary or {}).get("findings_by_severity") or {}
    flow = [_h1("Severity Distribution")]
    rows = []
    total = 0
    for sev in report.severity_order:
        count = dist.get(sev, len(report.findings_by_severity(sev)))
        total += count
        rows.append([_severity_badge(sev), str(count)])
    if total == 0:
        flow.append(_empty("No findings recorded."))
    else:
        flow.append(_data_table(["Severity", "Count"], rows, [USABLE_WIDTH * 0.7, USABLE_WIDTH * 0.3]))
    return flow


def _asset_stats_section(report: ReportData) -> list:
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
    rows = [[label, str(value)] for label, value in stats]
    return [
        _h1("Asset Statistics"),
        _data_table(["Metric", "Count"], rows, [USABLE_WIDTH * 0.7, USABLE_WIDTH * 0.3]),
    ]


def _attack_surface_section(report: ReportData) -> list:
    assets = report.assets
    flow = [_h1("Attack Surface Overview")]
    if not assets:
        flow.append(_empty("No assets discovered."))
        return flow
    in_scope = len([a for a in assets if a.in_scope])
    out_scope = len(assets) - in_scope
    rel_count = len(report.relationships)
    text = (
        f"Insyte mapped {len(assets)} asset{'s' if len(assets) != 1 else ''} in this scan's graph, "
        f"of which {in_scope} sit within the target's registrable scope and {out_scope} were observed "
        f"as related but out-of-scope context. {rel_count} relationship{'s' if rel_count != 1 else ''} "
        "connect these assets across domains, IPs, certificates and technologies."
    )
    flow.append(Paragraph(text, STYLE_BODY))
    return flow


def _domain_registration_section(report: ReportData) -> list:
    """RDAP registration detail - the one piece of `domain_intelligence`'s
    output that has no home in the typed asset tables (nameservers do; the
    registrar, lifecycle dates and redaction status do not)."""
    flow = [_h1("Domain Registration")]
    data = report.module_data("domain_intelligence")
    if not data or not data.get("available"):
        reason = (data or {}).get("reason")
        flow.append(_empty(
            f"No RDAP registration record available{f' - {reason}' if reason else '.'}"
        ))
        return flow

    def row(label: str, value: Any) -> list:
        return [label, _text(value) if value not in (None, "", []) else "-"]

    def iso_date(value: Any) -> str | None:
        # `module_data()` values have already been through the persistence
        # layer's datetime->ISO-string normalisation, not a live datetime.
        return value[:10] if isinstance(value, str) and len(value) >= 10 else None

    rows = [
        row("Registrar", data.get("registrar")),
        row("Registered", iso_date(data.get("registration_date"))),
        row("Expires", iso_date(data.get("expiration_date"))),
        row("Last changed", iso_date(data.get("last_changed"))),
        row("Nameservers", ", ".join(data.get("nameservers") or []) or None),
        row("DNSSEC signed", data.get("dnssec_signed")),
        row(
            "Registrant",
            "Redacted for privacy" if data.get("registrant_redacted") else data.get("registrant"),
        ),
    ]
    flow.append(_data_table(
        ["Field", "Value"], rows,
        [USABLE_WIDTH * 0.30, USABLE_WIDTH * 0.70],
    ))
    return flow


def _asset_table_section(title: str, report: ReportData, types: set[str], empty_text: str) -> list:
    in_scope_rows, collapsed = report.scoped_assets(types)
    flow = [_h1(title)]
    if not in_scope_rows and not collapsed:
        flow.append(_empty(empty_text))
        return flow
    if in_scope_rows:
        capped, note = _cap(in_scope_rows, 100)
        data_rows = []
        for a in capped:
            srcs = ", ".join(str(s) for s in (a.sources or []))
            data_rows.append([a.value, str(a.confidence), srcs or "-"])
        flow.append(_data_table(
            ["Value", "Confidence", "Sources"], data_rows,
            [USABLE_WIDTH * 0.45, USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.40],
        ))
        if note:
            flow.append(Paragraph(note, STYLE_NOTE))
    for line in collapsed:
        flow.append(Paragraph(f"<i>{escape(line)}</i>", STYLE_NOTE))
    return flow


def _dns_section(report: ReportData) -> list:
    flow = [_h1("DNS Records")]
    rows = report.dns_records
    if not rows:
        flow.append(_empty("No DNS records discovered."))
        return flow
    capped, note = _cap(rows, 100)
    data_rows = [[d.name, d.record_type, d.value] for d in capped]
    flow.append(_data_table(
        ["Name", "Type", "Value"], data_rows,
        [USABLE_WIDTH * 0.35, USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.50],
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _expired_badge(is_expired: bool) -> Paragraph:
    if is_expired:
        return Paragraph('<font color="#dc2626"><b>EXPIRED</b></font>', STYLE_CELL)
    return Paragraph('<font color="#16a34a">Valid</font>', STYLE_CELL)


def _certificates_section(report: ReportData) -> list:
    flow = [_h1("Certificates")]
    certs = report.certificates
    if not certs:
        flow.append(_empty("No certificates discovered."))
        return flow
    capped, note = _cap(certs, 100)
    rows = []
    for c in capped:
        if c.from_ct_log:
            validity = "n/a (CT log hostnames only)"
            badge = "CT log"
        else:
            validity = f"{_fmt_date(c.not_before)} – {_fmt_date(c.not_after)}"
            badge = _expired_badge(c.is_expired)
        rows.append([c.subject_cn or "-", c.issuer_org or "-", validity, badge])
    flow.append(_data_table(
        ["Subject CN", "Issuer", "Validity", "Status"], rows,
        [USABLE_WIDTH * 0.30, USABLE_WIDTH * 0.30, USABLE_WIDTH * 0.25, USABLE_WIDTH * 0.15],
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _technologies_section(
    report: ReportData,
    technologies: list | None = None,
    title: str = "Technologies",
    empty_text: str = "No technologies detected.",
) -> list:
    flow = [_h1(title)]
    techs = report.technologies if technologies is None else technologies
    if not techs:
        flow.append(_empty(empty_text))
        return flow
    capped, note = _cap(techs, 100)
    rows = [[t.name, t.version or "unknown", t.category or "-", str(t.confidence)] for t in capped]
    flow.append(_data_table(
        ["Name", "Version", "Category", "Confidence"], rows,
        [USABLE_WIDTH * 0.3, USABLE_WIDTH * 0.2, USABLE_WIDTH * 0.3, USABLE_WIDTH * 0.2],
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _javascript_section(report: ReportData) -> list:
    flow = [_h1("JavaScript Intelligence")]
    files = report.javascript
    if not files:
        flow.extend(_client_side_empty(report, "No JavaScript files analysed."))
        return flow
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
    flow.append(_data_table(
        ["URL", "3rd Party", "Libraries", "Endpoints", "Source Map", "Secrets"], rows,
        [USABLE_WIDTH * 0.30, USABLE_WIDTH * 0.10, USABLE_WIDTH * 0.25,
         USABLE_WIDTH * 0.10, USABLE_WIDTH * 0.10, USABLE_WIDTH * 0.15],
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))

    # Secret indicators are already masked at detection time (see
    # services/artifacts/masking.py) - only the stored type/masked/severity
    # fields are ever rendered, never re-processed.
    secret_rows = []
    for j in files:
        for indicator in (j.secret_indicators or []):
            if not isinstance(indicator, dict):
                continue
            secret_rows.append([
                j.url,
                indicator.get("type", "-"),
                indicator.get("masked", "-"),
                indicator.get("severity", "-"),
            ])
    if secret_rows:
        flow.append(Spacer(1, 8))
        flow.append(_h2("Secret Indicators (masked)"))
        capped_secrets, snote = _cap(secret_rows, 100)
        flow.append(_data_table(
            ["File", "Type", "Masked Value", "Severity"], capped_secrets,
            [USABLE_WIDTH * 0.30, USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.30, USABLE_WIDTH * 0.20],
        ))
        if snote:
            flow.append(Paragraph(snote, STYLE_NOTE))
    return flow


def _osint_section(report: ReportData) -> list:
    """Corporate-intelligence candidates, HIBP domain-breach hits, and the
    social/username footprint - three optional, credential-gated sources
    folded into one section (each with its own empty-state) rather than
    three separately-headed ones, so a scan with none of them configured
    does not reintroduce the empty-page problem the whitespace pass fixed.
    """
    flow = [_h1("OSINT & Digital Footprint")]
    any_content = False

    corp = report.module_data("corporate_intelligence").get("candidates") or []
    flow.append(_h2("Corporate Intelligence"))
    if corp:
        any_content = True
        rows = [[c.get("source", "-"), c.get("name") or "-", str(c.get("confidence", "-"))] for c in corp[:20]]
        flow.append(Paragraph(
            "Best-effort name matching against public registries - a match is not proof of ownership.",
            STYLE_NOTE,
        ))
        flow.append(_data_table(
            ["Source", "Candidate Name", "Confidence"], rows,
            [USABLE_WIDTH * 0.25, USABLE_WIDTH * 0.55, USABLE_WIDTH * 0.20],
        ))
    else:
        flow.append(_empty("No corporate-registry candidates found."))
    flow.append(Spacer(1, 8))

    breaches = report.module_data("email_osint").get("domain_breaches")
    flow.append(_h2("Domain Breach History (Have I Been Pwned)"))
    if breaches and breaches.get("breach_names"):
        any_content = True
        flow.append(Paragraph(
            f"{len(breaches['breach_names'])} named breach(es) reference this domain: "
            f"{', '.join(breaches['breach_names'][:15])}."
            + (" (list truncated)" if len(breaches["breach_names"]) > 15 else ""),
            STYLE_BODY,
        ))
    elif breaches is not None:
        flow.append(_empty("No domain-wide breach history found."))
    else:
        flow.append(_empty("Not checked - HIBP_API_KEY not configured."))
    flow.append(Spacer(1, 8))

    profiles = report.module_data("social_footprint").get("social_profiles") or []
    flow.append(_h2("Social & Username Footprint"))
    confirmed = [p for p in profiles if p.get("status") == "found"]
    if confirmed:
        any_content = True
        rows = [[p.get("platform", "-"), p.get("url", "-"), p.get("source", "-")] for p in confirmed[:25]]
        flow.append(_data_table(
            ["Platform", "URL", "Source"], rows,
            [USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.55, USABLE_WIDTH * 0.25],
        ))
    else:
        flow.append(_empty("No confirmed social profiles discovered."))

    if not any_content:
        flow.append(Spacer(1, 4))
        flow.append(Paragraph(
            "None of Corporate Intelligence, HIBP or Social Footprint returned results for "
            "this scan - either nothing was found, or the relevant optional credential is "
            "not configured (see the Scan Module Appendix).",
            STYLE_NOTE,
        ))
    return flow


def _client_side_empty(report: ReportData, empty_text: str) -> list:
    """Passive-mode scans never fetch pages, so they structurally cannot see
    JavaScript or API endpoints - say so instead of leaving the reader to
    assume there is no client-side attack surface."""
    flow = [_empty(empty_text)]
    if report.is_passive:
        flow.append(Paragraph(
            "Passive mode does not collect JavaScript or API endpoint data by design; "
            "run a Web Surface scan for client-side attack surface.",
            STYLE_NOTE,
        ))
    return flow


def _apis_section(report: ReportData) -> list:
    flow = [_h1("APIs")]
    apis = report.api_endpoints
    if not apis:
        flow.extend(_client_side_empty(report, "No API endpoints discovered."))
        return flow
    capped, note = _cap(apis, 100)
    rows = [[a.url, a.api_type or "-", a.method or "-", a.auth_hint or "-", "Not validated"] for a in capped]
    flow.append(_data_table(
        ["URL", "Type", "Method", "Auth Hint", "Validation"], rows,
        [USABLE_WIDTH * 0.40, USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.10,
         USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.20],
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _urls_section(report: ReportData) -> list:
    flow = [_h1("URLs")]
    urls = report.urls
    if not urls:
        flow.append(_empty("No URLs discovered."))
        return flow

    counts = Counter(u.classification for u in urls)
    by_class: dict[str, list] = defaultdict(list)
    for u in urls:
        by_class[u.classification].append(u)

    summary_rows = [[cls or "unknown", str(n)] for cls, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    flow.append(_data_table(["Classification", "Count"], summary_rows, [USABLE_WIDTH * 0.7, USABLE_WIDTH * 0.3]))
    flow.append(Spacer(1, 8))

    top_n = 10
    for cls, items in sorted(by_class.items(), key=lambda kv: -len(kv[1])):
        flow.append(_h2(f"{(cls or 'unknown').title()} ({len(items)})"))
        top, note = _cap(items, top_n)
        rows = [[u.url, str(u.status_code) if u.status_code is not None else "-"] for u in top]
        flow.append(_data_table(["URL", "Status"], rows, [USABLE_WIDTH * 0.85, USABLE_WIDTH * 0.15]))
        if note:
            flow.append(Paragraph(note, STYLE_NOTE))
        flow.append(Spacer(1, 4))
    return flow


def _email_security_section(report: ReportData) -> list:
    flow = [_h1("Email Security")]
    posture = report.module_data("email_security").get("posture") or {}
    findings = [f for f in report.findings if f.category == "email_security" or f.module_id == "email_security"]

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
        flow.append(_data_table(
            ["Signal", "Status"], rows,
            [USABLE_WIDTH * 0.40, USABLE_WIDTH * 0.60],
        ))
        flow.append(Spacer(1, 8))

    if not findings:
        flow.append(_empty("No email security posture issues found." if posture else "No email security data collected."))
        return flow
    rows = [[f.title, _severity_badge(f.severity), f.description or "-"] for f in findings]
    flow.append(_data_table(
        ["Title", "Severity", "Description"], rows,
        [USABLE_WIDTH * 0.3, USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.55],
    ))
    return flow


def _historical_section(report: ReportData) -> list:
    flow = [_h1("Historical Intelligence")]
    events = report.historical_events
    if not events:
        flow.append(_empty("No historical events discovered."))
        return flow
    capped, note = _cap(events, 150)
    by_year: dict[Any, list] = defaultdict(list)
    for e in capped:
        year = e.first_seen.year if e.first_seen else "Unknown"
        by_year[year].append(e)

    def _sort_key(year: Any) -> tuple:
        return (year == "Unknown", -(year if isinstance(year, int) else 0))

    for year in sorted(by_year.keys(), key=_sort_key):
        items = by_year[year]
        flow.append(_h2(str(year)))
        rows = [[h.asset_type, h.value, h.source_id, h.status] for h in items]
        flow.append(_data_table(
            ["Type", "Value", "Source", "Status"], rows,
            [USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.40, USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.25],
        ))
        flow.append(Spacer(1, 4))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _indexed_exposure_section(report: ReportData) -> list:
    flow = [_h1("Indexed Exposure")]
    rows_data = report.indexed_exposures
    if not rows_data:
        flow.append(_empty("No indexed exposures discovered."))
        return flow
    capped, note = _cap(rows_data, 100)
    rows = [[e.exposure_type, e.url, e.observation_class, _severity_badge(e.severity)] for e in capped]
    flow.append(_data_table(
        ["Type", "URL", "Observation", "Severity"], rows,
        [USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.40, USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.20],
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _cve_section(report: ReportData) -> list:
    flow = [_h1("CVE Intelligence")]
    cves = report.cves_by_exploitability()
    if not cves:
        flow.append(_empty("No CVE correlations produced for detected technologies."))
        return flow
    capped, note = _cap(cves, 100)
    rows = []
    for c in capped:
        if c.definitive:
            status = Paragraph('<font color="#16a34a"><b>Confirmed</b></font>', STYLE_CELL)
        else:
            status = Paragraph(
                '<font color="#d97706">Potentially Affected - version confidence '
                "insufficient for definitive mapping</font>",
                STYLE_CELL,
            )
        kev = (
            Paragraph("KNOWN EXPLOITED (CISA KEV)", STYLE_KEV)
            if c.known_exploited else Paragraph("-", STYLE_CELL)
        )
        epss = f"{c.epss_score:.2f}" if c.epss_score is not None else "-"
        rows.append([
            c.cve_id,
            c.technology_name,
            c.detected_version or "-",
            str(c.cvss_score) if c.cvss_score is not None else "-",
            epss,
            status,
            kev,
        ])
    flow.append(_data_table(
        ["CVE", "Technology", "Version", "CVSS", "EPSS", "Match Status", "KEV"], rows,
        [USABLE_WIDTH * 0.11, USABLE_WIDTH * 0.15, USABLE_WIDTH * 0.09,
         USABLE_WIDTH * 0.08, USABLE_WIDTH * 0.08, USABLE_WIDTH * 0.31, USABLE_WIDTH * 0.18],
    ))
    flow.append(Paragraph(
        "CVEs are matched against detected technology names without confirmed versions "
        "unless marked Confirmed. EPSS estimates the probability of real-world "
        "exploitation in the next 30 days; KEV marks vulnerabilities CISA lists as "
        "actively exploited.",
        STYLE_NOTE,
    ))
    if note:
        flow.append(Paragraph(note, STYLE_NOTE))
    return flow


def _finding_block(f: Any) -> list:
    hexv = SEVERITY_HEX.get((f.severity or "").lower(), SEVERITY_HEX["informational"])
    parts: list = [Paragraph(
        f'{escape(f.title)} &nbsp; <font color="{hexv}"><b>[{escape((f.severity or "").upper())}]</b></font>',
        STYLE_FINDING_TITLE,
    )]
    meta = (
        f"Confidence: {f.confidence} ({(f.confidence_band or '').replace('_', ' ').title()}) &middot; "
        f"Exposure: {(f.exposure or '').title()} &middot; Risk score: {f.risk_score}"
    )
    parts.append(Paragraph(meta, STYLE_META))
    if f.description:
        parts.append(Paragraph(escape(f.description), STYLE_BODY))
    if f.recommendation:
        parts.append(Paragraph(f"<b>Recommendation:</b> {escape(f.recommendation)}", STYLE_RECOMMENDATION))
    if f.location:
        parts.append(Paragraph(f"<b>Location:</b> {escape(f.location)}", STYLE_META))
    if f.sources:
        src_text = _truncate(", ".join(str(s) for s in f.sources), 300)
        parts.append(Paragraph(f"<b>Sources:</b> {escape(src_text)}", STYLE_META))
    if f.cve_ids:
        parts.append(Paragraph(f"<b>Related CVEs:</b> {escape(', '.join(f.cve_ids))}", STYLE_META))
    if f.evidence:
        ev_text = _truncate(json.dumps(f.evidence, default=str, ensure_ascii=False), 500)
        parts.append(Paragraph(f"<b>Evidence:</b> {escape(ev_text)}", STYLE_EVIDENCE))
    parts.append(Spacer(1, 10))
    return parts


def _findings_section(report: ReportData) -> list:
    flow = [_h1("Findings")]
    if not report.findings:
        flow.append(_empty("No findings recorded."))
        return flow
    for sev in report.severity_order:
        items = report.findings_by_severity(sev)
        if not items:
            continue
        flow.append(_h2(f"{sev.title()} ({len(items)})"))
        for f in items:
            flow.extend(_finding_block(f))
    return flow


def _recommendations_section(report: ReportData) -> list:
    flow = [_h1("Recommendations")]
    recs = report.recommendations()
    if not recs:
        flow.append(_empty("No recommendations generated."))
        return flow
    for i, rec in enumerate(recs, start=1):
        flow.append(Paragraph(f"{i}. {escape(rec)}", STYLE_BODY))
    return flow


def _module_status_badge(status: str | None) -> Paragraph:
    color_map = {
        "completed": "#16a34a",
        "failed": "#dc2626",
        "skipped": "#6b7280",
        "running": "#2563eb",
        "queued": "#6b7280",
    }
    hexv = color_map.get(status or "", "#6b7280")
    return Paragraph(f'<font color="{hexv}"><b>{escape((status or "").upper())}</b></font>', STYLE_CELL)


def _module_appendix_section(report: ReportData) -> list:
    flow = [_h1("Scan Module Appendix")]
    modules = report.modules
    if not modules:
        flow.append(_empty("No module execution data recorded."))
        return flow
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
            m.display_name, m.category, _module_status_badge(m.status),
            duration, str(m.result_count), str(m.finding_count), detail,
        ])
    flow.append(_data_table(
        ["Module", "Category", "Status", "Duration", "Results", "Findings", "Detail"], rows,
        [USABLE_WIDTH * 0.20, USABLE_WIDTH * 0.12, USABLE_WIDTH * 0.12, USABLE_WIDTH * 0.10,
         USABLE_WIDTH * 0.10, USABLE_WIDTH * 0.10, USABLE_WIDTH * 0.26],
    ))
    return flow


def _stamp_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(COLOR_MUTED)
    canvas.drawString(MARGIN, 20, f"{settings.APP_NAME} - {settings.APP_TAGLINE}")
    canvas.drawRightString(PAGE_SIZE[0] - MARGIN, 20, f"Page {doc.page}")
    canvas.restoreState()


def write_pdf_report(report: ReportData, output_path: Path) -> int:
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=PAGE_SIZE,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title=f"{settings.APP_NAME} Exposure Intelligence Report - {report.target}",
        author=settings.APP_NAME,
    )

    # Beyond the cover page, sections are left to reportlab's automatic
    # flowable pagination rather than forced onto their own page each. A
    # scan with several empty categories (no JavaScript, no CVEs, no
    # indexed exposures...) would otherwise produce a forced page break
    # per empty section - a heading plus one "nothing found" line,
    # stranded on an otherwise blank page. Only the cover (a title page by
    # convention) and Findings (routinely the longest section, and only
    # when it actually has rows) get an explicit break.
    story: list = []
    story.extend(_cover_page(report))
    story.append(PageBreak())

    story.extend(_executive_summary_section(report))
    story.append(Spacer(1, 14))
    story.extend(_exposure_score_section(report))
    story.append(Spacer(1, 14))
    story.extend(_severity_distribution_section(report))
    story.append(Spacer(1, 14))
    story.extend(_asset_stats_section(report))
    story.append(Spacer(1, 14))

    story.extend(_attack_surface_section(report))
    story.append(Spacer(1, 10))
    story.extend(_domain_registration_section(report))
    story.append(Spacer(1, 10))
    story.extend(_asset_table_section(
        "Domains & Subdomains", report, {"domain", "subdomain"},
        "No domains or subdomains discovered.",
    ))
    story.append(Spacer(1, 10))
    story.extend(_asset_table_section(
        "IPs & ASN", report, {"ip", "asn", "netblock"},
        "No IP addresses or ASN data discovered.",
    ))
    story.append(Spacer(1, 14))

    story.extend(_dns_section(report))
    story.append(Spacer(1, 14))
    story.extend(_certificates_section(report))
    story.append(Spacer(1, 14))
    story.extend(_technologies_section(report))
    story.append(Spacer(1, 14))

    story.extend(_javascript_section(report))
    story.append(Spacer(1, 14))
    story.extend(_apis_section(report))
    story.append(Spacer(1, 14))
    story.extend(_urls_section(report))
    story.append(Spacer(1, 14))

    story.extend(_technologies_section(
        report,
        technologies=[t for t in report.technologies if "cloud" in (t.category or "").lower()],
        title="Cloud",
        empty_text="No cloud technologies detected.",
    ))
    story.append(Spacer(1, 10))
    story.extend(_technologies_section(
        report,
        technologies=[t for t in report.technologies if (t.category or "").lower() in ("waf", "cdn", "edge")],
        title="WAF / CDN",
        empty_text="No WAF or CDN technologies detected.",
    ))
    story.append(Spacer(1, 10))
    story.extend(_email_security_section(report))
    story.append(Spacer(1, 14))

    story.extend(_historical_section(report))
    story.append(Spacer(1, 14))
    story.extend(_indexed_exposure_section(report))
    story.append(Spacer(1, 14))
    story.extend(_cve_section(report))
    story.append(Spacer(1, 14))
    story.extend(_osint_section(report))
    story.append(Spacer(1, 14))

    # Findings is the one section worth a guaranteed fresh start - but
    # only when there's something to read; an empty scan's "No findings
    # recorded." line can share the page like everything else.
    if report.findings:
        story.append(PageBreak())
    story.extend(_findings_section(report))
    story.append(Spacer(1, 14))

    story.extend(_recommendations_section(report))
    story.append(Spacer(1, 14))

    story.extend(_module_appendix_section(report))

    doc.build(story, onFirstPage=_stamp_footer, onLaterPages=_stamp_footer)
    return output_path.stat().st_size
