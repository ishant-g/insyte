"""Security Header Intelligence.

Inspects the response headers Web Surface Collection already retrieved and
reports each security-relevant header as present, missing, weak or
suspicious. A missing header becomes a low-severity finding, not "a
vulnerability" - the brief is explicit that not every gap is one, and
overstating these is how security tooling trains people to ignore it.
"""

from __future__ import annotations

import re

from app.core.contracts import FindingRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import (
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: header -> (severity if missing, recommendation)
_EXPECTED_HEADERS: dict[str, tuple[Severity, str]] = {
    "strict-transport-security": (
        Severity.LOW,
        "Send Strict-Transport-Security with a max-age of at least one year "
        "to prevent protocol-downgrade attacks against future visits.",
    ),
    "content-security-policy": (
        Severity.LOW,
        "Define a Content-Security-Policy to constrain where scripts, "
        "styles and frames may load from.",
    ),
    "x-content-type-options": (
        Severity.INFORMATIONAL,
        "Send X-Content-Type-Options: nosniff to stop browsers from "
        "MIME-sniffing responses away from the declared content type.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Send X-Frame-Options or a CSP frame-ancestors directive to "
        "control whether the page can be framed by another origin.",
    ),
    "referrer-policy": (
        Severity.INFORMATIONAL,
        "Send a Referrer-Policy to control how much of the URL is leaked "
        "to third-party destinations on navigation.",
    ),
    "permissions-policy": (
        Severity.INFORMATIONAL,
        "Send a Permissions-Policy to explicitly opt out of browser "
        "features (camera, microphone, geolocation) the site does not use.",
    ),
    "cross-origin-opener-policy": (
        Severity.INFORMATIONAL,
        "Send Cross-Origin-Opener-Policy: same-origin to isolate the page "
        "from cross-origin popups that could otherwise reference it.",
    ),
    "cross-origin-resource-policy": (
        Severity.INFORMATIONAL,
        "Send Cross-Origin-Resource-Policy to control which origins may "
        "load this response as a sub-resource.",
    ),
}

_WEAK_CSP_SOURCES = ("*", "unsafe-inline", "unsafe-eval", "data:")


class SecurityHeaderModule(IntelligenceModule):
    id = "security_headers"
    name = "Security Header Intelligence"
    description = (
        "Inspects HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
        "Referrer-Policy, Permissions-Policy and Cross-Origin isolation "
        "headers on every retrieved page."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("web_surface",)
    timeout = 20.0
    order = 71

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        headers_by_url = ctx.response_headers()
        if not headers_by_url:
            output.data["pages_analysed"] = 0
            return output

        # Analyse the target's own homepage in depth (the finding that
        # matters); summarise the rest to avoid one finding per page.
        primary_url = next(iter(headers_by_url))
        for url in headers_by_url:
            if _is_homepage(url):
                primary_url = url
                break
        primary_headers = {k.lower(): v for k, v in headers_by_url[primary_url].items()}

        per_header: dict[str, dict] = {}
        for header, (severity, recommendation) in _EXPECTED_HEADERS.items():
            value = primary_headers.get(header)
            if value is None:
                per_header[header] = {"status": "missing"}
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.SECURITY_HEADER,
                        severity=severity,
                        title=f"{_display_name(header)} not set",
                        description=(
                            f"The response from {primary_url} does not include "
                            f"a {_display_name(header)} header."
                        ),
                        recommendation=recommendation,
                        location=primary_url,
                        confidence=97,
                        exposure=ExposureLevel.DIRECT,
                        sources=["web_surface"],
                        evidence={"header": header, "response_headers_sample": list(primary_headers)[:15]},
                    )
                )
            else:
                weakness = _weakness(header, value)
                per_header[header] = {"status": "weak" if weakness else "present", "value": value[:300]}
                if weakness:
                    output.findings.append(
                        FindingRecord(
                            module_id=self.id,
                            category=FindingCategory.SECURITY_HEADER,
                            severity=Severity.LOW,
                            title=f"Weak {_display_name(header)} configuration",
                            description=weakness,
                            recommendation=recommendation,
                            location=primary_url,
                            confidence=85,
                            exposure=ExposureLevel.DIRECT,
                            sources=["web_surface"],
                            evidence={"header": header, "value": value[:300]},
                        )
                    )

        server_header = primary_headers.get("server")
        powered_by = primary_headers.get("x-powered-by")
        disclosure: dict = {}
        if server_header and re.search(r"\d", server_header):
            disclosure["server"] = server_header
        if powered_by:
            disclosure["x_powered_by"] = powered_by
        if disclosure:
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.TECHNOLOGY_DISCLOSURE,
                    severity=Severity.INFORMATIONAL,
                    title="Server software version disclosed in response headers",
                    description=(
                        "One or more response headers reveal specific software "
                        f"versions: {disclosure}."
                    ),
                    recommendation=(
                        "Suppress version numbers in Server and X-Powered-By "
                        "headers to reduce reconnaissance value to an attacker."
                    ),
                    location=primary_url,
                    confidence=90,
                    exposure=ExposureLevel.DIRECT,
                    sources=["web_surface"],
                    evidence=disclosure,
                )
            )

        cache_control = primary_headers.get("cache-control")

        output.data["headers_by_status"] = per_header
        output.data["server_info"] = {
            "server": server_header,
            "powered_by": powered_by,
            "cache_control": cache_control,
        }
        output.data["pages_analysed"] = len(headers_by_url)
        output.data["primary_url"] = primary_url
        return output


def _is_homepage(url: str) -> bool:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return parts.path in ("", "/")


def _display_name(header: str) -> str:
    return "-".join(part.capitalize() for part in header.split("-"))


def _weakness(header: str, value: str) -> str | None:
    lowered = value.lower()
    if header == "strict-transport-security":
        match = re.search(r"max-age=(\d+)", lowered)
        if not match or int(match.group(1)) < 15552000:  # 180 days
            return f"Strict-Transport-Security max-age is below the recommended six months ({value[:200]})."
    if header == "content-security-policy":
        if any(weak in lowered for weak in _WEAK_CSP_SOURCES):
            return f"Content-Security-Policy permits a broad or unsafe source ({value[:200]})."
    if header == "x-frame-options" and lowered not in ("deny", "sameorigin"):
        return f"X-Frame-Options value '{value}' is non-standard and may not be enforced by all browsers."
    if header == "referrer-policy" and lowered in ("unsafe-url",):
        return "Referrer-Policy is set to 'unsafe-url', which leaks the full URL to third-party destinations."
    return None
