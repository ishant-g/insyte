"""WAF / CDN / Edge Intelligence.

Passive fingerprinting of the edge infrastructure in front of the target:
headers, cookies, DNS delegation and TLS certificate issuer all leak which
CDN or WAF is terminating the connection. Every result is a confidence
score, never a certainty - the brief is explicit that passive fingerprinting
is not absolute proof.
"""

from __future__ import annotations

from app.core.contracts import FindingRecord, ModuleOutput, TechnologyRecord
from app.core.target import TargetType
from app.models.enums import (
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: provider -> list of (signal_kind, needle)
_PROVIDER_SIGNALS: dict[str, list[tuple[str, str]]] = {
    "Cloudflare": [
        ("header", "cf-ray"), ("header", "cf-cache-status"), ("header", "server:cloudflare"),
        ("cookie", "__cfduid"), ("cookie", "cf_clearance"),
        ("nameserver", "cloudflare.com"), ("issuer", "cloudflare"),
    ],
    "Amazon CloudFront": [
        ("header", "x-amz-cf-id"), ("header", "x-amz-cf-pop"), ("header", "via:cloudfront"),
    ],
    "Fastly": [("header", "x-served-by:fastly"), ("header", "x-fastly-request-id"), ("header", "via:varnish")],
    "Akamai": [("header", "x-akamai-transformed"), ("header", "server:akamaighost"), ("nameserver", "akam.net")],
    "Azure Front Door": [("header", "x-azure-ref"), ("header", "x-azure-fdid")],
    "Google Cloud CDN": [("header", "via:google"), ("header", "server:gws")],
    "Vercel": [("header", "x-vercel-id"), ("header", "x-vercel-cache"), ("nameserver", "vercel-dns.com")],
    "Netlify": [("header", "x-nf-request-id"), ("header", "server:netlify")],
    "Sucuri": [("header", "x-sucuri-id"), ("header", "server:sucuri")],
    "Imperva Incapsula": [("header", "x-iinfo"), ("cookie", "visid_incap")],
    "F5 BIG-IP ASM": [("cookie", "ts01"), ("header", "server:big-ip")],
    "AWS WAF": [("header", "x-amzn-requestid"), ("header", "x-amzn-waf-action")],
    "Barracuda WAF": [("cookie", "barra_counter_session")],
}

_WAF_NAMES = frozenset(
    {"Sucuri", "Imperva Incapsula", "F5 BIG-IP ASM", "AWS WAF", "Barracuda WAF"}
)
_CDN_NAMES = frozenset(
    {"Cloudflare", "Amazon CloudFront", "Fastly", "Akamai", "Azure Front Door", "Google Cloud CDN", "Vercel", "Netlify"}
)


class WafCdnIntelligenceModule(IntelligenceModule):
    id = "waf_cdn_intelligence"
    name = "WAF / CDN / Edge Intelligence"
    description = (
        "Passive fingerprinting of the edge layer in front of the target - "
        "CDN, WAF and reverse-proxy - from headers, cookies, DNS delegation "
        "and certificate issuer, each with a confidence score."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("dns_intelligence", "certificate_intelligence")
    timeout = 20.0
    order = 72

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)

        headers_by_url = ctx.response_headers()
        primary_headers: dict[str, str] = {}
        if headers_by_url:
            primary_headers = {
                k.lower(): v for k, v in next(iter(headers_by_url.values())).items()
            }

        nameserver_providers = ctx.data_of("dns_intelligence", "nameserver_providers", []) or []
        issuer = (ctx.data_of("certificate_intelligence", "live_certificate", {}) or {}).get(
            "issuer_cn", ""
        ) or ""

        detected: dict[str, list[str]] = {}
        for provider, signals in _PROVIDER_SIGNALS.items():
            evidence: list[str] = []
            for kind, needle in signals:
                if kind == "header":
                    header_name, _, expected_value = needle.partition(":")
                    value = primary_headers.get(header_name, "")
                    if expected_value:
                        if expected_value.lower() in value.lower():
                            evidence.append(f"header {header_name}: {value[:60]}")
                    elif header_name in primary_headers:
                        evidence.append(f"header present: {header_name}")
                elif kind == "cookie":
                    set_cookie = primary_headers.get("set-cookie", "").lower()
                    if needle.lower() in set_cookie:
                        evidence.append(f"cookie: {needle}")
                elif kind == "nameserver":
                    if any(needle in (p or "").lower() for p in nameserver_providers):
                        evidence.append(f"nameserver provider: {needle}")
                elif kind == "issuer" and needle.lower() in issuer.lower():
                    evidence.append(f"certificate issuer: {issuer}")
            if evidence:
                detected[provider] = evidence

        for provider, evidence in detected.items():
            confidence = min(96, 55 + len(evidence) * 15)
            kind = "waf" if provider in _WAF_NAMES else "cdn" if provider in _CDN_NAMES else "edge"
            output.technologies.append(
                TechnologyRecord(
                    name=provider,
                    category=kind,
                    confidence=confidence,
                    sources=["headers", "dns", "tls"],
                    evidence={"signals": evidence},
                )
            )

        cdns = [p for p in detected if p in _CDN_NAMES]
        wafs = [p for p in detected if p in _WAF_NAMES]

        if not wafs and headers_by_url:
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.ATTACK_SURFACE,
                    severity=Severity.INFORMATIONAL,
                    title="No web application firewall detected",
                    description=(
                        "Passive fingerprinting found no evidence of a WAF or "
                        "bot-protection layer in front of the target."
                    ),
                    recommendation=(
                        "This is informational: passive fingerprinting cannot "
                        "prove a WAF's absence, only that no signal for one "
                        "was observed."
                    ),
                    confidence=45,
                    exposure=ExposureLevel.INFERRED,
                    sources=["headers"],
                )
            )

        output.data["summary"] = {
            "cdn_providers": cdns,
            "waf_providers": wafs,
            "edge_providers": [p for p in detected if p not in _CDN_NAMES and p not in _WAF_NAMES],
            "detections": {p: ev for p, ev in detected.items()},
        }
        return output
