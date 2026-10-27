"""JavaScript Intelligence Engine - Insyte's flagship feature.

Every JavaScript file Web Surface Collection retrieved is analysed for:
libraries and their versions, API/GraphQL/WebSocket endpoints, referenced
domains and IPs, emails, source-map references, third-party integrations,
and secret-shaped values. Nothing here executes the script; every signal is
extracted with regular expressions and light parsing over the raw text.

Secret handling is the one rule that overrides everything else in this
module: `services/artifacts/masking.py` is applied before a secret
indicator leaves this module, so a full credential never reaches the
`JavaScriptRecord`, the database, the API, or a report. See that module's
docstring for exactly what "masked" means.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlsplit

from app.core.contracts import (
    ApiEndpointRecord,
    FindingRecord,
    JavaScriptRecord,
    ModuleOutput,
    ObservationRecord,
)
from app.core.target import TargetType, is_subdomain_of, normalize_hostname
from app.core.tld_list import has_known_tld
from app.models.enums import (
    ApiType,
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ObservationStatus,
    ScanMode,
    Severity,
    SourceKind,
)
from app.modules.base import IntelligenceModule, ModuleContext
from app.services.artifacts.masking import find_secrets

_ENDPOINT_RE = re.compile(
    r"""["'`](/(?:api|v[0-9]+|graphql|rest|rpc|oauth|auth|admin)[a-zA-Z0-9_\-/{}.]*)["'`]""",
    re.I,
)
_ABSOLUTE_URL_RE = re.compile(r"""https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>\\]*)?""")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I
)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*]+)")
_WEBSOCKET_RE = re.compile(r"""["'`](wss?://[^\s"'`<>\\]+)["'`]""")
_COMMENT_RE = re.compile(r"/\*(.*?)\*/|//([^\n]*)", re.S)
_CONFIG_OBJECT_RE = re.compile(
    r"\b(?:window\.)?(?:__[A-Z0-9_]+__|APP_CONFIG|window\.config|ENV)\s*=\s*(\{.{0,400}?\})",
    re.S,
)
_ENV_HINT_RE = re.compile(
    r"\b(process\.env\.[A-Z0-9_]+|import\.meta\.env\.[A-Z0-9_]+)\b"
)
_PACKAGE_COMMENT_RE = re.compile(
    r"/\*!?\s*([\w.@/\-]+)\s+v?(\d+\.\d+\.\d+[\w.\-]*)", re.I
)

_LIBRARY_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)", re.I), "jQuery"),
    (re.compile(r"React\s+v?(\d+\.\d+\.\d+)", re.I), "React"),
    (re.compile(r"Vue\.js\s+v?(\d+\.\d+\.\d+)", re.I), "Vue.js"),
    (re.compile(r"AngularJS\s+v?(\d+\.\d+\.\d+)", re.I), "AngularJS"),
    (re.compile(r"lodash\.js\s+v?(\d+\.\d+\.\d+)", re.I), "Lodash"),
    (re.compile(r"axios\s+v?(\d+\.\d+\.\d+)", re.I), "Axios"),
    (re.compile(r"moment\.js\s+v?(\d+\.\d+\.\d+)", re.I), "Moment.js"),
    (re.compile(r"chart\.js\s+v?(\d+\.\d+\.\d+)", re.I), "Chart.js"),
    (re.compile(r"three\.js\s+r?(\d+)", re.I), "Three.js"),
    (re.compile(r"d3\s+v?(\d+\.\d+\.\d+)", re.I), "D3.js"),
    (re.compile(r"@?stripe/stripe-js@?(\d+\.\d+\.\d+)?", re.I), "Stripe.js"),
)

_INTEGRATION_HINTS: tuple[tuple[str, str, str], ...] = (
    ("stripe.com", "Stripe", "payment_processor"),
    ("checkout.com", "Checkout.com", "payment_processor"),
    ("paypal.com", "PayPal", "payment_processor"),
    ("googleapis.com/maps", "Google Maps", "mapping"),
    ("api.mapbox.com", "Mapbox", "mapping"),
    ("sentry.io", "Sentry", "error_tracking"),
    ("bugsnag.com", "Bugsnag", "error_tracking"),
    ("segment.com", "Segment", "analytics"),
    ("googletagmanager.com", "Google Tag Manager", "analytics"),
    ("google-analytics.com", "Google Analytics", "analytics"),
    ("hotjar.com", "Hotjar", "analytics"),
    ("mixpanel.com", "Mixpanel", "analytics"),
    ("amplitude.com", "Amplitude", "analytics"),
    ("intercom.io", "Intercom", "customer_support"),
    ("zendesk.com", "Zendesk", "customer_support"),
    ("firebaseio.com", "Firebase", "backend_as_a_service"),
    ("firebaseapp.com", "Firebase", "backend_as_a_service"),
    ("supabase.co", "Supabase", "backend_as_a_service"),
    ("auth0.com", "Auth0", "authentication"),
    ("okta.com", "Okta", "authentication"),
    ("clerk.dev", "Clerk", "authentication"),
    ("algolia.net", "Algolia", "search"),
    ("cloudinary.com", "Cloudinary", "media_cdn"),
    ("recaptcha.net", "reCAPTCHA", "bot_protection"),
    ("hcaptcha.com", "hCaptcha", "bot_protection"),
    ("launchdarkly.com", "LaunchDarkly", "feature_flags"),
    ("optimizely.com", "Optimizely", "experimentation"),
)

def _sld_looks_real(hostname: str) -> bool:
    """Reject candidates whose second-level label is a minified identifier.

    A real registrable domain's SLD is a chosen word, almost always 3+
    characters. A single-letter or two-letter label immediately before a
    common-word TLD is overwhelmingly a property-access chain
    (`a.top`, `e.id`) rather than a domain.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    sld = labels[-2]
    return len(sld) >= 3


_PACKAGE_NAME_RE = re.compile(r"""(?:from|require\()\s*["']([a-zA-Z0-9@/_\-.]+)["']""")


class JavaScriptIntelligenceModule(IntelligenceModule):
    id = "javascript_intelligence"
    name = "JavaScript Intelligence"
    description = (
        "Analyses every retrieved JavaScript file for libraries, API "
        "endpoints, referenced domains, source-map exposure and masked "
        "secret-shaped values."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.WEB_SURFACE,)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("web_surface",)
    timeout = 60.0
    order = 73

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        js_bodies = ctx.data_of("web_surface", "js_bodies", {}) or {}
        target_registrable = ctx.target.registrable or ctx.target.value

        total_secrets = 0
        total_endpoints = 0
        source_maps_found = 0

        for url, body in js_bodies.items():
            ctx.check_cancelled()
            record = self._analyse(ctx, output, url, body, target_registrable)
            output.javascript.append(record)
            total_secrets += len(record.secret_indicators)
            total_endpoints += len(record.endpoints)
            if record.has_source_map:
                source_maps_found += 1

            for finding in _findings_for(record, url):
                output.findings.append(finding)

        output.data["summary"] = {
            "files_analysed": len(js_bodies),
            "total_endpoints": total_endpoints,
            "total_secret_indicators": total_secrets,
            "files_with_source_maps": source_maps_found,
            "third_party_files": sum(1 for r in output.javascript if r.is_third_party),
        }
        return output

    def _analyse(
        self,
        ctx: ModuleContext,
        output: ModuleOutput,
        url: str,
        body: str,
        target_registrable: str,
    ) -> JavaScriptRecord:
        content_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        host = urlsplit(url).hostname or ""
        is_third_party = bool(host) and not is_subdomain_of(host, target_registrable)

        endpoints = sorted({m.group(1) for m in _ENDPOINT_RE.finditer(body)})[:150]
        websockets = sorted({m.group(1) for m in _WEBSOCKET_RE.finditer(body)})[:30]

        for match in _ABSOLUTE_URL_RE.finditer(body):
            candidate = match.group(0)
            path = urlsplit(candidate).path
            if any(hint in path.lower() for hint in ("/api/", "/graphql", "/v1/", "/v2/", "/rest/")):
                endpoints.append(candidate)
        endpoints = sorted(set(endpoints))[:200]

        for endpoint in endpoints:
            api_type = ApiType.GRAPHQL if "graphql" in endpoint.lower() else ApiType.REST
            resolved = endpoint if endpoint.startswith("http") else urljoin(url, endpoint)
            parts = urlsplit(resolved)
            if not parts.hostname:
                continue
            output.api_endpoints.append(
                ApiEndpointRecord(
                    url=resolved,
                    normalized_url=resolved.split("?", 1)[0].rstrip("/") or resolved,
                    host=parts.hostname,
                    path=parts.path or "/",
                    api_type=api_type,
                    source_artifact=url,
                    in_scope=is_subdomain_of(parts.hostname, target_registrable),
                    confidence=70,
                    sources=["javascript"],
                    evidence={"discovery": f"referenced in {url}"},
                )
            )

        domain_candidates = {
            normalize_hostname(m.group(0)) or "" for m in _DOMAIN_RE.finditer(body)
        }
        domains = sorted(
            d
            for d in domain_candidates
            if d
            and has_known_tld(d)
            and _sld_looks_real(d)
            and not d.endswith((".js", ".css", ".png", ".svg", ".woff", ".woff2"))
        )[:100]
        for domain in domains:
            if is_subdomain_of(domain, target_registrable):
                output.observations.append(
                    ObservationRecord(
                        source="javascript",
                        asset_type=AssetType.SUBDOMAIN if domain != target_registrable else AssetType.DOMAIN,
                        value=domain,
                        source_type=SourceKind.WEB_SURFACE,
                        confidence=68,
                        status=ObservationStatus.OBSERVED,
                        evidence={"discovery": f"referenced in {url}"},
                    )
                )

        ip_addresses = sorted(set(_IPV4_RE.findall(body)))[:50]
        emails = sorted(
            {e for e in _EMAIL_RE.findall(body) if not e.lower().endswith((".png", ".jpg", ".svg"))}
        )[:50]

        integrations = []
        lowered_body = body[:200000].lower()
        for needle, name, category in _INTEGRATION_HINTS:
            if needle in lowered_body:
                integrations.append({"name": name, "category": category})

        libraries = []
        for pattern, name in _LIBRARY_SIGNATURES:
            match = pattern.search(body[:5000])
            if match:
                libraries.append({"name": name, "version": match.group(1) if match.groups() else None})
        for match in _PACKAGE_COMMENT_RE.finditer(body[:5000]):
            libraries.append({"name": match.group(1), "version": match.group(2)})

        package_names = sorted(set(_PACKAGE_NAME_RE.findall(body)))[:80]

        comments = []
        for match in _COMMENT_RE.finditer(body[:100000]):
            text = (match.group(1) or match.group(2) or "").strip()
            if text and len(text) > 8 and not text.startswith(("!", "eslint", "webpack")):
                comments.append(text[:300])
        comments = comments[:40]

        config_objects = []
        for match in _CONFIG_OBJECT_RE.finditer(body[:200000]):
            config_objects.append({"raw": match.group(1)[:400]})
        config_objects = config_objects[:10]

        environment_hints = sorted(set(_ENV_HINT_RE.findall(body[:200000])))[:40]

        source_map_match = _SOURCEMAP_RE.search(body[-2000:])
        source_map_url = None
        has_source_map = False
        if source_map_match:
            raw_ref = source_map_match.group(1).strip()
            if not raw_ref.startswith("data:"):
                source_map_url = urljoin(url, raw_ref)
                has_source_map = True

        secrets = find_secrets(body, source=url)

        return JavaScriptRecord(
            url=url,
            content_sha256=content_hash,
            size=len(body.encode("utf-8", errors="replace")),
            is_inline=False,
            is_third_party=is_third_party,
            truncated=False,
            libraries=libraries[:30],
            endpoints=endpoints,
            domains=domains,
            ip_addresses=ip_addresses,
            emails=emails,
            cloud_references=[],
            integrations=integrations,
            secret_indicators=secrets,
            comments=comments,
            config_objects=config_objects,
            environment_hints=environment_hints,
            package_names=package_names,
            source_map_url=source_map_url,
            has_source_map=has_source_map,
            source_map_retrieved=False,
            confidence=92,
            sources=["web_surface"],
            evidence={"websockets": websockets},
        )


def _findings_for(record: JavaScriptRecord, url: str) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    for secret in record.secret_indicators:
        findings.append(
            FindingRecord(
                module_id="javascript_intelligence",
                category=FindingCategory.SECRET_INDICATOR,
                severity=Severity.HIGH if secret.get("severity") == "high" else Severity.MEDIUM,
                title=f"Potential {secret.get('type', 'secret')} in JavaScript",
                description=(
                    f"A value matching the shape of a {secret.get('type', 'secret')} "
                    f"was found in {url}. The value is masked; Insyte does not "
                    "validate or use discovered credentials."
                ),
                recommendation=(
                    "Rotate the credential if it is real, and move secrets out "
                    "of client-shipped JavaScript into a server-side "
                    "configuration store."
                ),
                location=url,
                confidence=secret.get("confidence", 60),
                exposure=ExposureLevel.DIRECT,
                sources=["javascript"],
                evidence={"masked_value": secret.get("masked"), "pattern": secret.get("type")},
            )
        )
    if record.has_source_map:
        findings.append(
            FindingRecord(
                module_id="javascript_intelligence",
                category=FindingCategory.SOURCE_MAP_EXPOSURE,
                severity=Severity.LOW,
                title="Source map reference exposed",
                description=(
                    f"{url} references a source map at {record.source_map_url}, "
                    "which - if publicly retrievable - reveals original source "
                    "file paths and structure."
                ),
                recommendation=(
                    "Do not deploy source maps to production, or restrict access "
                    "to them, unless they are intentionally public."
                ),
                location=url,
                confidence=90,
                exposure=ExposureLevel.INDEXED,
                sources=["javascript"],
                evidence={"source_map_url": record.source_map_url},
            )
        )
    return findings
