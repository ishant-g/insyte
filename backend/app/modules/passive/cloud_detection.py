"""Cloud Intelligence.

Detects which cloud providers host or front the target from four
independent passive signals, ordered by evidential strength:

1. **Published IP-range matching** - AWS, GCP and Cloudflare publish
   their IP ranges as public, keyless feeds. A target IP inside one of
   those ranges is direct evidence of tenancy, and it is the strongest
   signal this module has. (Azure publishes its ServiceTags feed under a
   versioned URL with no stable address, so Azure tenancy still relies on
   the weaker ASN-holder heuristic.)
2. A hostname (usually a CNAME target) matching a known cloud provider
   suffix - a CNAME pointed straight at `*.s3.amazonaws.com` is close to
   proof.
3. DNS delegation to a provider's nameservers.
4. The organisation name on the announcing ASN - the weakest signal, kept
   at low confidence because it says who leases the address space, not
   what runs on it.

Detection only. This module never enumerates a bucket, requests a
resource, or otherwise interacts with the cloud provider it names - it
reads DNS, routing metadata and public IP-range feeds.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time

from app.core.contracts import AssetRecord, FindingRecord, ModuleOutput, TechnologyRecord
from app.core.target import TargetType
from app.models.enums import AssetType, ExposureLevel, FindingCategory, ModuleCategory, ScanMode, Severity
from app.modules.base import IntelligenceModule, ModuleContext

#: (substring, provider, resource_type). Substring rather than strict
#: suffix matching because some of these (S3 website hosting) place a
#: variable region segment inside the hostname, e.g.
#: "bucket.s3-website-us-east-1.amazonaws.com".
_CLOUD_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    (".s3.amazonaws.com", "Amazon Web Services", "s3_bucket"),
    (".s3-website", "Amazon Web Services", "s3_static_site"),
    (".cloudfront.net", "Amazon Web Services", "cloudfront_distribution"),
    (".blob.core.windows.net", "Microsoft Azure", "azure_blob_storage"),
    (".azurewebsites.net", "Microsoft Azure", "azure_app_service"),
    (".storage.googleapis.com", "Google Cloud Platform", "gcs_bucket"),
    (".appspot.com", "Google Cloud Platform", "app_engine"),
    (".run.app", "Google Cloud Platform", "cloud_run"),
    (".herokuapp.com", "Heroku", "heroku_app"),
    (".vercel.app", "Vercel", "vercel_deployment"),
    (".netlify.app", "Netlify", "netlify_deployment"),
    (".onrender.com", "Render", "render_service"),
    (".railway.app", "Railway", "railway_service"),
    (".fly.dev", "Fly.io", "fly_app"),
    (".firebaseapp.com", "Google Firebase", "firebase_hosting"),
    (".web.app", "Google Firebase", "firebase_hosting"),
    (".github.io", "GitHub Pages", "github_pages"),
)

_CLOUD_PROVIDER_NAMES: frozenset[str] = frozenset(p for _, p, _ in _CLOUD_SIGNATURES)

#: (substring of the ASN holder name, provider). ASN holder is a
#: self-reported organisation string, so this is the weakest of the three
#: signals - it says who leases the address space, not what runs on it.
_ASN_HOLDER_HINTS: tuple[tuple[str, str], ...] = (
    ("amazon", "Amazon Web Services"),
    ("aws", "Amazon Web Services"),
    ("microsoft", "Microsoft Azure"),
    ("azure", "Microsoft Azure"),
    ("google", "Google Cloud Platform"),
    ("digitalocean", "DigitalOcean"),
    ("digital ocean", "DigitalOcean"),
    ("linode", "Akamai (Linode)"),
    ("ovh", "OVHcloud"),
    ("hetzner", "Hetzner"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly"),
    ("heroku", "Heroku"),
    ("vultr", "Vultr"),
)

#: (header name, provider, resource_type) - the same edge signals
#: `waf_cdn_intelligence` looks for, read here only for corroboration.
_HEADER_SIGNALS: tuple[tuple[str, str, str], ...] = (
    ("x-vercel-id", "Vercel", "vercel_deployment"),
    ("x-amz-cf-id", "Amazon Web Services", "cloudfront_distribution"),
    ("x-nf-request-id", "Netlify", "netlify_deployment"),
    ("fly-request-id", "Fly.io", "fly_app"),
)

#: Public, keyless, stable endpoints publishing cloud IP ranges. AWS and
#: GCP publish JSON; Cloudflare publishes plain-text lists. Azure has no
#: stable URL (its ServiceTags feed is versioned weekly), so it is
#: intentionally absent - Azure tenancy keeps relying on the ASN-holder
#: heuristic rather than a feed that would silently go stale.
_RANGE_SOURCES: tuple[dict[str, str], ...] = (
    {
        "provider": "Amazon Web Services",
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "format": "aws",
    },
    {
        "provider": "Google Cloud Platform",
        "url": "https://www.gstatic.com/ipranges/goog.json",
        "format": "gcp",
    },
    {
        "provider": "Cloudflare",
        "url": "https://www.cloudflare.com/ips-v4",
        "format": "text",
    },
    {
        "provider": "Cloudflare",
        "url": "https://www.cloudflare.com/ips-v6",
        "format": "text",
    },
)

#: Refresh daily - cloud ranges change slowly, and these are multi-hundred-
#: kilobyte downloads we should not repeat on every scan.
_RANGE_CACHE_TTL = 24 * 3600
_RANGE_CACHE: dict = {"fetched_at": 0.0, "networks": []}
_RANGE_CACHE_LOCK = threading.Lock()


def _parse_aws_ranges(payload: dict, provider: str) -> list[tuple]:
    out: list[tuple] = []
    for entry in payload.get("prefixes", []) or []:
        prefix = entry.get("ip_prefix")
        if _add_network(out, prefix, provider, entry.get("service"), entry.get("region")):
            continue
    for entry in payload.get("ipv6_prefixes", []) or []:
        _add_network(out, entry.get("ipv6_prefix"), provider, entry.get("service"), entry.get("region"))
    return out


def _parse_gcp_ranges(payload: dict, provider: str) -> list[tuple]:
    out: list[tuple] = []
    for entry in payload.get("prefixes", []) or []:
        prefix = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        _add_network(out, prefix, provider, entry.get("service"), entry.get("scope"))
    return out


def _parse_text_ranges(text: str, provider: str) -> list[tuple]:
    out: list[tuple] = []
    for line in text.splitlines():
        _add_network(out, line.strip(), provider, None, None)
    return out


def _add_network(
    out: list[tuple], prefix: str | None, provider: str,
    service: str | None, region: str | None,
) -> bool:
    if not prefix:
        return False
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False
    out.append((network, provider, service or "unknown", region or "unknown", prefix))
    return True


def _load_cloud_ranges(http) -> list[tuple]:
    """Fetch and parse published cloud IP ranges, cached for 24h.

    Never raises and never fails the module: on any fetch or parse
    problem the source is skipped and the module falls back to its
    DNS/ASN heuristics.
    """
    with _RANGE_CACHE_LOCK:
        if (
            _RANGE_CACHE["networks"]
            and time.monotonic() - _RANGE_CACHE["fetched_at"] < _RANGE_CACHE_TTL
        ):
            return _RANGE_CACHE["networks"]

    networks: list[tuple] = []
    for source in _RANGE_SOURCES:
        try:
            response = http.try_get(
                source["url"],
                max_bytes=8 * 1024 * 1024,
                accept="application/json, text/plain",
            )
        except Exception:  # noqa: BLE001 - a range feed is a bonus, not a dependency
            continue
        if response is None or not response.ok or response.truncated:
            continue
        try:
            if source["format"] == "text":
                networks.extend(_parse_text_ranges(response.text, source["provider"]))
            else:
                payload = json.loads(response.text)
                if not isinstance(payload, dict):
                    continue
                if source["format"] == "aws":
                    networks.extend(_parse_aws_ranges(payload, source["provider"]))
                else:
                    networks.extend(_parse_gcp_ranges(payload, source["provider"]))
        except (ValueError, TypeError, AttributeError):
            continue

    with _RANGE_CACHE_LOCK:
        _RANGE_CACHE["fetched_at"] = time.monotonic()
        _RANGE_CACHE["networks"] = networks
    return networks


class CloudDetectionModule(IntelligenceModule):
    id = "cloud_detection"
    name = "Cloud Intelligence"
    description = (
        "Detects cloud providers hosting or fronting the target by matching "
        "discovered IPs against providers' published IP ranges, plus DNS "
        "delegation, CNAME targets matching known cloud-provider suffixes, "
        "and the announcing ASN's holder name. Detection only - no bucket "
        "enumeration, no resource access."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("dns_intelligence", "ip_asn_intelligence")
    providers = ("grayhatwarfare",)
    timeout = 15.0
    order = 55

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        detected: dict[tuple[str, str], TechnologyRecord] = {}

        def record(
            provider: str, resource_type: str, host: str | None,
            confidence: int, evidence_text: str, source: str,
        ) -> None:
            key = (provider, resource_type)
            existing = detected.get(key)
            if existing is not None:
                if source not in existing.sources:
                    existing.sources.append(source)
                existing.confidence = min(100, existing.confidence + 5)
                return
            detected[key] = TechnologyRecord(
                name=provider,
                category="cloud_platform",
                confidence=confidence,
                host=host,
                sources=[source],
                evidence={"signal": evidence_text, "resource_type": resource_type},
            )

        cname_target = ctx.data_of("dns_intelligence", "cname_target", None)
        hosts = set(ctx.known_hosts())
        if cname_target:
            hosts.add(cname_target)

        # Strongest keyless signal: match discovered IPs against cloud
        # providers' published ranges. Longest-prefix match wins per IP so
        # nested announcements (e.g. an AWS service prefix inside a region
        # prefix) report the most specific evidence.
        range_networks = _load_cloud_ranges(ctx.http)
        if range_networks:
            for ip_str in ctx.known_ips():
                ctx.check_cancelled()
                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                best: tuple | None = None
                for network, provider, service, region, prefix in range_networks:
                    if ip.version != network.version or ip not in network:
                        continue
                    if best is None or network.prefixlen > best[0].prefixlen:
                        best = (network, provider, service, region, prefix)
                if best is not None:
                    _, provider, service, region, prefix = best
                    record(
                        provider,
                        "cloud_ip_range",
                        ip_str,
                        92,
                        f"IP {ip_str} falls within {provider} published range "
                        f"{prefix} (service: {service}, region/scope: {region})",
                        "cloud_ip_ranges",
                    )

        for host in hosts:
            lowered = host.lower()
            for suffix, provider, resource_type in _CLOUD_SIGNATURES:
                if suffix not in lowered:
                    continue
                is_cname = host == cname_target
                record(
                    provider, resource_type, host,
                    90 if is_cname else 80,
                    f"{'CNAME target' if is_cname else 'hostname'} matches cloud suffix {suffix}",
                    "dns",
                )

        for provider_name in ctx.data_of("dns_intelligence", "nameserver_providers", []) or []:
            record(provider_name, "dns_delegation", None, 85, f"nameservers delegated to {provider_name}", "dns")

        for entry in ctx.data_of("ip_asn_intelligence", "asn_summary", []) or []:
            holder = str(entry.get("holder") or "").lower()
            if not holder:
                continue
            for needle, provider in _ASN_HOLDER_HINTS:
                if needle in holder:
                    record(
                        provider, "asn_holder", None, 65,
                        f"ASN holder contains '{needle}': {entry.get('holder')}", "asn",
                    )

        waf_cdn_output = ctx.output_of("waf_cdn_intelligence")
        if waf_cdn_output is not None:
            for tech in waf_cdn_output.technologies:
                if tech.name in _CLOUD_PROVIDER_NAMES:
                    record(
                        tech.name, "edge_cdn", tech.host, min(95, tech.confidence + 5),
                        "corroborated by WAF/CDN fingerprinting", "waf_cdn_intelligence",
                    )

        headers_by_url = ctx.response_headers()
        if headers_by_url:
            primary = {k.lower(): v for k, v in next(iter(headers_by_url.values())).items()}
            for header_name, provider, resource_type in _HEADER_SIGNALS:
                if header_name in primary:
                    record(provider, resource_type, None, 85, f"response header {header_name} present", "headers")

        bucket_observations, bucket_statuses = self.gather(ctx, "cloud_buckets")
        output.providers.extend(bucket_statuses)
        open_buckets = []
        for observation in bucket_observations:
            output.assets.append(
                AssetRecord(
                    asset_type=AssetType.CLOUD_RESOURCE,
                    value=observation.value,
                    confidence=observation.confidence,
                    sources=[observation.source],
                    evidence=observation.evidence,
                    attributes=observation.attributes,
                )
            )
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.CLOUD_EXPOSURE,
                    severity=Severity.HIGH,
                    title=f"Open cloud storage bucket referencing the target: {observation.value}",
                    description=(
                        "A publicly indexed cloud storage bucket referencing the target "
                        "was found via GrayhatWarfare's open-bucket search."
                    ),
                    recommendation=(
                        "Confirm bucket ownership and, if it belongs to the target, "
                        "review its access policy - public listing/read access on a "
                        "bucket is rarely intentional."
                    ),
                    confidence=observation.confidence,
                    exposure=ExposureLevel.INDEXED,
                    sources=[observation.source],
                    evidence=observation.evidence,
                    asset_type=AssetType.CLOUD_RESOURCE,
                    asset_value=observation.value,
                )
            )
            open_buckets.append(observation.value)

        output.technologies = list(detected.values())
        output.data["summary"] = {
            "providers_detected": sorted({t.name for t in detected.values()}),
            "resource_types": sorted(
                {t.evidence.get("resource_type") for t in detected.values() if t.evidence.get("resource_type")}
            ),
            "open_buckets": sorted(open_buckets),
        }
        return output
