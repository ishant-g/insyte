"""Passive DNS and public-dataset providers that need no credential.

These are the sources that keep Insyte useful with an empty `.env`. None of
them touches the target: every one is a third party reporting what it
already observed.
"""

from __future__ import annotations

import ipaddress

from app.core.contracts import ObservationRecord
from app.core.ratelimit import RateLimit
from app.core.target import is_subdomain_of, normalize_hostname
from app.models.enums import AssetType, ObservationStatus, SourceKind
from app.providers.base import Provider, ProviderQuery, parse_timestamp


class HackerTargetProvider(Provider):
    id = "hackertarget"
    name = "HackerTarget Host Search"
    kind = SourceKind.PASSIVE
    homepage = "https://hackertarget.com"
    description = (
        "Public host-search dataset returning hostname/address pairs previously "
        "observed for a domain."
    )
    reliability = 72
    requires_api_key = False
    intents = ("subdomains",)
    # Free tier is a small daily allowance; be conservative.
    rate_limit = RateLimit(requests=4, window=60.0, min_interval=1.5, concurrency=1)
    cache_ttl = 21600
    timeout = 25.0
    max_response_bytes = 4 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        text = self._http_text(
            f"https://api.hackertarget.com/hostsearch/?q={domain}"
        )
        if not text:
            return []
        # The free endpoint signals its limits in prose, not a status code.
        lowered = text.lower()
        if "api count exceeded" in lowered or "error" in lowered[:40]:
            self.errors.append("daily free-tier quota exceeded")
            return []

        out: list[ObservationRecord] = []
        seen: set[str] = set()
        for line in text.splitlines():
            if "," not in line:
                continue
            raw_host, _, raw_ip = line.partition(",")
            host = normalize_hostname(raw_host)
            if not host or not is_subdomain_of(host, domain) or host in seen:
                continue
            seen.add(host)
            attributes: dict[str, object] = {}
            try:
                attributes["resolved_ip"] = str(ipaddress.ip_address(raw_ip.strip()))
            except ValueError:
                pass
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=(
                        AssetType.DOMAIN
                        if host == query.target.value
                        else AssetType.SUBDOMAIN
                    ),
                    value=host,
                    source_type=SourceKind.PASSIVE,
                    confidence=70,
                    status=ObservationStatus.OBSERVED,
                    evidence={"discovery": "public host-search dataset"},
                    attributes=attributes,
                )
            )
        return out

    def reverse_ip(self, ip: str) -> list[str]:
        """Other hostnames HackerTarget has observed on `ip`.

        Shares this provider's own rate-limit budget rather than declaring
        a second one, since it is the same free service.
        """
        text = self._http_text(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if not text:
            return []
        lowered = text.lower()
        if "api count exceeded" in lowered or "error" in lowered[:40]:
            return []
        hosts: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            host = normalize_hostname(line.strip())
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts


class RapidDnsProvider(Provider):
    id = "rapiddns"
    name = "RapidDNS Subdomain Dataset"
    kind = SourceKind.PASSIVE
    homepage = "https://rapiddns.io"
    description = "Public passive-DNS subdomain dataset."
    reliability = 65
    requires_api_key = False
    intents = ("subdomains",)
    rate_limit = RateLimit(requests=4, window=60.0, min_interval=2.0, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0
    max_response_bytes = 6 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        html = self._http_text(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            accept="text/html",
        )
        if not html:
            return []

        # RapidDNS returns an HTML table. Rather than parse the markup
        # (which changes), extract every hostname-shaped token and filter
        # by scope - the same result, and immune to layout churn.
        import re

        candidates = set(
            re.findall(
                r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                + re.escape(domain)
                + r")\b",
                html.lower(),
            )
        )
        candidates.add(domain)

        out: list[ObservationRecord] = []
        for raw in sorted(candidates):
            host = normalize_hostname(raw)
            if not host or not is_subdomain_of(host, domain):
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=(
                        AssetType.DOMAIN
                        if host == query.target.value
                        else AssetType.SUBDOMAIN
                    ),
                    value=host,
                    source_type=SourceKind.PASSIVE,
                    confidence=62,
                    status=ObservationStatus.OBSERVED,
                    evidence={"discovery": "public subdomain dataset"},
                )
            )
        return out


class OtxProvider(Provider):
    id = "otx"
    name = "AlienVault OTX"
    kind = SourceKind.EXTERNAL
    homepage = "https://otx.alienvault.com"
    description = (
        "Open Threat Exchange passive DNS and URL history. Works without a "
        "credential but is aggressively rate limited when anonymous, so an "
        "OTX_API_KEY materially improves coverage."
    )
    reliability = 78
    #: Usable anonymously, so not marked as key-required - but the adapter
    #: reports the 429 honestly rather than pretending it found nothing.
    requires_api_key = False
    intents = ("subdomains", "urls", "ips")
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=2)
    cache_ttl = 10800
    timeout = 30.0
    max_response_bytes = 8 * 1024 * 1024

    def auth_headers(self) -> dict[str, str]:
        key = self.credential()
        return {"X-OTX-API-KEY": key} if key else {}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if query.intent == "urls":
            return self._fetch_urls(query)
        if query.intent == "ips" and query.target.is_ip:
            return self._fetch_ip(query)
        return self._fetch_passive_dns(query)

    def _base(self, query: ProviderQuery) -> str:
        if query.target.is_ip:
            section = "IPv6" if query.target.target_type.value == "ipv6" else "IPv4"
            return f"https://otx.alienvault.com/api/v1/indicators/{section}/{query.target.value}"
        return (
            "https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{query.target.registrable or query.target.value}"
        )

    def _fetch_passive_dns(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        payload = self._http_json(f"{self._base(query)}/passive_dns")
        if not isinstance(payload, dict):
            return []
        domain = query.target.registrable or query.target.value
        out: list[ObservationRecord] = []
        seen: set[str] = set()
        for row in payload.get("passive_dns") or []:
            if not isinstance(row, dict):
                continue
            host = normalize_hostname(str(row.get("hostname") or ""))
            if not host or not is_subdomain_of(host, domain) or host in seen:
                continue
            seen.add(host)
            first = parse_timestamp(row.get("first"))
            last = parse_timestamp(row.get("last"))
            attributes: dict[str, object] = {}
            address = str(row.get("address") or "").strip()
            if address:
                try:
                    attributes["resolved_ip"] = str(ipaddress.ip_address(address))
                except ValueError:
                    pass
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=(
                        AssetType.DOMAIN if host == query.target.value else AssetType.SUBDOMAIN
                    ),
                    value=host,
                    source_type=SourceKind.EXTERNAL,
                    confidence=76,
                    status=ObservationStatus.OBSERVED,
                    observed_at=last or first,
                    first_seen=first,
                    last_seen=last,
                    evidence={"discovery": "OTX passive DNS record"},
                    attributes=attributes,
                )
            )
        return out

    def _fetch_urls(self, query: ProviderQuery) -> list[ObservationRecord]:
        payload = self._http_json(f"{self._base(query)}/url_list?limit=500")
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        for row in payload.get("url_list") or []:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            observed = parse_timestamp(row.get("date"))
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.URL,
                    value=url,
                    source_type=SourceKind.HISTORICAL,
                    confidence=70,
                    status=ObservationStatus.HISTORICAL,
                    observed_at=observed,
                    first_seen=observed,
                    last_seen=observed,
                    evidence={
                        "discovery": "OTX observed URL",
                        "http_code": row.get("httpcode"),
                    },
                )
            )
        return out

    def _fetch_ip(self, query: ProviderQuery) -> list[ObservationRecord]:
        payload = self._http_json(f"{self._base(query)}/general")
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        asn = str(payload.get("asn") or "").strip()
        if asn:
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.ASN,
                    value=asn,
                    source_type=SourceKind.EXTERNAL,
                    confidence=80,
                    evidence={"discovery": "OTX IP metadata"},
                    attributes={
                        "country": payload.get("country_name"),
                        "city": payload.get("city"),
                    },
                )
            )
        return out
