"""IP reputation and network-adjacent providers.

Reputation providers are a different shape than the rest of the provider
framework: the IP asset itself was already discovered by DNS resolution or
RDAP, so there is nothing new to assert as an `ObservationRecord`. Instead
each one exposes a companion lookup method - the same pattern
`RipeStatProvider.reverse_dns` already uses - that `ip_asn_intelligence`
calls directly to enrich an existing IP asset's `attributes` and, where the
signal is strong enough, raise a `FindingRecord`. `fetch()` still exists (it
is the abstract contract, and it is what `collect()` caches and rate-limits
through), but for these two it always returns an empty list.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from app.core.contracts import ObservationRecord
from app.core.net import HttpError
from app.core.ratelimit import RateLimit
from app.core.target import normalize_hostname
from app.models.enums import AssetType, SourceKind
from app.providers.base import Provider, ProviderQuery


class AbuseIpDbProvider(Provider):
    id = "abuseipdb"
    name = "AbuseIPDB"
    kind = SourceKind.EXTERNAL
    homepage = "https://www.abuseipdb.com"
    description = (
        "Crowdsourced IP abuse reports. Used to attach an abuse-confidence "
        "score and recent report count to discovered IP addresses, not to "
        "discover new assets."
    )
    reliability = 75
    requires_api_key = True
    #: Not consulted by `gather()` for a graph asset - `ip_asn_intelligence`
    #: calls `abuse_lookup()` directly. Declared anyway so the provider
    #: catalogue and `describe()` are accurate.
    intents = ("reputation",)
    rate_limit = RateLimit(requests=15, window=60.0, min_interval=2.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def auth_headers(self) -> dict[str, str]:
        return {"Key": self.credential()}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        return []

    def abuse_lookup(self, ip: str) -> dict[str, Any] | None:
        """Abuse-confidence score and report metadata for `ip`, or None."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if self.unavailable_reason() is not None:
            return None
        try:
            payload = self._http_json(
                "https://api.abuseipdb.com/api/v2/check"
                f"?ipAddress={ip}&maxAgeInDays=90"
            )
        except HttpError:
            return None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return None
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_tor": data.get("isTor"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "country_code": data.get("countryCode"),
        }


class GreyNoiseProvider(Provider):
    id = "greynoise"
    name = "GreyNoise Community"
    kind = SourceKind.EXTERNAL
    homepage = "https://greynoise.io"
    description = (
        "Classifies whether an address is a known internet-wide scanner "
        "(mass-scan noise) versus a device with no such history. Context, "
        "not a vulnerability - a 'noisy' classification does not by itself "
        "raise a finding."
    )
    reliability = 78
    #: The Community endpoint answers unauthenticated requests at a lower
    #: rate limit (confirmed live: 25 req/day observed with no key at all).
    #: A key is only ever a rate-limit upgrade, so this is not key-gated.
    requires_api_key = False
    intents = ("reputation",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def auth_headers(self) -> dict[str, str]:
        key = self.credential()
        return {"key": key} if key else {}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        return []

    def classify(self, ip: str) -> dict[str, Any] | None:
        """GreyNoise's classification of `ip`, or None on a lookup failure.

        Confirmed live: an address GreyNoise has never seen scanning
        returns HTTP 404 with a genuine JSON body (`{"noise": false, ...}`),
        not an empty "not found". `_http_json`'s shared 404-means-null
        convention would silently discard that body, so this call bypasses
        it and parses the response directly - the 404 here is data, not an
        absence of data.
        """
        import json

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        try:
            response = self._client.provider_get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"Accept": "application/json", **self.auth_headers()},
            )
        except HttpError:
            return None
        self.calls += 1
        if response.status_code not in (200, 404):
            return None
        try:
            payload = json.loads(response.text)
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        return {
            "classification": payload.get("classification"),
            "noise": bool(payload.get("noise")),
            "riot": bool(payload.get("riot")),
            "name": payload.get("name"),
            "last_seen": payload.get("last_seen"),
        }


class ChaosProvider(Provider):
    id = "chaos"
    name = "Chaos (ProjectDiscovery)"
    kind = SourceKind.EXTERNAL
    homepage = "https://chaos.projectdiscovery.io"
    description = (
        "ProjectDiscovery's Chaos subdomain dataset, built from their own "
        "internet-wide scanning. Requires a free account at "
        "cloud.projectdiscovery.io."
    )
    reliability = 82
    requires_api_key = True
    intents = ("subdomains",)
    rate_limit = RateLimit(requests=20, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 25.0

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": self.credential()}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        payload = self._http_json(
            f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        )
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        for name in payload.get("subdomains") or []:
            host = normalize_hostname(f"{name}.{domain}")
            if not host:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=(
                        AssetType.DOMAIN if host == query.target.value else AssetType.SUBDOMAIN
                    ),
                    value=host,
                    source_type=SourceKind.EXTERNAL,
                    confidence=80,
                    evidence={"discovery": "Chaos subdomain dataset"},
                )
            )
        return out
