"""abuse.ch threat intelligence via keyless bulk exports.

Why exports instead of the documented per-target APIs: ThreatFox and
URLhaus both moved their direct lookups behind an Auth-Key, and both APIs
are POST-only while the shared HTTP client is deliberately GET-only. What
stays keyless and GET-friendly are the recent-IOC bulk exports, so these
providers download the export and match the target locally. Export formats
and keyless availability verified 2026-09-27.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from app.core.target import TargetType
from app.models.enums import AssetType, SourceKind
from app.providers.base import ObservationRecord, Provider, ProviderQuery, RateLimit


def _target_host(query: ProviderQuery) -> tuple[str, bool]:
    """Return (normalized target, is_ip) for the current query."""
    value = (query.value or query.target.value or "").strip().lower()
    try:
        ipaddress.ip_address(value)
        return value, True
    except ValueError:
        return value, False


class ThreatFoxProvider(Provider):
    id = "threatfox"
    name = "ThreatFox"
    kind = SourceKind.PASSIVE
    homepage = "https://threatfox.abuse.ch"
    description = (
        "abuse.ch ThreatFox recent-IOC export matched against the target "
        "locally. Keyless: the export is public, the per-target API is not, "
        "so this provider checks whether the target appears in currently "
        "circulating threat indicators rather than querying per target."
    )
    reliability = 88
    requires_api_key = False
    intents = ("threat_intel",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0
    max_response_bytes = 8 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if query.target.target_type not in (
            TargetType.DOMAIN,
            TargetType.IPV4,
            TargetType.IPV6,
        ):
            return []
        target, is_ip = _target_host(query)
        if not target:
            return []

        payload = self._http_json("https://threatfox.abuse.ch/export/json/recent/")
        if not isinstance(payload, dict):
            return []
        entries = payload.get("data")
        if not isinstance(entries, dict):
            return []

        out: list[ObservationRecord] = []
        for entry in entries.values():
            if not isinstance(entry, dict):
                continue
            ioc = str(entry.get("ioc") or "").strip().lower()
            ioc_type = str(entry.get("ioc_type") or "").strip().lower()
            if not ioc or not self._matches(ioc, ioc_type, target, is_ip):
                continue
            malware = str(entry.get("malware") or "").strip()
            threat_type = str(entry.get("threat_type") or "").strip()
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.EXPOSURE,
                    value=ioc,
                    source_type=SourceKind.PASSIVE,
                    confidence=88,
                    evidence={
                        "discovery": "target appears in the ThreatFox recent-IOC export",
                        "ioc_type": ioc_type,
                        "threat_type": threat_type or None,
                        "malware": malware or None,
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "reporter": entry.get("reporter"),
                        "reference": entry.get("reference"),
                    },
                )
            )
            if len(out) >= (query.limit or 25):
                break
        return out

    @staticmethod
    def _matches(ioc: str, ioc_type: str, target: str, is_ip: bool) -> bool:
        if is_ip:
            if ioc_type.startswith("ip"):
                return ioc.split(":")[0] == target
            return False
        if ioc_type == "domain":
            return ioc == target
        if ioc_type == "url":
            try:
                return (urlsplit(ioc).hostname or "").lower() == target
            except ValueError:
                return False
        return False


class UrlhausProvider(Provider):
    id = "urlhaus"
    name = "URLhaus"
    kind = SourceKind.PASSIVE
    homepage = "https://urlhaus.abuse.ch"
    description = (
        "abuse.ch URLhaus recent-URL export matched against the target "
        "locally. Keyless: the export is public, the per-target API is not, "
        "so this provider checks whether the target hosts malware URLs seen "
        "recently rather than querying per host."
    )
    reliability = 88
    requires_api_key = False
    intents = ("threat_intel",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 45.0
    max_response_bytes = 16 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if query.target.target_type not in (
            TargetType.DOMAIN,
            TargetType.IPV4,
            TargetType.IPV6,
        ):
            return []
        target, _is_ip = _target_host(query)
        if not target:
            return []

        payload = self._http_json("https://urlhaus.abuse.ch/downloads/json_recent/")
        if not isinstance(payload, list):
            return []

        out: list[ObservationRecord] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            host = str(entry.get("host") or "").strip().lower()
            url = str(entry.get("url") or "").strip()
            if not host or not url or host != target:
                continue
            tags = entry.get("tags")
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.URL,
                    value=url,
                    source_type=SourceKind.PASSIVE,
                    confidence=85,
                    evidence={
                        "discovery": "target hosts a URL in the URLhaus recent feed",
                        "host": host,
                        "threat": entry.get("threat"),
                        "url_status": entry.get("url_status"),
                        "date_added": entry.get("dateadded"),
                        "tags": tags if isinstance(tags, list) else [],
                        "urlhaus_id": entry.get("id"),
                    },
                )
            )
            if len(out) >= (query.limit or 25):
                break
        return out
