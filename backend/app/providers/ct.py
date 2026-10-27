"""Certificate Transparency providers.

CT logs are the single most productive passive source for subdomains,
because every publicly-trusted certificate issued for a name is logged and
the logs are queryable. Two adapters are shipped rather than one: crt.sh is
the best-known but is frequently overloaded (502s and read timeouts are
routine), and a scan that loses all CT coverage when one service is having
a bad day is a scan with a hole in it. Cert Spotter is queried as well, and
either one alone still produces useful results.
"""

from __future__ import annotations

from typing import Any

from app.core.contracts import ObservationRecord
from app.core.ratelimit import RateLimit
from app.core.target import is_subdomain_of, normalize_hostname
from app.models.enums import AssetType, ObservationStatus, SourceKind
from app.providers.base import Provider, ProviderQuery, parse_timestamp


class CrtShProvider(Provider):
    id = "crtsh"
    name = "crt.sh Certificate Transparency"
    kind = SourceKind.PASSIVE
    homepage = "https://crt.sh"
    description = (
        "Comprehensive Certificate Transparency log search operated by Sectigo. "
        "Yields subject alternative names for every publicly-trusted certificate "
        "issued for the target."
    )
    reliability = 95
    requires_api_key = False
    intents = ("subdomains", "certificates")
    # crt.sh is a free service running expensive Postgres queries. One
    # request per query with a generous timeout is the polite shape.
    rate_limit = RateLimit(requests=6, window=60.0, min_interval=2.0, concurrency=1)
    cache_ttl = 21600
    timeout = 60.0
    max_response_bytes = 12 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        url = f"https://crt.sh/?q=%25.{domain}&output=json&exclude=expired"
        payload = self._http_json(url)
        if not isinstance(payload, list):
            return []

        seen: set[str] = set()
        out: list[ObservationRecord] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            not_before = parse_timestamp(entry.get("not_before"))
            not_after = parse_timestamp(entry.get("not_after"))
            issuer = str(entry.get("issuer_name") or "")[:255]
            # name_value is newline separated and contains the CN plus SANs.
            names = str(entry.get("name_value") or "").split("\n")
            names.append(str(entry.get("common_name") or ""))
            for raw_name in names:
                host = normalize_hostname(raw_name)
                if not host:
                    continue
                bare = host.removeprefix("*.")
                if not is_subdomain_of(bare, domain):
                    continue
                if bare in seen:
                    continue
                seen.add(bare)
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=(
                            AssetType.DOMAIN
                            if bare == query.target.value
                            else AssetType.SUBDOMAIN
                        ),
                        value=bare,
                        source_type=SourceKind.PASSIVE,
                        confidence=92,
                        status=ObservationStatus.OBSERVED,
                        observed_at=not_before,
                        first_seen=not_before,
                        last_seen=not_after,
                        evidence={
                            "discovery": "certificate transparency log entry",
                            "issuer": issuer,
                            "wildcard": host.startswith("*."),
                            "certificate_id": entry.get("id"),
                        },
                        attributes={
                            "certificate_serial": str(entry.get("serial_number") or "")[:64],
                        },
                    )
                )
        return out


class CertSpotterProvider(Provider):
    id = "certspotter"
    name = "Cert Spotter Certificate Transparency"
    kind = SourceKind.PASSIVE
    homepage = "https://sslmate.com/certspotter/"
    description = (
        "Certificate Transparency issuance search operated by SSLMate. Queried "
        "alongside crt.sh so Certificate Transparency coverage survives one "
        "service being unavailable."
    )
    reliability = 93
    requires_api_key = False
    intents = ("subdomains", "certificates")
    # The unauthenticated endpoint permits a modest number of queries per hour.
    rate_limit = RateLimit(requests=8, window=3600.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0
    max_response_bytes = 8 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true"
            "&expand=dns_names&expand=issuer&expand=not_before&expand=not_after"
        )
        payload = self._http_json(url)
        if not isinstance(payload, list):
            return []

        seen: set[str] = set()
        out: list[ObservationRecord] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            not_before = parse_timestamp(entry.get("not_before"))
            not_after = parse_timestamp(entry.get("not_after"))
            issuer_obj = entry.get("issuer")
            issuer = ""
            if isinstance(issuer_obj, dict):
                issuer = str(issuer_obj.get("name") or "")[:255]
            for raw_name in entry.get("dns_names") or []:
                host = normalize_hostname(str(raw_name))
                if not host:
                    continue
                bare = host.removeprefix("*.")
                if not is_subdomain_of(bare, domain) or bare in seen:
                    continue
                seen.add(bare)
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=(
                            AssetType.DOMAIN
                            if bare == query.target.value
                            else AssetType.SUBDOMAIN
                        ),
                        value=bare,
                        source_type=SourceKind.PASSIVE,
                        confidence=92,
                        status=ObservationStatus.OBSERVED,
                        observed_at=not_before,
                        first_seen=not_before,
                        last_seen=not_after,
                        evidence={
                            "discovery": "certificate transparency issuance",
                            "issuer": issuer,
                            "wildcard": host.startswith("*."),
                        },
                        attributes={"certspotter_id": entry.get("id")},
                    )
                )
        return out


def certificate_payloads(entries: list[Any]) -> list[dict[str, Any]]:
    """Reduce CT entries to certificate-shaped dicts.

    Kept separate from the observation flow because the certificate module
    wants the certificate as an object (issuer, validity, SAN set) while
    subdomain enumeration only wants the names.
    """
    out: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = [
            normalize_hostname(str(n))
            for n in (
                entry.get("dns_names")
                or str(entry.get("name_value") or "").split("\n")
            )
        ]
        out.append(
            {
                "sans": sorted({n for n in names if n}),
                "issuer": entry.get("issuer") or entry.get("issuer_name"),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "serial": entry.get("serial_number"),
            }
        )
    return out
