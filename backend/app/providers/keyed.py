"""Credential-dependent external intelligence providers.

Every provider here is optional. With no credentials configured, each one
reports `available=False, reason="API key not configured"`, contributes
nothing, and the scan proceeds - which is the difference between "optional
integration" and "the demo only works if you pay for five APIs".
"""

from __future__ import annotations

import base64

from app.core.config import settings
from app.core.contracts import ObservationRecord
from app.core.ratelimit import RateLimit
from app.core.target import is_subdomain_of, normalize_hostname
from app.models.enums import AssetType, ObservationStatus, SourceKind
from app.providers.base import Provider, ProviderQuery, parse_timestamp


class VirusTotalProvider(Provider):
    id = "virustotal"
    name = "VirusTotal"
    kind = SourceKind.EXTERNAL
    homepage = "https://virustotal.com"
    description = (
        "Domain relationship data: observed subdomains, resolutions and "
        "historical certificates."
    )
    reliability = 88
    requires_api_key = True
    intents = ("subdomains", "urls", "ips")
    # The free public API tier is 4 requests/minute. Exceeding it is the
    # fastest way to have a key suspended.
    rate_limit = RateLimit(requests=4, window=60.0, min_interval=15.0, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0

    def auth_headers(self) -> dict[str, str]:
        return {"x-apikey": self.credential()}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return self._fetch_ip(query)
        domain = query.target.registrable or query.target.value
        url = (
            f"https://www.virustotal.com/api/v3/domains/{domain}"
            f"/subdomains?limit={min(query.limit, 1000)}"
        )
        payload = self._http_json(url)
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        for row in payload.get("data") or []:
            if not isinstance(row, dict):
                continue
            host = normalize_hostname(str(row.get("id") or ""))
            if not host or not is_subdomain_of(host, domain):
                continue
            attributes = row.get("attributes") if isinstance(row.get("attributes"), dict) else {}
            first = parse_timestamp(attributes.get("creation_date"))
            last = parse_timestamp(attributes.get("last_modification_date"))
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.SUBDOMAIN,
                    value=host,
                    source_type=SourceKind.EXTERNAL,
                    confidence=86,
                    status=ObservationStatus.OBSERVED,
                    observed_at=last or first,
                    first_seen=first,
                    last_seen=last,
                    evidence={"discovery": "VirusTotal domain relationship"},
                    attributes={
                        "reputation": attributes.get("reputation"),
                        "registrar": attributes.get("registrar"),
                    },
                )
            )
        return out

    def _fetch_ip(self, query: ProviderQuery) -> list[ObservationRecord]:
        payload = self._http_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{query.target.value}"
        )
        if not isinstance(payload, dict):
            return []
        attributes = payload.get("data", {}).get("attributes", {})
        if not isinstance(attributes, dict):
            return []
        out: list[ObservationRecord] = []
        asn = attributes.get("asn")
        if asn:
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.ASN,
                    value=f"AS{asn}",
                    source_type=SourceKind.EXTERNAL,
                    confidence=85,
                    evidence={"discovery": "VirusTotal address metadata"},
                    attributes={
                        "as_owner": attributes.get("as_owner"),
                        "country": attributes.get("country"),
                        "network": attributes.get("network"),
                    },
                )
            )
        return out


class ShodanProvider(Provider):
    id = "shodan"
    name = "Shodan"
    kind = SourceKind.EXTERNAL
    homepage = "https://shodan.io"
    description = (
        "Shodan's existing host database. Insyte queries stored results only "
        "and never requests an on-demand scan."
    )
    reliability = 90
    requires_api_key = True
    intents = ("subdomains", "ips", "technologies")
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.2, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        key = self.credential()
        if query.target.is_ip:
            return self._fetch_host(query, key)
        domain = query.target.registrable or query.target.value
        payload = self._http_json(
            f"https://api.shodan.io/dns/domain/{domain}?key={key}"
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
                    asset_type=AssetType.SUBDOMAIN,
                    value=host,
                    source_type=SourceKind.EXTERNAL,
                    confidence=86,
                    evidence={"discovery": "Shodan DNS database"},
                )
            )
        for record in payload.get("data") or []:
            if not isinstance(record, dict):
                continue
            if record.get("type") in ("A", "AAAA") and record.get("value"):
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.IP,
                        value=str(record["value"]),
                        source_type=SourceKind.EXTERNAL,
                        confidence=84,
                        observed_at=parse_timestamp(record.get("last_seen")),
                        last_seen=parse_timestamp(record.get("last_seen")),
                        evidence={
                            "discovery": "Shodan DNS record",
                            "record": record.get("subdomain") or domain,
                        },
                    )
                )
        return out

    def _fetch_host(self, query: ProviderQuery, key: str) -> list[ObservationRecord]:
        payload = self._http_json(
            f"https://api.shodan.io/shodan/host/{query.target.value}?key={key}"
        )
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
                    confidence=88,
                    evidence={"discovery": "Shodan host record"},
                    attributes={
                        "organization": payload.get("org"),
                        "isp": payload.get("isp"),
                        "country": payload.get("country_name"),
                    },
                )
            )
        for hostname in payload.get("hostnames") or []:
            host = normalize_hostname(str(hostname))
            if host:
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.DOMAIN,
                        value=host,
                        source_type=SourceKind.EXTERNAL,
                        confidence=82,
                        evidence={
                            "discovery": "hostname associated with this address",
                            "address": query.target.value,
                        },
                    )
                )
        # Shodan reports banner-derived product names. These are recorded as
        # technology observations but with modest confidence: a banner is a
        # claim by the server, not a verified fact.
        for service in payload.get("data") or []:
            if not isinstance(service, dict):
                continue
            product = str(service.get("product") or "").strip()
            if not product:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.TECHNOLOGY,
                    value=product,
                    source_type=SourceKind.EXTERNAL,
                    confidence=72,
                    evidence={
                        "discovery": "Shodan service banner",
                        "port": service.get("port"),
                    },
                    attributes={"version": service.get("version")},
                )
            )
        return out


class CensysProvider(Provider):
    id = "censys"
    name = "Censys"
    kind = SourceKind.EXTERNAL
    homepage = "https://censys.io"
    description = "Censys certificate and host search."
    reliability = 90
    requires_api_key = True
    intents = ("subdomains", "certificates")
    rate_limit = RateLimit(requests=8, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0

    def _creds(self) -> tuple[str, str]:
        from app.core.credentials import override_value

        api_id = override_value("censys", "api_id") or settings.CENSYS_API_ID
        api_secret = override_value("censys", "api_secret") or settings.CENSYS_API_SECRET
        return api_id, api_secret

    def configured(self) -> bool:
        api_id, api_secret = self._creds()
        return bool(api_id and api_secret)

    def unavailable_reason(self) -> str | None:
        api_id, api_secret = self._creds()
        if not api_id or not api_secret:
            return "API credentials not configured (CENSYS_API_ID / CENSYS_API_SECRET)"
        return None

    def auth_headers(self) -> dict[str, str]:
        api_id, api_secret = self._creds()
        token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        url = (
            "https://search.censys.io/api/v2/certificates/search"
            f"?q=names%3A{domain}&per_page=100"
        )
        payload = self._http_json(url)
        if not isinstance(payload, dict):
            return []
        hits = payload.get("result", {}).get("hits", [])
        out: list[ObservationRecord] = []
        seen: set[str] = set()
        for hit in hits if isinstance(hits, list) else []:
            if not isinstance(hit, dict):
                continue
            for raw in hit.get("names") or []:
                host = normalize_hostname(str(raw))
                if not host:
                    continue
                bare = host.removeprefix("*.")
                if bare in seen or not is_subdomain_of(bare, domain):
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
                        source_type=SourceKind.EXTERNAL,
                        confidence=88,
                        evidence={"discovery": "Censys certificate name"},
                    )
                )
        return out


class SecurityTrailsProvider(Provider):
    id = "securitytrails"
    name = "SecurityTrails"
    kind = SourceKind.EXTERNAL
    homepage = "https://securitytrails.com"
    description = "Historical DNS and subdomain inventory."
    reliability = 90
    requires_api_key = True
    intents = ("subdomains", "ips")
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 30.0

    def auth_headers(self) -> dict[str, str]:
        return {"APIKEY": self.credential()}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        payload = self._http_json(
            f"https://api.securitytrails.com/v1/domain/{domain}"
            "/subdomains?children_only=false&include_inactive=true"
        )
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        for prefix in payload.get("subdomains") or []:
            host = normalize_hostname(f"{prefix}.{domain}")
            if not host:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.SUBDOMAIN,
                    value=host,
                    source_type=SourceKind.EXTERNAL,
                    confidence=88,
                    evidence={"discovery": "SecurityTrails subdomain inventory"},
                )
            )
        return out


class GitHubProvider(Provider):
    id = "github"
    name = "GitHub"
    kind = SourceKind.EXTERNAL
    homepage = "https://github.com"
    description = (
        "Searches public GitHub code and repositories for references to the "
        "target: hostnames, API endpoints, cloud resources and configuration. "
        "Read-only - Insyte never authenticates with, uses, or acts on anything "
        "it discovers."
    )
    reliability = 80
    #: The code-search endpoint requires authentication; without a token the
    #: provider reports itself unavailable rather than silently degrading.
    requires_api_key = True
    intents = ("subdomains", "urls", "repositories")
    # GitHub's search API allows 30 requests/minute authenticated.
    rate_limit = RateLimit(requests=20, window=60.0, min_interval=2.0, concurrency=1)
    cache_ttl = 10800
    timeout = 30.0

    def unavailable_reason(self) -> str | None:
        # `credential()` checks the scan owner's stored key first, then the
        # deployment default. Reading `settings.GITHUB_TOKEN` directly here
        # used to ignore keys users saved in Settings entirely.
        if not self.credential():
            return "GitHub token not configured"
        return None

    def auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.credential()}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept": "application/vnd.github+json",
        }

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if query.intent == "repositories":
            return self._search_repositories(query)
        return self._search_code(query)

    def _search_repositories(self, query: ProviderQuery) -> list[ObservationRecord]:
        domain = query.target.registrable or query.target.value
        payload = self._http_json(
            "https://api.github.com/search/repositories"
            f"?q={domain}+in:name,description,readme&per_page=30"
        )
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("full_name") or "")
            if not full_name:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.REPOSITORY,
                    value=f"github.com/{full_name}",
                    source_type=SourceKind.EXTERNAL,
                    confidence=64,
                    observed_at=parse_timestamp(item.get("pushed_at")),
                    first_seen=parse_timestamp(item.get("created_at")),
                    last_seen=parse_timestamp(item.get("pushed_at")),
                    evidence={
                        "discovery": "public repository mentioning the target",
                        "description": str(item.get("description") or "")[:200],
                    },
                    attributes={
                        "stars": item.get("stargazers_count"),
                        "language": item.get("language"),
                        "archived": item.get("archived"),
                        "owner": (item.get("owner") or {}).get("login"),
                    },
                )
            )
        return out

    def _search_code(self, query: ProviderQuery) -> list[ObservationRecord]:
        domain = query.target.registrable or query.target.value
        payload = self._http_json(
            f'https://api.github.com/search/code?q="{domain}"&per_page=50'
        )
        if not isinstance(payload, dict):
            return []

        out: list[ObservationRecord] = []
        hosts: set[str] = set()
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            html_url = str(item.get("html_url") or "")
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.REPOSITORY,
                    value=f"github.com/{repo.get('full_name', '')}",
                    source_type=SourceKind.EXTERNAL,
                    confidence=60,
                    evidence={
                        "discovery": "public code referencing the target",
                        "path": str(item.get("path") or "")[:200],
                        "match_url": html_url[:300],
                    },
                )
            )
            # The search API returns file metadata, not content, so hostname
            # extraction happens on the path and repository name only.
            for candidate in (str(item.get("path") or ""), str(repo.get("name") or "")):
                for token in candidate.replace("/", " ").replace("_", " ").split():
                    if domain in token:
                        host = normalize_hostname(token.strip(".,:;\"'"))
                        if host and host not in hosts and is_subdomain_of(host, domain):
                            hosts.add(host)
                            out.append(
                                ObservationRecord(
                                    source=self.id,
                                    asset_type=AssetType.SUBDOMAIN,
                                    value=host,
                                    source_type=SourceKind.EXTERNAL,
                                    confidence=55,
                                    evidence={
                                        "discovery": "hostname referenced in public code"
                                    },
                                )
                            )
        return out
