"""Provider registry.

Providers are instantiated lazily and cached per process, because each one
owns a rate limiter whose state must be shared by everything that uses it.
Asking the registry for "every provider that can answer 'subdomains'" is
how modules stay ignorant of which specific services exist.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any

from app.core.logging import get_logger
from app.providers.archives import (
    CommonCrawlProvider,
    UrlScanProvider,
    WaybackProvider,
)
from app.providers.base import (
    Provider,
    ProviderQuery,
    ProviderRateLimited,
    ProviderResult,
    parse_timestamp,
)
from app.providers.bgp_origin import BgpOriginProvider
from app.providers.corporate_intel import (
    GrayhatWarfareProvider,
    OpenCorporatesProvider,
    SecEdgarProvider,
    WikidataProvider,
)
from app.providers.ct import CertSpotterProvider, CrtShProvider
from app.providers.grepapp import GrepAppProvider
from app.providers.keyed import (
    CensysProvider,
    GitHubProvider,
    SecurityTrailsProvider,
    ShodanProvider,
    VirusTotalProvider,
)
from app.providers.network_intel import (
    AbuseIpDbProvider,
    ChaosProvider,
    GreyNoiseProvider,
)
from app.providers.osint import (
    GoogleCseProvider,
    HibpProvider,
    HunterIoProvider,
)
from app.providers.passive_dns import (
    HackerTargetProvider,
    OtxProvider,
    RapidDnsProvider,
)
from app.providers.registration import (
    RdapProvider,
    RipeStatProvider,
    parse_rdap_domain,
)
from app.providers.threat_intel import ThreatFoxProvider, UrlhausProvider
from app.providers.vulnerability import EpssProvider, KevProvider, NvdProvider

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Sources evaluated and deliberately NOT implemented (live-tested 2026-09):
#
# * BGPView (api.bgpview.io) - DNS for the `api` subdomain is NXDOMAIN
#   (confirmed via both direct resolution and Google DoH; the apex
#   `bgpview.io` still resolves, so this is the service having been
#   decommissioned, not a sandbox restriction). Dead. Its role (BGP origin
#   AS for an IP) is covered by `bgp_origin` via bgp.bortzmeyer.org,
#   verified live 2026-09-27.
# * BufferOver.run - `dns.bufferover.run` is NXDOMAIN (same evidence as
#   above: apex `bufferover.run` resolves, the subdomain does not).
#   `tls.bufferover.run` does resolve but returns HTTP 403
#   `{"message":"Forbidden"}` from an API Gateway/CloudFront front end for
#   every request, matching widely reported reports that the free
#   anonymous endpoint was retired in favour of a paid RapidAPI listing.
#   Dead as a free source either way.
# * DNSDumpster - the documented free API is gone; `api.dnsdumpster.com`
#   returns HTTP 401 `{"error":"API key is missing"}` for every request
#   and its public pricing is a paid API-marketplace product with no
#   usable free tier. The dnsdumpster.com website itself works, but
#   scraping an unofficial HTML-only workflow is out of scope.
# ---------------------------------------------------------------------------

#: Declaration order is also the order results are gathered in, which keeps
#: scan output stable between runs when two sources report the same asset.
PROVIDER_CLASSES: tuple[type[Provider], ...] = (
    CrtShProvider,
    CertSpotterProvider,
    HackerTargetProvider,
    RapidDnsProvider,
    OtxProvider,
    WaybackProvider,
    CommonCrawlProvider,
    UrlScanProvider,
    RdapProvider,
    RipeStatProvider,
    BgpOriginProvider,
    VirusTotalProvider,
    ShodanProvider,
    CensysProvider,
    SecurityTrailsProvider,
    GitHubProvider,
    GrepAppProvider,
    NvdProvider,
    EpssProvider,
    KevProvider,
    AbuseIpDbProvider,
    GreyNoiseProvider,
    ThreatFoxProvider,
    UrlhausProvider,
    ChaosProvider,
    OpenCorporatesProvider,
    SecEdgarProvider,
    WikidataProvider,
    GrayhatWarfareProvider,
    HibpProvider,
    HunterIoProvider,
    GoogleCseProvider,
)

_instances: dict[str, Provider] = {}
_lock = threading.Lock()


def get_provider(provider_id: str) -> Provider | None:
    """Return the shared instance of a provider by id."""
    key = provider_id.strip().lower()
    with _lock:
        existing = _instances.get(key)
        if existing is not None:
            return existing
        for cls in PROVIDER_CLASSES:
            if cls.id == key:
                instance = cls()
                _instances[key] = instance
                return instance
    return None


def providers_for(intent: str) -> list[Provider]:
    """Every provider that claims it can answer `intent`, in declared order."""
    out: list[Provider] = []
    for cls in PROVIDER_CLASSES:
        if intent in cls.intents:
            instance = get_provider(cls.id)
            if instance is not None:
                out.append(instance)
    return out


def available_providers_for(intent: str) -> list[Provider]:
    """Providers for `intent` that are actually usable right now."""
    return [p for p in providers_for(intent) if p.unavailable_reason() is None]


def all_providers() -> list[Provider]:
    return [p for p in (get_provider(cls.id) for cls in PROVIDER_CLASSES) if p]


def describe_providers() -> list[dict[str, Any]]:
    """Provider catalogue for the settings screen and the report appendix."""
    return [provider.describe() for provider in all_providers()]


def reset_providers() -> None:
    """Drop cached instances. Used between tests."""
    with _lock:
        _instances.clear()


def collect_from(
    provider_ids: Iterable[str], query: ProviderQuery
) -> list[ProviderResult]:
    """Run several providers for one query, isolating each one's failures."""
    results: list[ProviderResult] = []
    for provider_id in provider_ids:
        provider = get_provider(provider_id)
        if provider is None:
            logger.warning("unknown_provider", extra={"provider": provider_id})
            continue
        results.append(provider.collect(query))
    return results


#: Static catalogue seeded into the `sources` table by migration, so
#: provenance is a foreign key rather than an unvalidated string.
def source_catalogue() -> list[dict[str, Any]]:
    rows = [
        {
            "id": cls.id,
            "name": cls.name,
            "kind": cls.kind.value,
            "description": cls.description,
            "homepage": cls.homepage,
            "requires_api_key": cls.requires_api_key,
            "reliability": cls.reliability,
        }
        for cls in PROVIDER_CLASSES
    ]
    # Sources that are not third-party providers but still need provenance.
    rows.extend(
        [
            {
                "id": "dns",
                "name": "DNS",
                "kind": "passive",
                "description": "Direct DNS resolution via the configured resolvers.",
                "homepage": "",
                "requires_api_key": False,
                "reliability": 97,
            },
            {
                "id": "doh",
                "name": "DNS over HTTPS",
                "kind": "passive",
                "description": (
                    "Public DNS-over-HTTPS resolvers, used as a second opinion "
                    "when the local resolver is restricted or inconsistent."
                ),
                "homepage": "https://dns.google",
                "requires_api_key": False,
                "reliability": 93,
            },
            {
                "id": "tls",
                "name": "TLS Handshake",
                "kind": "web_surface",
                "description": "Certificate observed during a TLS handshake.",
                "homepage": "",
                "requires_api_key": False,
                "reliability": 99,
            },
            {
                "id": "web_surface",
                "name": "Web Surface Collection",
                "kind": "web_surface",
                "description": (
                    "Read-only HTTP GET of publicly linked resources on the target."
                ),
                "homepage": "",
                "requires_api_key": False,
                "reliability": 95,
            },
            {
                "id": "derived",
                "name": "Insyte Correlation",
                "kind": "derived",
                "description": (
                    "Conclusion derived by Insyte from other observations rather "
                    "than reported by any single source."
                ),
                "homepage": "",
                "requires_api_key": False,
                "reliability": 75,
            },
        ]
    )
    return rows


__all__ = [
    "PROVIDER_CLASSES",
    "Provider",
    "ProviderQuery",
    "ProviderRateLimited",
    "ProviderResult",
    "all_providers",
    "available_providers_for",
    "collect_from",
    "describe_providers",
    "get_provider",
    "parse_rdap_domain",
    "parse_timestamp",
    "providers_for",
    "reset_providers",
    "source_catalogue",
]
