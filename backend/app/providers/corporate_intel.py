"""Organisation / corporate intelligence providers.

None of these can reliably tell "example.com" apart from an unrelated
company that happens to share a name - a domain label is not a legal
entity name. Each adapter is honest about that: matches are low-confidence
by default, and only promoted to high-confidence when there is independent
corroboration (Wikidata's official-website claim actually resolving to the
scanned domain). `CorporateIntelligenceModule` keeps these candidates out
of the asset graph entirely for the same reason - see its module docstring.
"""

from __future__ import annotations

from typing import Any

from app.core.contracts import ObservationRecord
from app.core.net import HttpError
from app.core.ratelimit import RateLimit
from app.core.target import is_subdomain_of, normalize_hostname
from app.models.enums import AssetType, SourceKind
from app.providers.base import Provider, ProviderQuery


def _company_query(query: ProviderQuery) -> str:
    """Search term: an upstream-supplied org name, or the domain label.

    `CorporateIntelligenceModule` passes the RDAP registrant organisation
    name via `ProviderQuery.value` when one is available and not redacted;
    that is a real (if self-reported) company name. Otherwise this falls
    back to the domain's second-level label - real company names rarely
    match that exactly (hyphens, abbreviations, "the/inc/ltd" suffixes),
    so this is deliberately not clever about disambiguation. The confidence
    score communicates the uncertainty instead of the query pretending to
    resolve it.
    """
    if query.value:
        return query.value.strip()
    domain = query.target.registrable or query.target.value
    label = domain.split(".", 1)[0]
    return label.replace("-", " ").strip()


class OpenCorporatesProvider(Provider):
    id = "opencorporates"
    name = "OpenCorporates"
    kind = SourceKind.EXTERNAL
    homepage = "https://opencorporates.com"
    description = (
        "The largest open database of company registration records. "
        "Anonymous search access was retired; a free registration token "
        "is required. Matches are name-only and low-confidence unless "
        "otherwise corroborated."
    )
    reliability = 55
    #: Confirmed live: the search endpoint now returns 401 "Invalid Api
    #: Token" for every request, including unauthenticated ones.
    requires_api_key = True
    intents = ("corporate",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        term = _company_query(query)
        if not term:
            return []
        payload = self._http_json(
            "https://api.opencorporates.com/v0.4/companies/search"
            f"?q={term}&format=json&api_token={self.credential()}"
        )
        if not isinstance(payload, dict):
            return []
        results = payload.get("results", {}) if isinstance(payload.get("results"), dict) else {}
        companies = results.get("companies") or []
        out: list[ObservationRecord] = []
        for entry in companies[:10]:
            company = entry.get("company") if isinstance(entry, dict) else None
            if not isinstance(company, dict):
                continue
            name = str(company.get("name") or "").strip()
            if not name:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.DOMAIN,
                    value=query.target.value,
                    source_type=SourceKind.EXTERNAL,
                    confidence=40,
                    evidence={
                        "discovery": "company name search by domain label",
                        "matched_name": name,
                        "query": term,
                    },
                    attributes={
                        "name": name,
                        "jurisdiction": company.get("jurisdiction_code"),
                        "company_number": company.get("company_number"),
                        "company_type": company.get("company_type"),
                        "status": company.get("current_status"),
                        "url": company.get("opencorporates_url"),
                    },
                )
            )
        return out


class SecEdgarProvider(Provider):
    id = "sec_edgar"
    name = "SEC EDGAR Full-Text Search"
    kind = SourceKind.EXTERNAL
    homepage = "https://www.sec.gov/edgar"
    description = (
        "U.S. Securities and Exchange Commission full-text filing search. "
        "Free with no registration; the SEC's fair-access policy asks only "
        "for a descriptive User-Agent identifying the requester, not a key. "
        "Matches are name-only and low-confidence, like OpenCorporates."
    )
    reliability = 60
    requires_api_key = False
    intents = ("corporate",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def auth_headers(self) -> dict[str, str]:
        return {"User-Agent": "Insyte Passive Exposure Intelligence contact@insyte.example"}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        term = _company_query(query)
        if not term:
            return []
        payload = self._http_json(f'https://efts.sec.gov/LATEST/search-index?q="{term}"')
        if not isinstance(payload, dict):
            return []
        hits = payload.get("hits", {}) if isinstance(payload.get("hits"), dict) else {}
        entries = hits.get("hits") or []
        out: list[ObservationRecord] = []
        seen: set[str] = set()
        for entry in entries[:10]:
            source = entry.get("_source") if isinstance(entry, dict) else None
            if not isinstance(source, dict):
                continue
            names = source.get("display_names") or []
            display = str(names[0]) if names else ""
            if not display or display in seen:
                continue
            seen.add(display)
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.DOMAIN,
                    value=query.target.value,
                    source_type=SourceKind.EXTERNAL,
                    confidence=35,
                    evidence={
                        "discovery": "SEC filer name matching domain label",
                        "matched_name": display,
                        "query": term,
                    },
                    attributes={
                        "ciks": source.get("ciks"),
                        "form": source.get("root_forms"),
                        "filed": source.get("file_date"),
                    },
                )
            )
        return out


class WikidataProvider(Provider):
    id = "wikidata"
    name = "Wikidata"
    kind = SourceKind.EXTERNAL
    homepage = "https://www.wikidata.org"
    description = (
        "Free structured-knowledge search. A name match alone is "
        "low-confidence, but when the matched entity's official-website "
        "claim (P856) resolves to the scanned domain, the match is "
        "corroborated and reported at much higher confidence."
    )
    reliability = 70
    requires_api_key = False
    intents = ("corporate",)
    rate_limit = RateLimit(requests=15, window=60.0, min_interval=0.5, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def auth_headers(self) -> dict[str, str]:
        return {
            "User-Agent": (
                "InsyteBot/1.0 (https://github.com/insyte; "
                "contact@insyte.example) Passive Exposure Intelligence"
            )
        }

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        term = _company_query(query)
        if not term:
            return []
        domain = query.target.registrable or query.target.value
        search = self._http_json(
            "https://www.wikidata.org/w/api.php"
            f"?action=wbsearchentities&search={term}&language=en&format=json&type=item&limit=5"
        )
        if not isinstance(search, dict):
            return []
        out: list[ObservationRecord] = []
        for entry in (search.get("search") or [])[:5]:
            if not isinstance(entry, dict):
                continue
            qid = str(entry.get("id") or "")
            label = str(entry.get("label") or "")
            if not qid or not label:
                continue
            confidence = 30
            official_site = None
            try:
                detail = self._http_json(
                    f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
                )
            except HttpError:
                detail = None
            if isinstance(detail, dict):
                official_site = _official_website(detail, qid)
                if official_site and is_subdomain_of(official_site, domain):
                    confidence = 80
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.DOMAIN,
                    value=query.target.value,
                    source_type=SourceKind.EXTERNAL,
                    confidence=confidence,
                    evidence={
                        "discovery": "Wikidata entity name search",
                        "matched_name": label,
                        "description": entry.get("description"),
                        "official_website_match": confidence >= 80,
                    },
                    attributes={
                        "qid": qid,
                        "wikidata_url": f"https://www.wikidata.org/wiki/{qid}",
                        "official_website": official_site,
                    },
                )
            )
        return out


def _official_website(detail: dict[str, Any], qid: str) -> str | None:
    entity = (detail.get("entities") or {}).get(qid)
    if not isinstance(entity, dict):
        return None
    claims = entity.get("claims")
    if not isinstance(claims, dict):
        return None
    for claim in claims.get("P856") or []:
        try:
            value = claim["mainsnak"]["datavalue"]["value"]
        except (KeyError, TypeError):
            continue
        host = normalize_hostname(str(value).split("//")[-1].split("/")[0])
        if host:
            return host
    return None


class GrayhatWarfareProvider(Provider):
    id = "grayhatwarfare"
    name = "GrayhatWarfare"
    kind = SourceKind.EXTERNAL
    homepage = "https://grayhatwarfare.com"
    description = (
        "Search index of open cloud storage buckets (S3, Azure, GCS). Free "
        "'Registered' tier available via signup. Confirmed endpoint: "
        "/api/v1/files/search (the /buckets/search path used by earlier "
        "API versions no longer exists)."
    )
    reliability = 70
    requires_api_key = True
    intents = ("cloud_buckets",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        keywords = domain.split(".", 1)[0]
        payload = self._http_json(
            "https://buckets.grayhatwarfare.com/api/v1/files/search"
            f"?keywords={keywords}&access_token={self.credential()}"
        )
        if not isinstance(payload, dict):
            return []
        files = payload.get("files") or payload.get("results") or []
        if not isinstance(files, list):
            return []
        out: list[ObservationRecord] = []
        seen: set[str] = set()
        for entry in files[:50]:
            if not isinstance(entry, dict):
                continue
            bucket = str(entry.get("bucket") or entry.get("bucketName") or "").strip()
            if not bucket or bucket in seen:
                continue
            seen.add(bucket)
            provider_hint = str(entry.get("domain") or entry.get("type") or "").lower()
            bucket_provider = (
                "azure" if "azure" in provider_hint or "blob" in provider_hint
                else "gcp" if "google" in provider_hint or "storage.googleapis" in provider_hint
                else "s3"
            )
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.CLOUD_RESOURCE,
                    value=bucket,
                    source_type=SourceKind.EXTERNAL,
                    confidence=70,
                    evidence={
                        "discovery": "open cloud bucket referencing the target",
                        "sample_file": entry.get("filename") or entry.get("path"),
                    },
                    attributes={
                        "bucket_provider": bucket_provider,
                        "public": True,
                        "region": entry.get("region"),
                    },
                )
            )
        return out
