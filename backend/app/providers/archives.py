"""Historical web-archive providers: Wayback, Common Crawl, URLScan.

These are what let Insyte answer "what did the public Internet know about
this target two years ago?" - old JavaScript bundles, retired API versions,
subdomains that no longer resolve, configuration paths that were once
linked. Historically-observed exposure is frequently the most interesting
part of an attack surface precisely because nobody is looking after it.

Two behaviours are deliberate:

* Insyte only *queries* existing archive data. It never submits the target
  for a new scan (URLScan's submission API is not used), because that would
  both interact with the target indirectly and publish the fact that
  someone is looking at it.
* Everything returned is marked `HISTORICAL`. An archived URL is evidence
  that the URL existed once, not that it resolves today, and the UI and
  reports say so.
"""

from __future__ import annotations

from typing import Any

from app.core.contracts import ObservationRecord
from app.core.net import HttpError
from app.core.ratelimit import RateLimit
from app.core.target import is_subdomain_of, normalize_hostname
from app.models.enums import AssetType, ObservationStatus, SourceKind
from app.providers.base import Provider, ProviderQuery, parse_timestamp


class WaybackProvider(Provider):
    id = "wayback"
    name = "Wayback Machine"
    kind = SourceKind.HISTORICAL
    homepage = "https://web.archive.org"
    description = (
        "Internet Archive CDX index. Yields historical URLs, retired API paths, "
        "old JavaScript bundles and hostnames that no longer resolve."
    )
    reliability = 85
    requires_api_key = False
    intents = ("urls", "subdomains")
    # The CDX API is generous but the service is often under load; one
    # in-flight request with real spacing is the difference between getting
    # results and getting a 503.
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 45.0
    max_response_bytes = 24 * 1024 * 1024

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        limit = min(query.limit, 10000)
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={domain}&matchType=domain"
            "&output=json"
            "&fl=original,timestamp,mimetype,statuscode,digest"
            "&collapse=urlkey"
            f"&limit={limit}"
        )
        try:
            payload = self._http_json(url)
        except HttpError as exc:
            # The Internet Archive returns an HTML "Temporarily Offline"
            # page with a 503 during maintenance. That is an outage, not a
            # scan failure, and it must read that way in the UI.
            if "503" in str(exc) or "502" in str(exc):
                self.errors.append("Internet Archive temporarily unavailable")
                return []
            raise

        if not isinstance(payload, list) or len(payload) < 2:
            return []

        header = [str(h) for h in payload[0]]
        rows = payload[1:]
        index = {name: position for position, name in enumerate(header)}

        out: list[ObservationRecord] = []
        hosts_seen: set[str] = set()
        for row in rows:
            if not isinstance(row, list):
                continue

            def cell(name: str, row: list = row) -> str:
                position = index.get(name, -1)
                return str(row[position]) if 0 <= position < len(row) else ""

            original = cell("original").strip()
            if not original:
                continue
            observed = parse_timestamp(cell("timestamp"))
            status_code = cell("statuscode")
            mimetype = cell("mimetype")

            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.URL,
                    value=original,
                    source_type=SourceKind.HISTORICAL,
                    confidence=82,
                    status=ObservationStatus.HISTORICAL,
                    observed_at=observed,
                    first_seen=observed,
                    last_seen=observed,
                    evidence={
                        "discovery": "Wayback Machine CDX index entry",
                        "archived_status": status_code or None,
                        "mimetype": mimetype or None,
                    },
                    attributes={"digest": cell("digest") or None},
                )
            )

            # Every archived URL is also evidence that its host existed.
            host = normalize_hostname(_host_of(original))
            if host and host not in hosts_seen and is_subdomain_of(host, domain):
                hosts_seen.add(host)
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=(
                            AssetType.DOMAIN
                            if host == query.target.value
                            else AssetType.SUBDOMAIN
                        ),
                        value=host,
                        source_type=SourceKind.HISTORICAL,
                        confidence=78,
                        status=ObservationStatus.HISTORICAL,
                        observed_at=observed,
                        first_seen=observed,
                        last_seen=observed,
                        evidence={"discovery": "host of an archived URL"},
                    )
                )
        return out


class CommonCrawlProvider(Provider):
    id = "commoncrawl"
    name = "Common Crawl"
    kind = SourceKind.HISTORICAL
    homepage = "https://commoncrawl.org"
    description = (
        "Common Crawl URL index. Independent of the Wayback Machine, so it "
        "frequently surfaces paths the Internet Archive never captured."
    )
    reliability = 82
    requires_api_key = False
    intents = ("urls", "subdomains")
    rate_limit = RateLimit(requests=8, window=60.0, min_interval=1.5, concurrency=1)
    cache_ttl = 43200
    timeout = 60.0
    max_response_bytes = 24 * 1024 * 1024
    #: How many of the most recent monthly crawls to query. Each is a
    #: separate HTTP request, so this trades coverage against scan time.
    crawl_count = 2

    def _latest_indexes(self) -> list[str]:
        """Resolve the newest crawl index ids.

        Hardcoding an index id would silently stop working every month, so
        the collection list is fetched (and cached for a day) instead.
        """
        cache_key = self._cache.key("provider", self.id, "collinfo")
        cached = self._cache.get(cache_key)
        if isinstance(cached, list) and cached:
            return [str(item) for item in cached][: self.crawl_count]

        payload = self._http_json("https://index.commoncrawl.org/collinfo.json")
        if not isinstance(payload, list):
            return []
        ids = [
            str(entry.get("cdx-api") or "")
            for entry in payload
            if isinstance(entry, dict) and entry.get("cdx-api")
        ]
        if ids:
            self._cache.set(cache_key, ids[:6], 86400)
        return ids[: self.crawl_count]

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        indexes = self._latest_indexes()
        if not indexes:
            self.errors.append("Common Crawl index list unavailable")
            return []

        per_index = max(200, min(query.limit, 5000) // max(len(indexes), 1))
        out: list[ObservationRecord] = []
        hosts_seen: set[str] = set()

        for index_url in indexes:
            request_url = (
                f"{index_url}?url=*.{domain}&output=json&limit={per_index}"
            )
            try:
                rows = self._http_ndjson(request_url)
            except HttpError as exc:
                # A 404 from one monthly index means "this crawl saw
                # nothing for this domain" - normal, not an error.
                if "404" in str(exc):
                    continue
                self.errors.append(f"index unavailable: {str(exc)[:80]}")
                continue

            for row in rows:
                if not isinstance(row, dict):
                    continue
                url_value = str(row.get("url") or "").strip()
                if not url_value:
                    continue
                observed = parse_timestamp(row.get("timestamp"))
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.URL,
                        value=url_value,
                        source_type=SourceKind.HISTORICAL,
                        confidence=80,
                        status=ObservationStatus.HISTORICAL,
                        observed_at=observed,
                        first_seen=observed,
                        last_seen=observed,
                        evidence={
                            "discovery": "Common Crawl index entry",
                            "crawl": index_url.rsplit("/", 1)[-1],
                            "archived_status": row.get("status"),
                            "mimetype": row.get("mime-detected") or row.get("mime"),
                        },
                        attributes={"digest": row.get("digest")},
                    )
                )
                host = normalize_hostname(_host_of(url_value))
                if host and host not in hosts_seen and is_subdomain_of(host, domain):
                    hosts_seen.add(host)
                    out.append(
                        ObservationRecord(
                            source=self.id,
                            asset_type=(
                                AssetType.DOMAIN
                                if host == query.target.value
                                else AssetType.SUBDOMAIN
                            ),
                            value=host,
                            source_type=SourceKind.HISTORICAL,
                            confidence=76,
                            status=ObservationStatus.HISTORICAL,
                            observed_at=observed,
                            first_seen=observed,
                            last_seen=observed,
                            evidence={"discovery": "host of a Common Crawl URL"},
                        )
                    )
        return out


class UrlScanProvider(Provider):
    id = "urlscan"
    name = "URLScan.io"
    kind = SourceKind.HISTORICAL
    homepage = "https://urlscan.io"
    description = (
        "Searches URLScan's existing public scan corpus for the target. Returns "
        "observed pages, hosts, technologies and requested resources. Insyte "
        "never submits the target for a new scan."
    )
    reliability = 86
    #: The search API works anonymously; a key raises the quota.
    requires_api_key = False
    intents = ("urls", "subdomains", "technologies")
    rate_limit = RateLimit(requests=20, window=60.0, min_interval=0.5, concurrency=2)
    cache_ttl = 10800
    timeout = 30.0
    max_response_bytes = 12 * 1024 * 1024

    def auth_headers(self) -> dict[str, str]:
        key = self.credential()
        return {"API-Key": key} if key else {}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return self._fetch_by_ip(query)
        domain = query.target.registrable or query.target.value
        size = min(query.limit, 1000)
        url = (
            "https://urlscan.io/api/v1/search/"
            f"?q=domain%3A{domain}&size={size}"
        )
        payload = self._http_json(url)
        if not isinstance(payload, dict):
            return []
        return self._parse_results(query, payload.get("results") or [], domain)

    def _fetch_by_ip(self, query: ProviderQuery) -> list[ObservationRecord]:
        url = (
            "https://urlscan.io/api/v1/search/"
            f"?q=ip%3A{query.target.value}&size={min(query.limit, 500)}"
        )
        payload = self._http_json(url)
        if not isinstance(payload, dict):
            return []
        out: list[ObservationRecord] = []
        for row in payload.get("results") or []:
            if not isinstance(row, dict):
                continue
            page = row.get("page") if isinstance(row.get("page"), dict) else {}
            host = normalize_hostname(str(page.get("domain") or ""))
            if not host:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.DOMAIN,
                    value=host,
                    source_type=SourceKind.HISTORICAL,
                    confidence=70,
                    status=ObservationStatus.HISTORICAL,
                    observed_at=parse_timestamp(
                        (row.get("task") or {}).get("time")
                        if isinstance(row.get("task"), dict)
                        else None
                    ),
                    evidence={
                        "discovery": "URLScan result served from this address",
                        "address": query.target.value,
                    },
                )
            )
        return out

    def _parse_results(
        self, query: ProviderQuery, results: list[Any], domain: str
    ) -> list[ObservationRecord]:
        out: list[ObservationRecord] = []
        hosts_seen: set[str] = set()
        for row in results:
            if not isinstance(row, dict):
                continue
            page = row.get("page") if isinstance(row.get("page"), dict) else {}
            task = row.get("task") if isinstance(row.get("task"), dict) else {}
            observed = parse_timestamp(task.get("time") or page.get("time"))

            page_url = str(page.get("url") or task.get("url") or "").strip()
            if page_url:
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.URL,
                        value=page_url,
                        source_type=SourceKind.HISTORICAL,
                        confidence=84,
                        status=ObservationStatus.HISTORICAL,
                        observed_at=observed,
                        first_seen=observed,
                        last_seen=observed,
                        evidence={
                            "discovery": "URLScan public scan result",
                            "scan_id": row.get("_id"),
                            "archived_status": page.get("status"),
                        },
                    )
                )

            for key in ("domain", "apexDomain"):
                host = normalize_hostname(str(page.get(key) or ""))
                if not host or host in hosts_seen or not is_subdomain_of(host, domain):
                    continue
                hosts_seen.add(host)
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=(
                            AssetType.DOMAIN
                            if host == query.target.value
                            else AssetType.SUBDOMAIN
                        ),
                        value=host,
                        source_type=SourceKind.HISTORICAL,
                        confidence=80,
                        status=ObservationStatus.HISTORICAL,
                        observed_at=observed,
                        first_seen=observed,
                        last_seen=observed,
                        evidence={"discovery": "URLScan observed host"},
                        attributes={
                            "ip": page.get("ip"),
                            "asn": page.get("asn"),
                            "asn_name": page.get("asnname"),
                            "server": page.get("server"),
                        },
                    )
                )

            address = str(page.get("ip") or "").strip()
            if address:
                out.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.IP,
                        value=address,
                        source_type=SourceKind.HISTORICAL,
                        confidence=76,
                        status=ObservationStatus.HISTORICAL,
                        observed_at=observed,
                        evidence={
                            "discovery": "address serving a URLScan result",
                            "host": page.get("domain"),
                        },
                        attributes={
                            "asn": page.get("asn"),
                            "asn_name": page.get("asnname"),
                            "country": page.get("country"),
                        },
                    )
                )
        return out


def _host_of(url: str) -> str:
    """Extract a hostname from a possibly-malformed archived URL."""
    text = url.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    elif text.startswith("//"):
        text = text[2:]
    text = text.split("/", 1)[0].split("?", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        return text.partition("]")[0].lstrip("[")
    return text.split(":", 1)[0]
