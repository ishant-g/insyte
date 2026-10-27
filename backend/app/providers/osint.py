"""Email breach, email discovery and search-engine dorking providers.

Three providers, three different shapes, one shared boundary: none of them
ever handles a password or a raw leaked credential.

* `HibpProvider` talks to Have I Been Pwned, which by design returns only
  breach *metadata* - a breach's name, date and which categories of data
  it exposed ("email addresses, passwords") - never the exposed values
  themselves. That is not an Insyte limitation layered on top of a richer
  API; HIBP's API does not have a code path that returns a password, so
  there is nothing to accidentally leak here. As of HIBP's 2024 terms,
  every breach-lookup endpoint requires a paid subscription key - there is
  no free tier - so this provider is the common case of "configured by
  almost nobody" and must degrade cleanly.
* `HunterIoProvider` is a conventional keyed domain-search provider, kept
  close to `keyed.GitHubProvider`'s shape.
* `GoogleCseProvider` answers arbitrary dork queries, which are not a
  domain lookup, so - like `vulnerability.NvdProvider.lookup_cpe` - it
  exposes a companion method (`search`) instead of doing the query through
  `fetch()`/`collect()`.

Insyte never queries DeHashed, LeakCheck, IntelX or any other service that
indexes raw leaked credentials. HIBP's breach-metadata-only design is the
deliberate line; nothing in this file, or anything built on it, is meant
to cross it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from app.core.config import settings
from app.core.contracts import ObservationRecord
from app.core.net import HttpError
from app.core.ratelimit import RateLimit
from app.models.enums import AssetType, ObservationStatus, SourceKind
from app.providers.base import Provider, ProviderQuery


class HibpProvider(Provider):
    id = "hibp"
    name = "Have I Been Pwned"
    kind = SourceKind.EXTERNAL
    homepage = "https://haveibeenpwned.com"
    description = (
        "Breach-metadata lookups: which named breaches an email address or "
        "domain appears in, when, and which data classes (e.g. 'email "
        "addresses, passwords') were exposed. Never returns an actual "
        "password or credential value - HIBP's API has no endpoint that "
        "does, by design."
    )
    reliability = 95
    requires_api_key = True
    intents = ("breaches",)
    # The paid tiers vary; this is a conservative floor that keeps Insyte
    # well clear of a 429 regardless of which tier the configured key is on.
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.5, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def auth_headers(self) -> dict[str, str]:
        return {"hibp-api-key": self.credential()}

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        # Breach metadata (a list of named breaches, dates, data classes) is
        # not asset-shaped, so `email_osint` calls `domain_breaches` /
        # `breaches_for_email` directly rather than through the observation
        # pipeline - the same bypass `NvdProvider.lookup_cpe` uses.
        return []

    def domain_breaches(self, domain: str) -> dict[str, list[str]] | None:
        """Every breach HIBP has indexed for `domain`, keyed by email alias.

        `None` means the lookup could not be attempted or failed (no key,
        rate limited, transport error). `{}` means the lookup succeeded and
        found nothing - a domain can legitimately have zero hits.
        """
        if self.unavailable_reason() is not None:
            return None
        cache_key = self._cache.key("provider", self.id, "domain_breaches", domain)
        cached = self._cache.get(cache_key)
        if isinstance(cached, dict):
            self.cache_hits += 1
            return cached
        payload = self._call(f"https://haveibeenpwned.com/api/v3/breacheddomain/{quote(domain)}")
        if payload is None:
            return None
        result = {
            str(alias): [str(name) for name in names]
            for alias, names in payload.items()
            if isinstance(names, list)
        } if isinstance(payload, dict) else {}
        self._cache.set(cache_key, result, self.cache_ttl)
        return result

    def breaches_for_email(self, email: str) -> list[dict[str, Any]] | None:
        """Full breach metadata (name, date, data classes) for one email.

        `None` on failure/unavailability; `[]` when HIBP has no record of
        the address (its 404 response, which is a normal, expected answer
        for the overwhelming majority of harvested emails, not an error).
        """
        if self.unavailable_reason() is not None:
            return None
        cache_key = self._cache.key("provider", self.id, "email_breaches", email.lower())
        cached = self._cache.get(cache_key)
        if isinstance(cached, list):
            self.cache_hits += 1
            return cached
        payload = self._call(
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{quote(email)}?truncateResponse=false"
        )
        if payload is None:
            return None
        out: list[dict[str, Any]] = []
        for row in payload if isinstance(payload, list) else []:
            if not isinstance(row, dict):
                continue
            out.append(
                {
                    "name": row.get("Name"),
                    "title": row.get("Title"),
                    "domain": row.get("Domain"),
                    "breach_date": row.get("BreachDate"),
                    "added_date": row.get("AddedDate"),
                    "data_classes": [str(c) for c in row.get("DataClasses") or []],
                    "is_verified": row.get("IsVerified"),
                    "is_sensitive": row.get("IsSensitive"),
                    "pwn_count": row.get("PwnCount"),
                }
            )
        self._cache.set(cache_key, out, self.cache_ttl)
        return out

    def _call(self, url: str) -> Any:
        """Shared rate-limited GET for the companion methods.

        Mirrors `NvdProvider._request_cves`: companion methods bypass
        `collect()`, so they take the shared-budget check and limiter
        acquisition that `_guarded_fetch` would otherwise provide.
        """
        if not self._limiter.check_shared_budget() or not self._limiter.acquire(
            timeout=self.timeout
        ):
            self.rate_limited = True
            return None
        try:
            with self._limiter:
                return self._http_json(url)
        except HttpError as exc:
            self.errors.append(str(exc)[:160])
            return None


class HunterIoProvider(Provider):
    id = "hunterio"
    name = "Hunter.io"
    kind = SourceKind.EXTERNAL
    homepage = "https://hunter.io"
    description = (
        "Domain-scoped email discovery: publicly indexed professional email "
        "addresses for a domain, plus Hunter's inferred naming pattern "
        "(e.g. {first}.{last}@domain.com). Free tier: 25 searches/month."
    )
    reliability = 78
    requires_api_key = True
    intents = ("emails",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=2.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not query.target.is_domain:
            return []
        domain = query.target.registrable or query.target.value
        url = (
            "https://api.hunter.io/v2/domain-search"
            f"?domain={quote(domain)}&api_key={quote(self.credential())}"
            f"&limit={max(1, min(query.limit, 100))}"
        )
        payload = self._http_json(url)
        if not isinstance(payload, dict):
            return []
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        pattern = data.get("pattern") or None

        out: list[ObservationRecord] = []
        for row in data.get("emails") or []:
            if not isinstance(row, dict):
                continue
            value = str(row.get("value") or "").strip().lower()
            if not value or "@" not in value:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.EMAIL,
                    value=value,
                    source_type=SourceKind.EXTERNAL,
                    confidence=int(row.get("confidence") or 50),
                    status=ObservationStatus.OBSERVED,
                    evidence={
                        "discovery": "Hunter.io domain search",
                        "type": row.get("type"),
                    },
                    attributes={
                        "position": row.get("position"),
                        "department": row.get("department"),
                        # Hunter's domain-search is domain-scoped by
                        # construction, distinct from any single-email
                        # filtering `email_osint` applies to other sources.
                        "domain_scoped": True,
                        # Carried per-observation rather than as provider
                        # state (the provider is a shared, reused instance)
                        # so the module can lift it into its own
                        # module-level `output.data["email_pattern"]`.
                        "email_pattern": pattern,
                    },
                )
            )
        return out


class GoogleCseProvider(Provider):
    id = "google_cse"
    name = "Google Programmable Search"
    kind = SourceKind.EXTERNAL
    homepage = "https://programmablesearchengine.google.com"
    description = (
        "Google Custom Search JSON API, scoped to a search engine ID (CX) "
        "the user configures at programmablesearchengine.google.com. Used "
        "for read-only Google-dork-style queries against Google's own "
        "index - never a direct request to the scan target. Free tier: "
        "100 queries/day."
    )
    reliability = 82
    requires_api_key = True
    intents = ("dorks",)
    rate_limit = RateLimit(requests=10, window=60.0, min_interval=1.0, concurrency=1)
    cache_ttl = 21600
    timeout = 20.0

    def _creds(self) -> tuple[str, str]:
        from app.core.credentials import override_value

        api_key = override_value("google_cse", "api_key") or settings.GOOGLE_CSE_API_KEY
        cx = override_value("google_cse", "cx") or settings.GOOGLE_CSE_CX
        return api_key, cx

    def configured(self) -> bool:
        api_key, cx = self._creds()
        return bool(api_key and cx)

    def unavailable_reason(self) -> str | None:
        api_key, cx = self._creds()
        missing = [
            name
            for name, value in (("GOOGLE_CSE_API_KEY", api_key), ("GOOGLE_CSE_CX", cx))
            if not value
        ]
        if missing:
            return f"API credentials not configured ({' / '.join(missing)})"
        return None

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        # A dork query is arbitrary free text chosen by the caller, not a
        # domain lookup - `google_dorking` calls `search()` directly, the
        # same bypass `NvdProvider.lookup_cpe` uses for CPE lookups. This
        # only exists to satisfy the abstract base class.
        return []

    def search(self, query: str, num: int = 10) -> list[dict[str, str]]:
        if self.unavailable_reason() is not None:
            return []
        cache_key = self._cache.key("provider", self.id, "search", query, num)
        cached = self._cache.get(cache_key)
        if isinstance(cached, list):
            self.cache_hits += 1
            return cached
        if not self._limiter.check_shared_budget() or not self._limiter.acquire(
            timeout=self.timeout
        ):
            self.rate_limited = True
            return []
        api_key, cx = self._creds()
        url = (
            "https://www.googleapis.com/customsearch/v1"
            f"?key={quote(api_key)}"
            f"&cx={quote(cx)}"
            f"&q={quote(query)}&num={max(1, min(num, 10))}"
        )
        try:
            with self._limiter:
                payload = self._http_json(url)
        except HttpError as exc:
            self.errors.append(str(exc)[:160])
            return []
        if not isinstance(payload, dict):
            return []
        out: list[dict[str, str]] = []
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            link = str(item.get("link") or "").strip()
            if not link:
                continue
            out.append(
                {
                    "url": link,
                    "title": str(item.get("title") or "")[:300],
                    "snippet": str(item.get("snippet") or "")[:500],
                }
            )
        self._cache.set(cache_key, out, self.cache_ttl)
        return out
