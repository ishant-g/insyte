"""External intelligence provider framework.

Rules that every provider obeys, because the brief makes them product
requirements rather than implementation details:

* **Optional.** A provider that needs a credential and does not have one
  reports `available=False, reason="API key not configured"` and returns
  nothing. It never raises and never fails the scan. Insyte's core is
  fully functional with zero API keys configured.
* **Isolated.** A provider that times out, returns malformed JSON, or is
  rate-limited affects only its own contribution.
* **Normalized.** Providers return `ObservationRecord`s. No provider's
  wire format escapes its adapter - that is the whole point of having an
  adapter.
* **Rate limited.** Every provider declares a budget and the shared
  limiter enforces it, with exponential backoff on failure.
* **Cached.** Responses are cached by (provider, query) so a re-scan
  within the TTL does not re-hit a free public service.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.cache import get_cache
from app.core.config import settings
from app.core.contracts import ObservationRecord, ProviderStatus
from app.core.logging import get_logger
from app.core.net import HttpError, SSRFBlocked, get_client
from app.core.ratelimit import RateLimit, limiter_for, with_retries
from app.core.target import Target
from app.models.enums import SourceKind

logger = get_logger(__name__)


@dataclass(slots=True)
class ProviderQuery:
    """What a provider is being asked about."""

    target: Target
    #: What kind of answer the caller wants: "subdomains", "urls", "ips",
    #: "certificates", "technologies", "repositories", "cves".
    intent: str = "subdomains"
    #: Optional narrower value, e.g. a specific IP or technology name.
    value: str | None = None
    limit: int = 5000

    @property
    def cache_key_parts(self) -> tuple[str, ...]:
        return (self.intent, self.value or self.target.value, str(self.limit))


@dataclass(slots=True)
class ProviderResult:
    """A provider's contribution to a scan."""

    provider: str
    observations: list[ObservationRecord] = field(default_factory=list)
    raw_summary: dict[str, Any] = field(default_factory=dict)
    status: ProviderStatus | None = None

    @property
    def count(self) -> int:
        return len(self.observations)


class Provider(abc.ABC):
    """Base class for every external intelligence adapter."""

    #: Stable slug; also the `sources.id` foreign key value.
    id: str = ""
    name: str = ""
    kind: SourceKind = SourceKind.PASSIVE
    homepage: str = ""
    description: str = ""
    #: 0-100 baseline trust used by the confidence engine.
    reliability: int = 70
    requires_api_key: bool = False
    #: Which intents this provider can answer.
    intents: tuple[str, ...] = ()
    rate_limit: RateLimit = RateLimit(requests=30, window=60.0, min_interval=0.2)
    cache_ttl: int = 3600
    timeout: float = 20.0
    #: Providers that fetch large index responses raise this.
    max_response_bytes: int | None = None

    def __init__(self) -> None:
        self._client = get_client()
        self._cache = get_cache()
        self._limiter = limiter_for(self.id, self.rate_limit)
        self.calls = 0
        self.cache_hits = 0
        self.errors: list[str] = []
        self.rate_limited = False

    # -- configuration ---------------------------------------------------

    def credential(self) -> str:
        # Per-account keys (installed by the scan) take precedence over the
        # deployment's environment defaults. See app/core/credentials.py.
        from app.core.credentials import override_single

        return override_single(self.id) or settings.provider_key(self.id)

    def configured(self) -> bool:
        """True when the provider has whatever it needs to run."""
        if not self.requires_api_key:
            return True
        return bool(self.credential())

    def unavailable_reason(self) -> str | None:
        if self.requires_api_key and not self.credential():
            return "API key not configured"
        return None

    def supports(self, intent: str) -> bool:
        return intent in self.intents

    def status_snapshot(self, *, result_count: int = 0, duration: float = 0.0) -> ProviderStatus:
        reason = self.unavailable_reason()
        return ProviderStatus(
            provider=self.id,
            name=self.name,
            available=reason is None and not self.errors,
            configured=self.configured(),
            requires_api_key=self.requires_api_key,
            reason=reason or (self.errors[0] if self.errors else None),
            calls=self.calls,
            cache_hits=self.cache_hits,
            errors=list(self.errors),
            result_count=result_count,
            rate_limited=self.rate_limited,
            duration=duration,
        )

    # -- public entry point ----------------------------------------------

    def collect(self, query: ProviderQuery) -> ProviderResult:
        """Run the provider. Never raises."""
        started = time.perf_counter()

        reason = self.unavailable_reason()
        if reason is not None:
            logger.info(
                "provider_unavailable",
                extra={"provider": self.id, "reason": reason},
            )
            return ProviderResult(
                provider=self.id,
                status=self.status_snapshot(duration=time.perf_counter() - started),
            )

        if not self.supports(query.intent):
            return ProviderResult(
                provider=self.id,
                status=ProviderStatus(
                    provider=self.id,
                    name=self.name,
                    available=True,
                    configured=True,
                    requires_api_key=self.requires_api_key,
                    reason=f"does not answer '{query.intent}' queries",
                ),
            )

        cache_key = self._cache.key("provider", self.id, *query.cache_key_parts)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self.cache_hits += 1
            observations = self._deserialise(cached)
            logger.info(
                "provider_cache_hit",
                extra={"provider": self.id, "count": len(observations)},
            )
            return ProviderResult(
                provider=self.id,
                observations=observations,
                status=self.status_snapshot(
                    result_count=len(observations),
                    duration=time.perf_counter() - started,
                ),
            )

        try:
            observations = with_retries(
                lambda: self._guarded_fetch(query),
                attempts=2,
                base_delay=0.8,
                retry_on=(HttpError,),
                give_up_on=(SSRFBlocked, ProviderRateLimited),
                label=f"provider:{self.id}",
            )
        except ProviderRateLimited as exc:
            self.rate_limited = True
            self.errors.append(str(exc))
            logger.warning("provider_rate_limited", extra={"provider": self.id})
            observations = []
        except (HttpError, SSRFBlocked) as exc:
            self.errors.append(f"{exc.__class__.__name__}: {str(exc)[:180]}")
            logger.warning(
                "provider_failed",
                extra={"provider": self.id, "detail": str(exc)[:200]},
            )
            observations = []
        except Exception as exc:  # noqa: BLE001 - a provider bug is not a scan bug
            self.errors.append(f"{exc.__class__.__name__}: {str(exc)[:180]}")
            logger.exception("provider_error", extra={"provider": self.id})
            observations = []

        observations = [
            obs for obs in observations if obs.is_valid
        ][: query.limit]

        if observations:
            self._cache.set(cache_key, self._serialise(observations), self.cache_ttl)

        duration = time.perf_counter() - started
        logger.info(
            "provider_completed",
            extra={
                "provider": self.id,
                "count": len(observations),
                "calls": self.calls,
                "duration": round(duration, 3),
                "errors": len(self.errors),
            },
        )
        return ProviderResult(
            provider=self.id,
            observations=observations,
            status=self.status_snapshot(
                result_count=len(observations), duration=duration
            ),
        )

    def _guarded_fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        if not self._limiter.check_shared_budget():
            raise ProviderRateLimited(f"{self.id}: shared budget exhausted")
        if not self._limiter.acquire(timeout=self.timeout):
            raise ProviderRateLimited(f"{self.id}: local rate limit timeout")
        with self._limiter:
            return self.fetch(query)

    # -- HTTP helpers ----------------------------------------------------

    def auth_headers(self) -> dict[str, str]:
        """Credential headers for this provider. Overridden as needed."""
        return {}

    def _http_json(self, url: str, *, accept: str = "application/json") -> Any:
        """GET a provider URL and parse JSON. Raises HttpError on failure."""
        import json

        response = self._client.provider_get(
            url,
            headers={"Accept": accept, **self.auth_headers()},
            max_bytes=self.max_response_bytes,
            accept=accept,
        )
        self.calls += 1
        if response.status_code == 429:
            raise ProviderRateLimited(f"{self.id}: HTTP 429")
        if response.status_code in (401, 403):
            raise HttpError(
                f"{self.id}: credential rejected (HTTP {response.status_code})",
                url=url,
                kind="auth",
            )
        if response.status_code == 404:
            return None
        if not response.ok:
            raise HttpError(
                f"{self.id}: HTTP {response.status_code}", url=url, kind="http_status"
            )
        text = response.text.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError as exc:
            raise HttpError(
                f"{self.id}: malformed JSON response", url=url, kind="parse"
            ) from exc

    def _http_text(self, url: str, *, accept: str = "text/plain") -> str | None:
        response = self._client.provider_get(
            url,
            headers={"Accept": accept, **self.auth_headers()},
            max_bytes=self.max_response_bytes,
            accept=accept,
        )
        self.calls += 1
        if response.status_code == 429:
            raise ProviderRateLimited(f"{self.id}: HTTP 429")
        if response.status_code == 404:
            return None
        if not response.ok:
            raise HttpError(
                f"{self.id}: HTTP {response.status_code}", url=url, kind="http_status"
            )
        return response.text

    def _http_ndjson(self, url: str) -> list[Any]:
        """GET a newline-delimited JSON index response (Common Crawl)."""
        import json

        text = self._http_text(url, accept="application/x-ndjson")
        if not text:
            return []
        rows: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows

    # -- serialisation for the cache -------------------------------------

    @staticmethod
    def _serialise(observations: list[ObservationRecord]) -> list[dict[str, Any]]:
        return [
            {
                "source": obs.source,
                "asset_type": obs.asset_type.value,
                "value": obs.value,
                "source_type": obs.source_type.value,
                "confidence": obs.confidence,
                "status": obs.status.value,
                "observed_at": obs.observed_at.isoformat() if obs.observed_at else None,
                "first_seen": obs.first_seen.isoformat() if obs.first_seen else None,
                "last_seen": obs.last_seen.isoformat() if obs.last_seen else None,
                "evidence": obs.evidence,
                "attributes": obs.attributes,
            }
            for obs in observations
        ]

    @staticmethod
    def _deserialise(payload: Any) -> list[ObservationRecord]:
        from app.models.enums import AssetType, ObservationStatus

        if not isinstance(payload, list):
            return []
        out: list[ObservationRecord] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            try:
                out.append(
                    ObservationRecord(
                        source=str(row.get("source") or ""),
                        asset_type=AssetType(row["asset_type"]),
                        value=str(row.get("value") or ""),
                        source_type=SourceKind(row.get("source_type") or "passive"),
                        confidence=int(row.get("confidence") or 50),
                        status=ObservationStatus(row.get("status") or "observed"),
                        observed_at=_parse_iso(row.get("observed_at")),
                        first_seen=_parse_iso(row.get("first_seen")),
                        last_seen=_parse_iso(row.get("last_seen")),
                        evidence=row.get("evidence") or {},
                        attributes=row.get("attributes") or {},
                    )
                )
            except (KeyError, ValueError):
                continue
        return out

    # -- to implement ----------------------------------------------------

    @abc.abstractmethod
    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        """Do the actual work. May raise; `collect` handles it."""
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind.value,
            "description": self.description,
            "homepage": self.homepage,
            "requires_api_key": self.requires_api_key,
            "configured": self.configured(),
            "reliability": self.reliability,
            "intents": list(self.intents),
            "rate_limit": {
                "requests": self.rate_limit.requests,
                "window_seconds": self.rate_limit.window,
            },
        }


class ProviderRateLimited(Exception):
    """The provider refused because a budget is exhausted."""


def _parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def parse_timestamp(value: Any) -> datetime | None:
    """Tolerant timestamp parsing for provider payloads.

    Providers return epoch seconds, epoch milliseconds, ISO-8601 with and
    without a zone, and Wayback's `YYYYMMDDhhmmss`. All of them appear in
    practice, so all of them are handled rather than trusted.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:  # milliseconds
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        if len(text) == 14:  # Wayback timestamp
            try:
                return datetime.strptime(text, "%Y%m%d%H%M%S").replace(
                    tzinfo=UTC
                )
            except ValueError:
                return None
        if len(text) == 8:
            try:
                return datetime.strptime(text, "%Y%m%d").replace(tzinfo=UTC)
            except ValueError:
                return None
        return parse_timestamp(int(text))
    parsed = _parse_iso(text)
    if parsed is not None:
        return parsed
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%Y/%m/%d",
    ):
        try:
            return datetime.strptime(text[: len(fmt) + 6], fmt).replace(
                tzinfo=UTC
            )
        except ValueError:
            continue
    return None
