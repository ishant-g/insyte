"""Per-provider rate limiting and retry policy.

Insyte leans heavily on free public services - crt.sh, the Wayback CDX
API, Common Crawl's index, HackerTarget, RapidDNS. Those services will
happily serve a polite client and will block an impolite one, so the
limiter is a correctness feature: exceeding a provider's budget makes the
scan's results *worse*, not faster.

Two enforcement layers:

* a process-local token bucket, which always works;
* a Redis counter shared across workers, so N concurrent workers do not
  each independently decide they are within budget.

Redis being unavailable degrades to the local bucket only. That is weaker
but never blocks a scan.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from app.core.cache import get_cache
from app.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RateLimit:
    """A provider's declared budget."""

    #: Requests permitted per window.
    requests: int
    #: Window length in seconds.
    window: float = 60.0
    #: Minimum gap between two consecutive calls, in seconds.
    min_interval: float = 0.0
    #: Concurrent in-flight calls allowed to this provider.
    concurrency: int = 2

    @property
    def per_second(self) -> float:
        return self.requests / self.window if self.window else float(self.requests)


class RateLimitExceeded(Exception):
    """The provider's budget is spent for this window."""


class ProviderLimiter:
    """Token bucket plus minimum-interval spacing for a single provider."""

    def __init__(self, provider: str, limit: RateLimit) -> None:
        self.provider = provider
        self.limit = limit
        self._lock = threading.Lock()
        self._tokens = float(limit.requests)
        self._updated = time.monotonic()
        self._last_call = 0.0
        self._semaphore = threading.BoundedSemaphore(max(1, limit.concurrency))
        self.throttled_count = 0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed <= 0:
            return
        self._tokens = min(
            float(self.limit.requests), self._tokens + elapsed * self.limit.per_second
        )
        self._updated = now

    def acquire(self, *, timeout: float = 30.0) -> bool:
        """Block until a token is available, or give up after `timeout`."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    gap = time.monotonic() - self._last_call
                    if gap >= self.limit.min_interval:
                        self._tokens -= 1.0
                        self._last_call = time.monotonic()
                        return True
                    wait = self.limit.min_interval - gap
                else:
                    wait = max(0.05, 1.0 / max(self.limit.per_second, 0.01))
            if time.monotonic() + wait > deadline:
                self.throttled_count += 1
                return False
            time.sleep(min(wait, 1.0))

    def check_shared_budget(self) -> bool:
        """Consult the cross-worker counter in Redis.

        Returns True when the call is within budget, and also True when
        Redis is unavailable - the local bucket is then the only control,
        which is the correct trade-off against failing the scan.
        """
        cache = get_cache()
        if not cache.available:
            return True
        window = int(self.limit.window)
        bucket = int(time.time() // window)
        key = cache.key("ratelimit", self.provider, bucket)
        count = cache.incr(key, window + 5)
        if count == 0:  # Redis write failed; do not block on it.
            return True
        # Allow a small shared overshoot: workers race, and refusing a call
        # that is one over budget costs more in lost intelligence than the
        # provider cares about.
        return count <= self.limit.requests + 1

    def __enter__(self) -> ProviderLimiter:
        self._semaphore.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._semaphore.release()


class RateLimiterRegistry:
    """Process-wide map of provider id → limiter."""

    def __init__(self) -> None:
        self._limiters: dict[str, ProviderLimiter] = {}
        self._lock = threading.Lock()

    def get(self, provider: str, limit: RateLimit) -> ProviderLimiter:
        with self._lock:
            limiter = self._limiters.get(provider)
            if limiter is None:
                limiter = ProviderLimiter(provider, limit)
                self._limiters[provider] = limiter
            return limiter

    def stats(self) -> dict[str, dict[str, float]]:
        return {
            name: {
                "requests_per_window": limiter.limit.requests,
                "window": limiter.limit.window,
                "throttled": limiter.throttled_count,
            }
            for name, limiter in self._limiters.items()
        }


_registry = RateLimiterRegistry()


def limiter_for(provider: str, limit: RateLimit) -> ProviderLimiter:
    return _registry.get(provider, limit)


def limiter_stats() -> dict[str, dict[str, float]]:
    return _registry.stats()


def with_retries(
    operation: Callable[[], T],
    *,
    attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    give_up_on: tuple[type[BaseException], ...] = (),
    label: str = "operation",
) -> T:
    """Exponential backoff with jitter.

    Jitter is not decoration: without it, several workers that all hit a
    provider's 429 at the same moment retry in lockstep and hit it again
    together.
    """
    last: BaseException | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return operation()
        except give_up_on:
            raise
        except retry_on as exc:
            last = exc
            if attempt >= attempts:
                break
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay *= 0.5 + random.random()  # noqa: S311 - jitter, not crypto
            logger.info(
                "retrying",
                extra={
                    "label": label,
                    "attempt": attempt,
                    "delay": round(delay, 2),
                    "detail": str(exc)[:160],
                },
            )
            time.sleep(delay)
    assert last is not None  # noqa: S101 - unreachable unless attempts < 1
    raise last
