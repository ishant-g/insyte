"""Redis-backed cache with graceful degradation.

Two jobs: stop Insyte from asking crt.sh the same question twice in one
scan, and stop it from asking twice across scans of the same target within
a TTL. Both matter because these are free public services and hammering
them is both rude and self-defeating (they rate-limit, and then the scan
gets worse results).

Redis being unreachable is not an error. Every method degrades to
"cache miss" and the scan proceeds, because a cache outage must not take
the product down.
"""

from __future__ import annotations

import json
import threading
from typing import Any

import redis

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_KEY_PREFIX = "insyte:v1"

#: Never cache anything that could contain a credential. Provider responses
#: are cached; artifact bodies and anything from the secret scanner are not.
_FORBIDDEN_NAMESPACES = frozenset({"secret", "credential", "token"})


class Cache:
    """Thin JSON cache over Redis. Thread-safe; safe to share."""

    def __init__(self, url: str | None = None, *, enabled: bool | None = None) -> None:
        self._url = url or settings.REDIS_URL
        self._enabled = settings.CACHE_ENABLED if enabled is None else enabled
        self._client: redis.Redis | None = None
        self._lock = threading.Lock()
        self._degraded = False
        self.hits = 0
        self.misses = 0

    # -- connection ------------------------------------------------------

    def _connect(self) -> redis.Redis | None:
        if not self._enabled or self._degraded:
            return None
        if self._client is not None:
            return self._client
        with self._lock:
            if self._client is not None:
                return self._client
            try:
                client = redis.Redis.from_url(
                    self._url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                    health_check_interval=30,
                )
                client.ping()
            except Exception as exc:  # noqa: BLE001 - any failure means "no cache"
                logger.warning(
                    "cache_unavailable",
                    extra={"detail": str(exc)[:200]},
                )
                self._degraded = True
                return None
            self._client = client
            return client

    @property
    def available(self) -> bool:
        return self._connect() is not None

    # -- operations ------------------------------------------------------

    @staticmethod
    def key(namespace: str, *parts: object) -> str:
        joined = ":".join(str(p).replace(" ", "_")[:200] for p in parts if p is not None)
        return f"{_KEY_PREFIX}:{namespace}:{joined}"

    def get(self, key: str) -> Any | None:
        client = self._connect()
        if client is None:
            self.misses += 1
            return None
        try:
            raw = client.get(key)
        except Exception as exc:  # noqa: BLE001
            logger.debug("cache_get_failed", extra={"detail": str(exc)[:120]})
            self.misses += 1
            return None
        if raw is None:
            self.misses += 1
            return None
        self.hits += 1
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            # A corrupt entry is a miss, not a crash.
            self.misses += 1
            return None

    def set(self, key: str, value: Any, ttl: int) -> bool:
        namespace = key.split(":")[2] if key.count(":") >= 2 else ""
        if namespace in _FORBIDDEN_NAMESPACES:
            logger.warning("cache_write_refused", extra={"namespace": namespace})
            return False
        client = self._connect()
        if client is None:
            return False
        try:
            payload = json.dumps(value, default=str)
        except (TypeError, ValueError):
            return False
        # A single cached provider response should never be enormous; a
        # multi-megabyte value in Redis is a symptom of a bug elsewhere.
        if len(payload) > 4 * 1024 * 1024:
            logger.warning("cache_value_too_large", extra={"size": len(payload)})
            return False
        try:
            client.setex(key, max(1, int(ttl)), payload)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("cache_set_failed", extra={"detail": str(exc)[:120]})
            return False

    def delete(self, key: str) -> None:
        client = self._connect()
        if client is None:
            return
        try:
            client.delete(key)
        except Exception:  # noqa: BLE001
            pass

    def incr(self, key: str, ttl: int) -> int:
        """Atomic counter, used by the rate limiter."""
        client = self._connect()
        if client is None:
            return 0
        try:
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, max(1, int(ttl)), nx=True)
            result = pipe.execute()
            return int(result[0])
        except Exception:  # noqa: BLE001
            return 0

    def close(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:  # noqa: BLE001
                    pass
                self._client = None

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self._enabled,
            "available": not self._degraded,
            "hits": self.hits,
            "misses": self.misses,
        }


_cache: Cache | None = None
_cache_lock = threading.Lock()


def get_cache() -> Cache:
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                _cache = Cache()
    return _cache


def reset_cache() -> None:
    global _cache
    with _cache_lock:
        if _cache is not None:
            _cache.close()
            _cache = None
