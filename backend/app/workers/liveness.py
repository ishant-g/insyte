"""Scan-worker liveness checks.

The API dispatches scans to Celery and otherwise never hears from the
worker again. When the worker is down (or was never started), scans sit
at "scanning" forever with no explanation - the single most confusing
failure in the product. These helpers let scan creation warn immediately
and let reads reap orphaned scans, so a dead worker is always visible
instead of silent.
"""

from __future__ import annotations

import time

from app.core.logging import get_logger

logger = get_logger(__name__)

#: A ping result is trusted this long before re-pinging, so health polls
#: and scan creation stay cheap.
_CACHE_TTL = 30.0

_cached: tuple[float, bool, int] | None = None


def worker_status(*, timeout: float = 2.0) -> tuple[bool, int]:
    """Return ``(alive, worker_count)``. Never raises.

    `alive` is True when at least one Celery worker answered the ping.
    Results are cached briefly; a down worker costs one `timeout`-second
    ping per cache window, not per request.
    """
    global _cached
    now = time.monotonic()
    if _cached is not None and now - _cached[0] < _CACHE_TTL:
        return _cached[1], _cached[2]
    alive, count = _ping(timeout)
    _cached = (now, alive, count)
    return alive, count


def _ping(timeout: float) -> tuple[bool, int]:
    try:
        from app.workers.celery_app import celery

        replies = celery.control.ping(timeout=timeout) or []
        return len(replies) > 0, len(replies)
    except Exception:  # noqa: BLE001 - liveness must never break a request
        logger.warning("worker_ping_failed")
        return False, 0
