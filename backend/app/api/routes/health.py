"""Health check - no auth, no database write, safe to poll aggressively."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.cache import get_cache
from app.core.config import settings
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - health check must not raise
        db_ok = False

    from app.workers.liveness import worker_status

    worker_alive, worker_count = worker_status()

    degraded = not db_ok or not worker_alive
    return HealthResponse(
        status="ok" if not degraded else "degraded",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        database=db_ok,
        redis=get_cache().available,
        worker_alive=worker_alive,
        worker_count=worker_count,
    )
