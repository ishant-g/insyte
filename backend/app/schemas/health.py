"""Health check schema."""

from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    database: bool
    redis: bool
    #: At least one Celery scan worker answered a ping recently. When this
    #: is False, new scans queue forever - the UI uses it to warn before
    #: the user waits on a scan that can never start.
    worker_alive: bool = False
    worker_count: int = 0
