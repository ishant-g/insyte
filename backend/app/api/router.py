"""Aggregates every route module under the /api prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    auth,
    credentials,
    health,
    modules,
    projects,
    reports,
    scan_data,
    scans,
    schedules,
)
from app.api.routes import (
    settings as settings_routes,
)
from app.core.config import settings

api_router = APIRouter()
# Health is unprefixed: orchestrators and load balancers expect /health.
api_router.include_router(health.router)

prefixed = APIRouter(prefix=settings.API_PREFIX)
prefixed.include_router(auth.router)
prefixed.include_router(credentials.router)
prefixed.include_router(scans.router)
prefixed.include_router(schedules.router)
prefixed.include_router(scan_data.router)
prefixed.include_router(reports.router)
prefixed.include_router(modules.router)
prefixed.include_router(projects.router)
prefixed.include_router(settings_routes.router)
api_router.include_router(prefixed)
