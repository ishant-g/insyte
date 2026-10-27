"""Read-only settings surface: effective limits and provider configuration.

There is no write endpoint. Insyte's configuration is environment-driven
(`.env` / process environment) by design - see `core/config.py` - so
"changing a setting" means changing the deployment's environment and
restarting, not a database-backed admin panel with its own trust and
validation surface to secure.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import settings
from app.providers import all_providers
from app.schemas.settings import EffectiveSettings, ProviderConfigStatus

router = APIRouter(tags=["settings"])


@router.get("/settings", response_model=EffectiveSettings)
def get_settings() -> EffectiveSettings:
    return EffectiveSettings(
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        tagline=settings.APP_TAGLINE,
        environment=settings.ENVIRONMENT,
        http_total_timeout=settings.HTTP_TOTAL_TIMEOUT,
        http_max_redirects=settings.HTTP_MAX_REDIRECTS,
        http_max_response_bytes=settings.HTTP_MAX_RESPONSE_BYTES,
        http_max_concurrency=settings.HTTP_MAX_CONCURRENCY,
        max_urls_per_scan=settings.MAX_URLS_PER_SCAN,
        max_js_files_per_scan=settings.MAX_JS_FILES_PER_SCAN,
        max_pages_per_scan=settings.MAX_PAGES_PER_SCAN,
        max_subdomains_per_scan=settings.MAX_SUBDOMAINS_PER_SCAN,
        scan_time_limit=settings.SCAN_TIME_LIMIT,
        cache_enabled=settings.CACHE_ENABLED,
        report_retention_days=settings.REPORT_RETENTION_DAYS,
        providers=[
            ProviderConfigStatus(
                id=p.id, name=p.name, requires_api_key=p.requires_api_key, configured=p.configured()
            )
            for p in all_providers()
        ],
    )
