"""Read-only effective-settings schema for the Settings screen.

Deliberately excludes every credential value - provider configuration is
shown as configured/not-configured only, per section 57 of the brief
("API secrets must never be displayed in plaintext after saving").
"""

from __future__ import annotations

from pydantic import BaseModel


class ProviderConfigStatus(BaseModel):
    id: str
    name: str
    requires_api_key: bool
    configured: bool


class EffectiveSettings(BaseModel):
    app_name: str
    app_version: str
    tagline: str
    environment: str
    http_total_timeout: float
    http_max_redirects: int
    http_max_response_bytes: int
    http_max_concurrency: int
    max_urls_per_scan: int
    max_js_files_per_scan: int
    max_pages_per_scan: int
    max_subdomains_per_scan: int
    scan_time_limit: int
    cache_enabled: bool
    report_retention_days: int
    providers: list[ProviderConfigStatus]
