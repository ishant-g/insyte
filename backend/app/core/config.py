"""Centralised, typed configuration for Insyte.

Every value is environment-driven. Nothing here contains a real credential:
the defaults are safe for local development and deliberately point at
localhost services. Production values come from the environment.

External intelligence providers are all optional. A provider whose key is
absent reports itself unavailable and the scan continues without it.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # ---- Application ---------------------------------------------------
    APP_NAME: str = "Insyte"
    APP_TAGLINE: str = "Passive Exposure Intelligence"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "json"

    # ---- Server --------------------------------------------------------
    HOST: str = "0.0.0.0"  # noqa: S104 - container-local bind, published selectively
    PORT: int = 8000
    API_PREFIX: str = "/api"

    # ---- Authentication / accounts -------------------------------------
    #: Signs session JWTs and derives the at-rest encryption key for stored
    #: provider credentials. MUST be overridden in staging/production - the
    #: validator below refuses to boot with this default in production.
    SECRET_KEY: str = "insyte-dev-secret-change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    #: When false, self-service registration is closed (seed/invite only).
    ALLOW_REGISTRATION: bool = True

    # ---- CORS ----------------------------------------------------------
    # Explicit origins only. Never "*" - see core/security_headers.py.
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # ---- HTTPS / transport security ------------------------------------
    # HSTS is opt-in: enabling it over plain HTTP in development would pin
    # localhost to https:// in the developer's browser.
    ENABLE_HSTS: bool = False

    # ---- Database ------------------------------------------------------
    # PostgreSQL only. Insyte relies on JSONB, native uuid and ON CONFLICT.
    DATABASE_URL: str = (
        "postgresql+psycopg://insyte:insyte@localhost:5432/insyte"
    )
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_RECYCLE: int = 1800
    DB_ECHO: bool = False

    # ---- Redis / Celery ------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    CELERY_TASK_ALWAYS_EAGER: bool = False
    #: Hard ceiling on a whole scan, in seconds.
    SCAN_TIME_LIMIT: int = 1800
    SCAN_SOFT_TIME_LIMIT: int = 1680
    #: Hard ceiling on a single module, in seconds.
    MODULE_TIME_LIMIT: int = 300
    #: How long a scan may wait with zero module rows (i.e. the worker
    #: never picked up its task) before reads reap it as an honest failure
    #: instead of showing "scanning" forever. Only applies when no worker
    #: is reachable at all.
    SCAN_PICKUP_TIMEOUT: int = 180

    # ---- HTTP collection limits (Web Surface Collection mode) ----------
    HTTP_CONNECT_TIMEOUT: float = 5.0
    HTTP_READ_TIMEOUT: float = 10.0
    HTTP_TOTAL_TIMEOUT: float = 20.0
    HTTP_MAX_REDIRECTS: int = 3
    HTTP_MAX_RESPONSE_BYTES: int = 5 * 1024 * 1024
    HTTP_MAX_HTML_BYTES: int = 3 * 1024 * 1024
    HTTP_MAX_JS_BYTES: int = 4 * 1024 * 1024
    HTTP_MAX_CSS_BYTES: int = 1 * 1024 * 1024
    HTTP_MAX_CONCURRENCY: int = 6
    #: Hard deadline for one DNS resolution inside the SSRF guard.
    #: `socket.getaddrinfo` takes no timeout of its own; without this a
    #: broken resolver wedges every fetch and the scan stalls at 0%.
    DNS_RESOLVE_TIMEOUT: float = 8.0
    HTTP_USER_AGENT: str = (
        "Insyte/1.0 (Passive Exposure Intelligence; +https://github.com/insyte)"
    )

    # ---- Collection budgets --------------------------------------------
    MAX_URLS_PER_SCAN: int = 5000
    MAX_JS_FILES_PER_SCAN: int = 60
    MAX_PAGES_PER_SCAN: int = 25
    MAX_SITEMAP_DEPTH: int = 3
    MAX_SITEMAP_URLS: int = 2000
    MAX_SUBDOMAINS_PER_SCAN: int = 5000
    MAX_HISTORICAL_URLS: int = 5000

    # ---- SSRF policy ---------------------------------------------------
    #: Only ever relaxed by tests, which point it at a loopback fixture server.
    ALLOW_PRIVATE_TARGETS: bool = False
    #: Extra hostnames the SSRF guard must always refuse, comma separated.
    BLOCKED_HOSTS: str = ""

    # ---- Caching -------------------------------------------------------
    CACHE_ENABLED: bool = True
    CACHE_TTL_DNS: int = 300
    CACHE_TTL_PROVIDER: int = 3600
    CACHE_TTL_HISTORICAL: int = 21600
    CACHE_TTL_ARTIFACT: int = 3600

    # ---- Artifact / report storage -------------------------------------
    DATA_DIR: str = "/var/lib/insyte"
    REPORT_RETENTION_DAYS: int = 30

    # ---- Optional external intelligence providers ----------------------
    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    SECURITYTRAILS_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    URLSCAN_API_KEY: str = ""
    OTX_API_KEY: str = ""
    #: HIBP's breach-lookup APIs require a paid key as of 2024; there is no
    #: free tier, so this is the common case of "left blank".
    HIBP_API_KEY: str = ""
    HUNTER_API_KEY: str = ""
    #: Google Programmable Search - both are required; CensysProvider's
    #: two-part-credential pattern (see `providers.keyed`) applies here too.
    GOOGLE_CSE_API_KEY: str = ""
    GOOGLE_CSE_CX: str = ""
    ABUSEIPDB_API_KEY: str = ""
    CHAOS_API_KEY: str = ""
    GRAYHATWARFARE_API_KEY: str = ""
    #: Optional - the GreyNoise Community API answers unauthenticated
    #: requests at a reduced rate limit, so this only raises the ceiling.
    GREYNOISE_API_KEY: str = ""
    #: Free registration token, not an anonymous-access key - see
    #: CorporateIntelligenceModule / OpenCorporatesProvider.
    OPENCORPORATES_API_TOKEN: str = ""

    # ---- CVE intelligence ----------------------------------------------
    #: NVD works without a key but is rate limited to 5 requests / 30s.
    NVD_API_KEY: str = ""
    CVE_LOOKUP_ENABLED: bool = True
    #: Refuse to map a CVE unless version evidence is at least this confident.
    CVE_MIN_VERSION_CONFIDENCE: int = 70

    # ---- Derived -------------------------------------------------------
    @field_validator("DATABASE_URL")
    @classmethod
    def _require_postgres(cls, value: str) -> str:
        """Insyte is PostgreSQL-only; fail loudly rather than half-work.

        SQLite is tolerated so the unit-test suite can run without a server,
        but it is never a valid production value.
        """
        allowed = (
            "postgresql://",
            "postgresql+psycopg://",
            "sqlite://",
            "sqlite+pysqlite://",
        )
        if not value.startswith(allowed):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL URL "
                "(postgresql+psycopg://...). Insyte does not support other "
                f"dialects; got {value.split('://', 1)[0]}://"
            )
        return value

    @model_validator(mode="after")
    def _require_prod_secret(self) -> Settings:
        if self.ENVIRONMENT == "production" and self.SECRET_KEY == "insyte-dev-secret-change-me":
            raise ValueError(
                "SECRET_KEY must be set to a strong random value in production "
                "(it signs session tokens and encrypts stored provider keys)."
            )
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def blocked_hosts(self) -> frozenset[str]:
        return frozenset(
            h.strip().lower() for h in self.BLOCKED_HOSTS.split(",") if h.strip()
        )

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    def provider_key(self, name: str) -> str:
        """Look up a provider credential by lowercase provider id."""
        return {
            "virustotal": self.VIRUSTOTAL_API_KEY,
            "shodan": self.SHODAN_API_KEY,
            "censys": self.CENSYS_API_ID,
            "securitytrails": self.SECURITYTRAILS_API_KEY,
            "github": self.GITHUB_TOKEN,
            "urlscan": self.URLSCAN_API_KEY,
            "otx": self.OTX_API_KEY,
            "nvd": self.NVD_API_KEY,
            "abuseipdb": self.ABUSEIPDB_API_KEY,
            "chaos": self.CHAOS_API_KEY,
            "grayhatwarfare": self.GRAYHATWARFARE_API_KEY,
            "greynoise": self.GREYNOISE_API_KEY,
            "opencorporates": self.OPENCORPORATES_API_TOKEN,
            "hibp": self.HIBP_API_KEY,
            "hunterio": self.HUNTER_API_KEY,
            # google_cse needs two values; its own configured()/
            # unavailable_reason() read the settings directly instead.
        }.get(name.lower(), "")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
