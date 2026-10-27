"""Intelligence module framework.

A module is a unit of collection with declared capabilities. The
orchestrator reads those declarations to decide what can run (mode and
input type), in what order (dependencies), and what to tell the user when
something does not run (`skip_reason`).

Three rules keep the design honest:

* **A module never touches the database.** It returns a `ModuleOutput`.
  Persistence is one layer's job, which is why modules are unit-testable
  without a server and why a module cannot leave a scan half-written.
* **A module never constructs its own HTTP client.** It uses `ctx.http`,
  which is the SSRF-guarded client. There is no code path from a module to
  an unguarded socket.
* **A module declares its mode support.** A module that cannot run in the
  active mode - wrong scan mode, wrong target type, or no credentials for
  any of its sources - skips itself with a user-actionable reason instead
  of running degraded or reporting an empty success.
* **"Passive" does not mean "zero direct contact."** Passive-mode modules
  may still make a small number of read-only GETs to well-known resources
  on the target itself (homepage, robots.txt, sitemap.xml, `.well-known/*`
  - one request per resource, never a crawl). What passive mode rules out
  is crawling, brute-forcing, fuzzing, port scanning, and exploitation.
  The mode labels say this plainly so the posture is never oversold.
"""

from __future__ import annotations

import abc
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings
from app.core.config import settings as global_settings
from app.core.contracts import ModuleOutput, ProviderStatus
from app.core.logging import ScanLogAdapter, get_logger, scan_logger
from app.core.net import SafeHttpClient, get_client
from app.core.target import Target, TargetType
from app.models.enums import ModuleCategory, ScanMode

logger = get_logger(__name__)


@dataclass(slots=True)
class CollectionLimits:
    """The per-scan collection budget.

    Materialised from settings at scan start and stored on the scan row, so
    a result set is reproducible: you can tell from the record whether a
    scan stopped because there was nothing more to find or because it hit
    its URL ceiling.
    """

    max_urls: int
    max_js_files: int
    max_pages: int
    max_sitemap_depth: int
    max_sitemap_urls: int
    max_subdomains: int
    max_historical_urls: int
    http_total_timeout: float
    http_max_redirects: int
    http_max_concurrency: int

    @classmethod
    def from_settings(cls, config: Settings | None = None) -> CollectionLimits:
        cfg = config or global_settings
        return cls(
            max_urls=cfg.MAX_URLS_PER_SCAN,
            max_js_files=cfg.MAX_JS_FILES_PER_SCAN,
            max_pages=cfg.MAX_PAGES_PER_SCAN,
            max_sitemap_depth=cfg.MAX_SITEMAP_DEPTH,
            max_sitemap_urls=cfg.MAX_SITEMAP_URLS,
            max_subdomains=cfg.MAX_SUBDOMAINS_PER_SCAN,
            max_historical_urls=cfg.MAX_HISTORICAL_URLS,
            http_total_timeout=cfg.HTTP_TOTAL_TIMEOUT,
            http_max_redirects=cfg.HTTP_MAX_REDIRECTS,
            http_max_concurrency=cfg.HTTP_MAX_CONCURRENCY,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_urls": self.max_urls,
            "max_js_files": self.max_js_files,
            "max_pages": self.max_pages,
            "max_sitemap_depth": self.max_sitemap_depth,
            "max_sitemap_urls": self.max_sitemap_urls,
            "max_subdomains": self.max_subdomains,
            "max_historical_urls": self.max_historical_urls,
            "http_total_timeout": self.http_total_timeout,
            "http_max_redirects": self.http_max_redirects,
            "http_max_concurrency": self.http_max_concurrency,
        }


class CancelledError(Exception):
    """Raised inside a module when the scan has been asked to stop."""


@dataclass
class ModuleContext:
    """Everything a module is given, and nothing more.

    Notably absent: a database session. A module that could write to the
    database could also corrupt a scan, and would need a database to test.
    """

    scan_id: str
    target: Target
    mode: ScanMode
    limits: CollectionLimits
    #: Outputs of modules that already ran this scan, keyed by module id.
    upstream: dict[str, ModuleOutput] = field(default_factory=dict)
    #: Called between expensive steps; raises CancelledError if the user
    #: cancelled the scan. Modules should call it in their own loops too.
    cancel_check: Any = None
    _http: SafeHttpClient | None = None
    #: Structured log sink; the orchestrator persists these to `scan_logs`.
    log_sink: Any = None

    # -- services --------------------------------------------------------

    @property
    def http(self) -> SafeHttpClient:
        """The SSRF-guarded client. The only egress a module may use."""
        if self._http is None:
            self._http = get_client()
        return self._http

    def log(self, module_id: str) -> ScanLogAdapter:
        return scan_logger(
            f"insyte.module.{module_id}",
            scan_id=self.scan_id,
            module=module_id,
            target=self.target.value,
        )

    def event(
        self,
        module_id: str,
        event: str,
        message: str = "",
        level: str = "INFO",
        **context: Any,
    ) -> None:
        """Emit a scan log line that the UI will show verbatim."""
        self.log(module_id).info(event, extra={"detail": message, **context})
        if self.log_sink is not None:
            self.log_sink(
                module_id=module_id,
                event=event,
                message=message,
                level=level,
                context=context,
            )

    def check_cancelled(self) -> None:
        if self.cancel_check is not None and self.cancel_check():
            raise CancelledError("scan cancelled by user")

    # -- upstream accessors ----------------------------------------------
    # Dependent modules read what earlier modules found through these, not
    # by reaching into each other's internals.

    def output_of(self, module_id: str) -> ModuleOutput | None:
        return self.upstream.get(module_id)

    def data_of(self, module_id: str, key: str, default: Any = None) -> Any:
        output = self.upstream.get(module_id)
        if output is None:
            return default
        return output.data.get(key, default)

    def web_fetch_blocker(self) -> str | None:
        """Why a module that needs live page content cannot run, if any.

        Returns a human-readable reason when the `web_surface` module ran
        but produced no page content (failed fetch, blocked target), so
        dependent modules can skip honestly instead of reporting a clean
        empty result. Returns None when the fetch was healthy or when
        `web_surface` was not part of this scan.
        """
        upstream = self.upstream.get("web_surface")
        if upstream is None:
            return None
        if not upstream.success:
            detail = upstream.errors[-1] if upstream.errors else "the target did not respond"
            return f"Web fetch failed ({detail[:160]}); no page content to analyze."
        if not (upstream.data.get("bodies") or upstream.data.get("headers")):
            return "Web fetch returned no pages; no page content to analyze."
        return None

    def known_hosts(self, *, in_scope_only: bool = True) -> list[str]:
        """Every hostname discovered so far, deduplicated."""
        from app.core.target import is_subdomain_of

        hosts: set[str] = {self.target.value} if self.target.is_domain else set()
        for output in self.upstream.values():
            for observation in output.observations:
                if observation.asset_type.value in ("domain", "subdomain"):
                    hosts.add(observation.normalized)
            for asset in output.assets:
                if asset.asset_type.value in ("domain", "subdomain"):
                    hosts.add(asset.normalized)
        if in_scope_only and self.target.is_domain:
            scope = self.target.registrable or self.target.value
            hosts = {h for h in hosts if is_subdomain_of(h, scope)}
        return sorted(h for h in hosts if h)

    def known_ips(self) -> list[str]:
        ips: set[str] = {self.target.value} if self.target.is_ip else set()
        for output in self.upstream.values():
            for observation in output.observations:
                if observation.asset_type.value == "ip":
                    ips.add(observation.value)
            for asset in output.assets:
                if asset.asset_type.value == "ip":
                    ips.add(asset.value)
            for record in output.dns_records:
                if record.record_type in ("A", "AAAA"):
                    ips.add(record.value)
        return sorted(i for i in ips if i)

    def known_urls(self, *, in_scope_only: bool = True) -> list[str]:
        urls: set[str] = set()
        for output in self.upstream.values():
            for record in output.urls:
                if in_scope_only and not record.in_scope:
                    continue
                urls.add(record.normalized_url)
            for observation in output.observations:
                if observation.asset_type.value == "url":
                    urls.add(observation.value)
        return sorted(urls)

    def artifacts_of_kind(self, kind: str) -> list[Any]:
        out: list[Any] = []
        for output in self.upstream.values():
            out.extend(a for a in output.artifacts if a.kind.value == kind)
        return out

    def html_bodies(self) -> dict[str, str]:
        """HTML retrieved by the web-surface module, keyed by URL.

        Bodies are passed in memory between modules rather than round-
        tripped through the database, so HTML parsed by four different
        modules is fetched once.
        """
        return dict(self.data_of("web_surface", "bodies", {}) or {})

    def javascript_bodies(self) -> dict[str, str]:
        return dict(self.data_of("javascript", "bodies", {}) or {})

    def response_headers(self) -> dict[str, dict[str, str]]:
        return dict(self.data_of("web_surface", "headers", {}) or {})


class IntelligenceModule(abc.ABC):
    """Base class for every Insyte intelligence module."""

    # -- declaration ------------------------------------------------------

    #: Stable machine id. Also the `scan_modules.module_id` value.
    id: str = ""
    name: str = ""
    description: str = ""
    category: ModuleCategory = ModuleCategory.CORE
    version: str = "1.0.0"

    #: Modes this module can run in. A module absent from the active mode
    #: skips itself with a reason instead of running.
    mode_support: tuple[ScanMode, ...] = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)

    #: Target types this module can act on.
    input_types: tuple[TargetType, ...] = (
        TargetType.DOMAIN,
        TargetType.IPV4,
        TargetType.IPV6,
    )

    #: Module ids that must run first. The orchestrator turns these into
    #: execution waves and runs each wave concurrently.
    dependencies: tuple[str, ...] = ()

    #: Providers this module consults. Used to render "which sources feed
    #: this module" in the UI and to decide whether the module is useful at
    #: all when no credentials are configured.
    providers: tuple[str, ...] = ()

    #: True when the module is useless without at least one configured
    #: credential; it then skips with a clear reason.
    requires_api_key: bool = False

    #: Seconds. Enforced by the orchestrator, not by the module.
    timeout: float = 120.0

    #: Included when the user picks "Recommended" rather than every module.
    recommended: bool = True

    #: Ordering hint within a dependency wave, for stable progress display.
    order: int = 100

    # -- lifecycle --------------------------------------------------------

    def supports_mode(self, mode: ScanMode) -> bool:
        return mode in self.mode_support

    def supports_target(self, target: Target) -> bool:
        return TargetType(target.target_type) in self.input_types

    def skip_reason(self, ctx: ModuleContext) -> str | None:
        """Why this module will not run, in words a user can act on."""
        if not self.supports_mode(ctx.mode):
            other = (
                ScanMode.WEB_SURFACE
                if ctx.mode is ScanMode.PASSIVE
                else ScanMode.PASSIVE
            )
            return f"Not available in {ctx.mode.label} mode - requires {other.label}."
        if not self.supports_target(ctx.target):
            kinds = ", ".join(t.value for t in self.input_types)
            return (
                f"Does not apply to a {ctx.target.target_type.value} target "
                f"(supports: {kinds})."
            )
        if self.requires_api_key:
            from app.providers import get_provider

            configured = [
                pid
                for pid in self.providers
                if (provider := get_provider(pid)) is not None
                and provider.unavailable_reason() is None
            ]
            if not configured:
                names = ", ".join(self.providers) or "its sources"
                return (
                    "No API key configured for any of this module's sources "
                    f"({names}) - add a key under Settings → Credentials to "
                    "enable it."
                )
        missing = [dep for dep in self.dependencies if dep not in ctx.upstream]
        if missing:
            return f"Prerequisite module did not run: {', '.join(missing)}."
        return None

    def run(self, ctx: ModuleContext) -> ModuleOutput:
        """Execute the module with uniform timing, logging and isolation.

        Subclasses implement `execute`. This wrapper guarantees that a
        module which raises still produces a well-formed output, so the
        orchestrator never has to reason about partial results.
        """
        started = time.perf_counter()
        skip = self.skip_reason(ctx)
        if skip is not None:
            ctx.event(self.id, "module_skipped", skip, level="INFO")
            return ModuleOutput(module_id=self.id, success=True, skip_reason=skip)

        ctx.event(self.id, "module_started", f"{self.name} started")
        try:
            output = self.execute(ctx)
        except CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            duration = time.perf_counter() - started
            ctx.log(self.id).exception("module_failed")
            ctx.event(
                self.id,
                "module_failed",
                f"{exc.__class__.__name__}: {str(exc)[:200]}",
                level="ERROR",
            )
            return ModuleOutput(
                module_id=self.id,
                success=False,
                errors=[f"{exc.__class__.__name__}: {str(exc)[:300]}"],
                metrics={"duration": round(duration, 3)},
            )

        output.module_id = self.id
        duration = time.perf_counter() - started
        output.metrics.setdefault("duration", round(duration, 3))
        ctx.event(
            self.id,
            "module_completed",
            f"{self.name} produced {output.record_count} records",
            records=output.record_count,
            findings=len(output.findings),
            duration=round(duration, 3),
        )
        return output

    @abc.abstractmethod
    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        """Do the collection. May raise; `run` handles it."""
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------

    def gather(
        self,
        ctx: ModuleContext,
        intent: str,
        *,
        limit: int | None = None,
        value: str | None = None,
    ) -> tuple[list[Any], list[ProviderStatus]]:
        """Query every provider this module declares that answers `intent`.

        Each provider's failure is isolated by `Provider.collect`, so this
        returns whatever succeeded plus a status row for each attempt -
        which is what lets the UI say "VirusTotal: unavailable, scan
        continued" instead of dropping the source silently.
        """
        from app.providers import ProviderQuery, get_provider

        observations: list[Any] = []
        statuses: list[ProviderStatus] = []
        query_limit = limit or ctx.limits.max_subdomains

        for provider_id in self.providers:
            ctx.check_cancelled()
            provider = get_provider(provider_id)
            if provider is None or not provider.supports(intent):
                continue
            result = provider.collect(
                ProviderQuery(
                    target=ctx.target, intent=intent, limit=query_limit, value=value
                )
            )
            observations.extend(result.observations)
            if result.status is not None:
                statuses.append(result.status)
            if result.status and not result.status.available:
                ctx.event(
                    self.id,
                    "provider_unavailable",
                    f"{provider.name}: {result.status.reason or 'unavailable'}",
                    provider=provider.id,
                )
            else:
                ctx.event(
                    self.id,
                    "provider_completed",
                    f"{provider.name} returned {result.count} observations",
                    provider=provider.id,
                    count=result.count,
                )
        return observations, statuses

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "category_label": self.category.label,
            "version": self.version,
            "mode_support": [m.value for m in self.mode_support],
            "input_types": [t.value for t in self.input_types],
            "dependencies": list(self.dependencies),
            "providers": list(self.providers),
            "requires_api_key": self.requires_api_key,
            "timeout": self.timeout,
            "recommended": self.recommended,
        }


def dedupe_observations(observations: Iterable[Any]) -> Iterator[Any]:
    """Collapse observations that assert the same value from the same source.

    Cross-source merging is the correlation stage's job; this only removes
    the trivial case of a provider reporting the same host twice.
    """
    seen: set[tuple[str, str, str]] = set()
    for observation in observations:
        key = (observation.source, observation.asset_type.value, observation.hash)
        if key in seen:
            continue
        seen.add(key)
        yield observation
