"""Module registry - single source of truth for scan modules.

Every module the platform ships is declared here, once, with the metadata
the orchestrator needs to run it: which mode(s) it supports, what it
depends on, whether it needs a credential, and whether it is part of
"Recommended". Modules are imported lazily inside `_build()` so a broken
optional module (say, one added later that fails to import because a
dependency is missing) cannot take the whole registry down - the same
defensive-import pattern the predecessor's registry used, which the audit
in `docs/AUDIT.md` flagged as worth keeping.

`execution_waves()` turns the dependency graph into a list of waves - each
wave is a set of modules whose dependencies are all satisfied by earlier
waves, so everything in one wave can run concurrently. This is what
section 76 of the brief ("run independent modules concurrently... dependent
modules wait for their prerequisites") means in code.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.core.logging import get_logger
from app.modules.base import IntelligenceModule

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ModuleEntry:
    module_id: str
    factory: Callable[[], IntelligenceModule]


class ModuleRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, ModuleEntry] = {}
        self._instances: dict[str, IntelligenceModule] = {}

    def register(self, module_id: str, factory: Callable[[], IntelligenceModule]) -> None:
        if module_id in self._entries:
            raise ValueError(f"module already registered: {module_id}")
        self._entries[module_id] = ModuleEntry(module_id, factory)

    def get(self, module_id: str) -> IntelligenceModule | None:
        if module_id in self._instances:
            return self._instances[module_id]
        entry = self._entries.get(module_id)
        if entry is None:
            return None
        try:
            instance = entry.factory()
        except Exception:  # noqa: BLE001 - one broken module must not break the rest
            logger.exception("module_load_failed", extra={"module_id": module_id})
            return None
        self._instances[module_id] = instance
        return instance

    def all(self) -> list[IntelligenceModule]:
        modules = []
        for module_id in self._entries:
            instance = self.get(module_id)
            if instance is not None:
                modules.append(instance)
        return modules

    def ids(self) -> list[str]:
        return list(self._entries.keys())

    def execution_waves(self, module_ids: list[str]) -> list[list[IntelligenceModule]]:
        """Topologically order the requested modules into concurrent waves.

        A dependency outside `module_ids` (the user deselected it) is
        treated as already satisfied - the dependent module will simply see
        nothing in `ctx.upstream` for it and degrade via its own
        `skip_reason`/defensive `ctx.data_of` checks rather than the
        orchestrator refusing to run it at all.
        """
        wanted = {mid: self.get(mid) for mid in module_ids if self.get(mid) is not None}
        remaining = dict(wanted)
        waves: list[list[IntelligenceModule]] = []
        placed: set[str] = set()

        guard = 0
        while remaining and guard < 50:
            guard += 1
            ready = [
                module
                for mid, module in remaining.items()
                if all(dep in placed or dep not in wanted for dep in module.dependencies)
            ]
            if not ready:
                # A dependency cycle or a dependency that never resolves -
                # break it by running whatever is left in one final wave
                # rather than dropping modules silently.
                logger.warning(
                    "module_dependency_stall",
                    extra={"remaining": list(remaining.keys())},
                )
                ready = list(remaining.values())
            ready.sort(key=lambda m: m.order)
            waves.append(ready)
            for module in ready:
                placed.add(module.id)
                remaining.pop(module.id, None)
        return waves

    def describe_all(self) -> list[dict]:
        return [m.describe() for m in sorted(self.all(), key=lambda m: m.order)]

    def recommended_ids(self) -> list[str]:
        return [m.id for m in self.all() if m.recommended]


def _build_registry() -> ModuleRegistry:
    registry = ModuleRegistry()

    def add(module_id: str, import_path: str, class_name: str) -> None:
        def factory() -> IntelligenceModule:
            import importlib

            module = importlib.import_module(import_path)
            return getattr(module, class_name)()

        registry.register(module_id, factory)

    # Core (order 10-59)
    add("domain_intelligence", "app.modules.passive.domain", "DomainIntelligenceModule")
    add("dns_intelligence", "app.modules.passive.dns_intel", "DnsIntelligenceModule")
    add("email_security", "app.modules.passive.email_security", "EmailSecurityModule")
    add("certificate_intelligence", "app.modules.passive.certificates", "CertificateIntelligenceModule")
    add("subdomain_intelligence", "app.modules.passive.subdomains", "SubdomainIntelligenceModule")
    add("ip_asn_intelligence", "app.modules.passive.ip_asn", "IpAsnIntelligenceModule")
    add("cloud_detection", "app.modules.passive.cloud_detection", "CloudDetectionModule")
    add(
        "corporate_intelligence",
        "app.modules.passive.corporate_intelligence",
        "CorporateIntelligenceModule",
    )
    add("email_osint", "app.modules.passive.email_osint", "EmailOsintModule")
    add("social_footprint", "app.modules.passive.social_footprint", "SocialFootprintModule")
    add("typosquat", "app.modules.passive.typosquat", "TyposquatModule")
    add("subdomain_takeover", "app.modules.passive.takeover", "TakeoverModule")
    add("threat_intelligence", "app.modules.passive.threat_intel", "ThreatIntelligenceModule")

    # Web surface (order 60-79)
    add("web_surface", "app.modules.web.surface", "WebSurfaceModule")
    add("technology_intelligence", "app.modules.web.technology", "TechnologyIntelligenceModule")
    add("security_headers", "app.modules.web.headers", "SecurityHeaderModule")
    add("waf_cdn_intelligence", "app.modules.web.waf_cdn", "WafCdnIntelligenceModule")
    add("javascript_intelligence", "app.modules.web.javascript", "JavaScriptIntelligenceModule")
    add("url_collection", "app.modules.web.url_collection", "UrlCollectionModule")
    add("api_discovery", "app.modules.web.api_discovery", "ApiDiscoveryModule")
    add("source_map_intelligence", "app.modules.web.source_maps", "SourceMapIntelligenceModule")
    add("document_intelligence", "app.modules.web.documents", "DocumentIntelligenceModule")
    add("favicon_intelligence", "app.modules.web.favicon", "FaviconModule")

    # Exposure (order 80-89)
    add("robots_sitemap_intelligence", "app.modules.web.robots_sitemap", "RobotsSitemapIntelligenceModule")
    add("indexed_exposure", "app.modules.web.indexed_exposure", "IndexedExposureModule")
    add("google_dorking", "app.modules.passive.google_dorking", "GoogleDorkingModule")

    # Historical (order 90-99)
    add("historical_intelligence", "app.modules.historical.timeline", "HistoricalIntelligenceModule")
    add("wayback_diff", "app.modules.passive.wayback_diff", "WaybackDiffModule")

    # External (order 100-109)
    add("github_intelligence", "app.modules.external.github", "GitHubIntelligenceModule")

    logger.info("module_registry_built", extra={"count": len(registry.ids())})
    return registry


default_registry: ModuleRegistry = _build_registry()
