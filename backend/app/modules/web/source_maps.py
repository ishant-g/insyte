"""Source Map Intelligence.

A JavaScript bundle's source map, if publicly retrievable, reverses the
minification the bundle was shipped with: original file paths, folder
structure, `node_modules` package names, and - when `sourcesContent` is
embedded - the original, unminified source itself. That is a meaningfully
larger disclosure than the bundle alone, which is why it gets its own
module rather than a few extra lines in `javascript_intelligence`.

Retrieval only happens for a source map JavaScript Intelligence already
found a reference to; nothing here constructs a `.map` path that was not
already declared by a `//# sourceMappingURL=` comment. The map is only ever
parsed as JSON - a source map is data, and this module never evaluates or
executes anything it recovers, including the original source text.

Secret handling follows the same rule as `javascript_intelligence`: a full
credential recovered from `sourcesContent` never leaves this module.
`services/artifacts/masking.py` is applied before anything secret-shaped is
recorded.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from app.core.contracts import ExposureRecord, FindingRecord, ModuleOutput
from app.core.target import TargetType, is_subdomain_of, normalize_hostname
from app.core.tld_list import has_known_tld
from app.models.enums import (
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext
from app.services.artifacts.masking import find_secrets

_NODE_MODULES_RE = re.compile(r"node_modules/(@[\w.\-]+/[\w.\-]+|[\w.\-]+)")
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I
)
_ENDPOINT_RE = re.compile(
    r"""["'`](/(?:api|v[0-9]+|graphql|rest|rpc|oauth|auth|admin)[a-zA-Z0-9_\-/{}.]*)["'`]""",
    re.I,
)
_INTERNAL_PATH_HINTS = ("internal", "staging", "corp", "vpn", ".local", "intranet", "private")

#: Source maps are large by nature (they embed original source); this caps
#: how much of `sourcesContent` is scanned for endpoints/secrets so a
#: pathological map cannot turn one fetch into a worker stall.
_SOURCES_CONTENT_SCAN_CAP = 500_000


def _sld_looks_real(hostname: str) -> bool:
    """Same false-positive guard `javascript.py` uses for extracted domains.

    A minified property-access chain (`a.top`) reads as a two-label
    hostname whose second-level label is one or two characters; a real
    registrable domain's SLD is almost always three or more.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    return len(labels[-2]) >= 3


class SourceMapIntelligenceModule(IntelligenceModule):
    id = "source_map_intelligence"
    name = "Source Map Intelligence"
    description = (
        "Retrieves and parses every source map JavaScript Intelligence "
        "found a reference to, recovering original file paths, package "
        "names, internal-looking hostnames and endpoint strings without "
        "ever executing the recovered source."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.WEB_SURFACE,)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("javascript_intelligence",)
    timeout = 60.0
    order = 78

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        js_output = ctx.output_of("javascript_intelligence")
        if js_output is None:
            output.data["summary"] = {"referenced": 0, "retrieved": 0, "internal_paths_recovered": 0}
            return output

        target_registrable = ctx.target.registrable or ctx.target.value
        referenced = 0
        retrieved = 0
        internal_paths_total = 0

        for record in js_output.javascript:
            if not record.has_source_map or not record.source_map_url:
                continue
            referenced += 1
            map_url = record.source_map_url
            parts = urlsplit(map_url)

            response = (
                ctx.http.try_get(map_url, accept="application/json,*/*")
                if ctx.mode is ScanMode.WEB_SURFACE
                else None
            )
            if response is None or not response.ok:
                output.exposures.append(
                    ExposureRecord(
                        exposure_type="source_map",
                        url=map_url,
                        observation_class="indexed",
                        host=parts.hostname,
                        path=parts.path,
                        severity=Severity.INFORMATIONAL,
                        confidence=50,
                        retrievable=False,
                        sources=["javascript_intelligence"],
                        evidence={"referenced_in": record.url},
                    )
                )
                continue

            content_type = response.content_type
            if "json" not in content_type and not map_url.endswith(".map"):
                continue
            try:
                payload = json.loads(response.text)
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue

            sources = payload.get("sources")
            sources = [str(s) for s in sources] if isinstance(sources, list) else []
            sources_content = payload.get("sourcesContent")
            retrieved += 1

            package_names = sorted(
                {m.group(1) for s in sources for m in [_NODE_MODULES_RE.search(s)] if m}
            )[:50]

            internal_hits: set[str] = set()
            for source_path in sources:
                lowered = source_path.lower()
                for host_match in _HOSTNAME_RE.finditer(source_path):
                    host = normalize_hostname(host_match.group(0)) or ""
                    if (
                        host
                        and has_known_tld(host)
                        and _sld_looks_real(host)
                        and not is_subdomain_of(host, target_registrable)
                    ):
                        internal_hits.add(host)
                # A vendored library's own folder-naming convention (rxjs and
                # much of the TypeScript ecosystem ship a "src/internal/"
                # tree as their public-API boundary) is not evidence about
                # the target's infrastructure - only first-party paths count.
                if "node_modules/" in lowered:
                    continue
                if any(hint in lowered for hint in _INTERNAL_PATH_HINTS):
                    internal_hits.add(source_path[:200])
            internal_hits_list = sorted(internal_hits)[:50]
            internal_paths_total += len(internal_hits_list)

            endpoint_hits: list[str] = []
            secrets_found: list[dict] = []
            if isinstance(sources_content, list):
                combined = "\n".join(
                    c for c in sources_content if isinstance(c, str)
                )[:_SOURCES_CONTENT_SCAN_CAP]
                if combined:
                    endpoint_hits = sorted({m.group(1) for m in _ENDPOINT_RE.finditer(combined)})[:50]
                    secrets_found = find_secrets(combined, source=map_url)

            record.source_map_retrieved = True
            record.source_map_detail = {
                "sources_count": len(sources),
                "package_names": package_names,
                "internal_paths": internal_hits_list,
                "endpoints": endpoint_hits,
                "secret_indicators": secrets_found,
            }

            if secrets_found:
                severity = (
                    Severity.HIGH
                    if any(s.get("severity") == "high" for s in secrets_found)
                    else Severity.MEDIUM
                )
            elif internal_hits_list:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            output.exposures.append(
                ExposureRecord(
                    exposure_type="source_map",
                    url=map_url,
                    observation_class="directly_retrievable",
                    host=parts.hostname,
                    path=parts.path,
                    severity=severity,
                    confidence=85,
                    retrievable=True,
                    sources=["source_map_intelligence"],
                    evidence={"sources_count": len(sources), "referenced_in": record.url},
                )
            )

            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.SOURCE_MAP_EXPOSURE,
                    severity=Severity.MEDIUM if internal_hits_list else Severity.LOW,
                    title="Source map publicly retrievable",
                    description=(
                        f"{map_url} was retrieved directly and reveals "
                        f"{len(sources)} original source file path(s)"
                        + (
                            ", including internal-looking paths or hostnames."
                            if internal_hits_list
                            else "."
                        )
                    ),
                    recommendation=(
                        "Remove source maps from production deployments, or "
                        "restrict access to them to authenticated users only."
                    ),
                    location=map_url,
                    confidence=88,
                    exposure=ExposureLevel.DIRECT,
                    sources=["source_map_intelligence"],
                    evidence={
                        "internal_paths": internal_hits_list[:10],
                        "package_names": package_names[:10],
                    },
                )
            )

            for secret in secrets_found:
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.SECRET_INDICATOR,
                        severity=Severity.HIGH if secret.get("severity") == "high" else Severity.MEDIUM,
                        title=f"Potential {secret.get('type', 'secret')} in recovered source",
                        description=(
                            f"A value matching the shape of a {secret.get('type', 'secret')} "
                            f"was found in original source recovered from {map_url}. "
                            "The value is masked; Insyte does not validate or use "
                            "discovered credentials."
                        ),
                        recommendation=(
                            "Rotate the credential if it is real, and ensure source "
                            "maps with embedded source content are not deployed to "
                            "production."
                        ),
                        location=map_url,
                        confidence=secret.get("confidence", 60),
                        exposure=ExposureLevel.DIRECT,
                        sources=["source_map_intelligence"],
                        evidence={"masked_value": secret.get("masked"), "pattern": secret.get("type")},
                    )
                )

        output.data["summary"] = {
            "referenced": referenced,
            "retrieved": retrieved,
            "internal_paths_recovered": internal_paths_total,
        }
        return output
