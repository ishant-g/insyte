"""API Discovery Engine.

Classifies the URL inventory and JavaScript-discovered endpoints into
API-shaped resources - REST, GraphQL, WebSocket, OAuth, and API
documentation - from path shape alone. Nothing here calls an endpoint to
see whether it responds; `ApiEndpointRecord` has no field that could assert
"this API is live" because Insyte discovers surface, it does not probe it.

The one exception where an actual GET happens is a documentation file
(`swagger.json`, `openapi.json`, ...) that the URL inventory already
classified as such: reading a publicly linked JSON document and parsing its
declared paths is the same "read-only GET of a linked resource" Web Surface
Collection itself does, and it is the only way to turn "there is a docs
link" into the endpoint list the docs actually declare. The declared
methods on those endpoints come from the document, not from a probe, so
recording them does not contradict "never validated".
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from app.core.contracts import ApiEndpointRecord, FindingRecord, ModuleOutput
from app.core.target import TargetType, is_subdomain_of
from app.models.enums import (
    ApiType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: (needle, ApiType). Order matters - more specific shapes are tried first
#: so `/api/oauth/token` classifies as OAuth rather than generic REST.
_API_TYPE_HINTS: tuple[tuple[str, ApiType], ...] = (
    ("/graphiql", ApiType.GRAPHQL),
    ("/graphql", ApiType.GRAPHQL),
    ("/socket.io", ApiType.WEBSOCKET),
    ("/swagger.json", ApiType.SWAGGER),
    ("/swagger.yaml", ApiType.SWAGGER),
    ("/swagger", ApiType.SWAGGER),
    ("/openapi.json", ApiType.OPENAPI),
    ("/openapi.yaml", ApiType.OPENAPI),
    ("/openapi", ApiType.OPENAPI),
    ("/api-docs", ApiType.DOCUMENTATION),
    ("/redoc", ApiType.DOCUMENTATION),
    ("/jwks.json", ApiType.OAUTH),
    ("/oauth2", ApiType.OAUTH),
    ("/oauth", ApiType.OAUTH),
    ("/authorize", ApiType.OAUTH),
    ("/token", ApiType.OAUTH),
    ("/api/v2/", ApiType.REST),
    ("/api/v1/", ApiType.REST),
    ("/api/", ApiType.REST),
)

_DOC_TYPES = (ApiType.SWAGGER, ApiType.OPENAPI, ApiType.DOCUMENTATION)

#: A fetched documentation file is only trusted this many times per scan -
#: a page linking to the same doc from every template must not turn into
#: repeated GETs of the same resource.
_MAX_DOC_FETCHES = 5


def _classify(path: str) -> ApiType:
    lowered = path.lower()
    for needle, api_type in _API_TYPE_HINTS:
        if needle in lowered:
            return api_type
    return ApiType.UNKNOWN


def _auth_hint(api_type: ApiType, path: str) -> str | None:
    if api_type is ApiType.OAUTH:
        return "oauth2"
    lowered = path.lower()
    if "key" in lowered:
        return "api_key"
    if "bearer" in lowered:
        return "bearer_token"
    return None


class ApiDiscoveryModule(IntelligenceModule):
    id = "api_discovery"
    name = "API Discovery Engine"
    description = (
        "Classifies the URL inventory and JavaScript-discovered endpoints "
        "into REST, GraphQL, WebSocket, OAuth and documentation resources "
        "by path shape, and reads any publicly linked API documentation "
        "file for the endpoints it declares."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.WEB_SURFACE,)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("url_collection", "javascript_intelligence")
    timeout = 45.0
    order = 77

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        target_registrable = ctx.target.registrable or ctx.target.value
        url_output = ctx.output_of("url_collection")
        js_output = ctx.output_of("javascript_intelligence")

        found: dict[str, ApiEndpointRecord] = {}

        def consider(
            url: str,
            host: str | None,
            path: str,
            source: str,
            confidence: int,
            *,
            method: str | None = None,
            source_artifact: str | None = None,
            extra_evidence: dict | None = None,
        ) -> ApiEndpointRecord | None:
            api_type = _classify(path)
            if api_type is ApiType.UNKNOWN:
                return None
            normalized = url.split("?", 1)[0].rstrip("/") or url
            existing = found.get(normalized)
            if existing is not None:
                if source not in existing.sources:
                    existing.sources.append(source)
                existing.confidence = min(100, existing.confidence + 5)
                if method and not existing.method:
                    existing.method = method
                return existing
            record = ApiEndpointRecord(
                url=url,
                normalized_url=normalized,
                host=host or urlsplit(url).hostname or "",
                path=path,
                api_type=api_type,
                method=method,
                auth_hint=_auth_hint(api_type, path),
                source_artifact=source_artifact,
                in_scope=is_subdomain_of(host, target_registrable) if host else True,
                confidence=confidence,
                sources=[source],
                evidence=extra_evidence or {},
            )
            found[normalized] = record
            return record

        if url_output is not None:
            for record in url_output.urls:
                consider(record.url, record.host, record.path, "url_collection", record.confidence)

        if js_output is not None:
            for api in js_output.api_endpoints:
                consider(
                    api.url, api.host, api.path, "javascript",
                    api.confidence, source_artifact=api.source_artifact,
                    extra_evidence=dict(api.evidence),
                )

        doc_findings = 0
        if ctx.mode is ScanMode.WEB_SURFACE:
            doc_candidates = [r for r in found.values() if r.api_type in _DOC_TYPES]
            for doc_endpoint in doc_candidates[:_MAX_DOC_FETCHES]:
                ctx.check_cancelled()
                response = ctx.http.try_get(doc_endpoint.url, accept="application/json,*/*")
                if response is None or not response.ok:
                    continue
                doc_endpoint.confidence = min(100, doc_endpoint.confidence + 10)
                doc_endpoint.evidence = {**doc_endpoint.evidence, "status_code": response.status_code}
                doc_findings += 1
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.API_DOCUMENTATION_EXPOSURE,
                        severity=Severity.LOW,
                        title="Publicly accessible API documentation",
                        description=(
                            f"{doc_endpoint.url} is a publicly retrievable API "
                            "documentation file, which discloses the API's "
                            "endpoint surface, parameters and (if present) "
                            "authentication scheme."
                        ),
                        recommendation=(
                            "Confirm this level of API disclosure is intentional; "
                            "restrict access to internal-only documentation."
                        ),
                        location=doc_endpoint.url,
                        confidence=80,
                        exposure=ExposureLevel.DIRECT,
                        sources=["api_discovery"],
                        evidence={"api_type": doc_endpoint.api_type.value},
                    )
                )

                is_json = "json" in (response.content_type or "") or doc_endpoint.url.endswith(".json")
                if not is_json:
                    continue
                try:
                    payload = json.loads(response.text)
                except ValueError:
                    continue
                if not isinstance(payload, dict):
                    continue
                paths = payload.get("paths")
                if not isinstance(paths, dict):
                    continue
                base_path = str(payload.get("basePath") or "")
                for path_key, operations in paths.items():
                    if not isinstance(operations, dict):
                        continue
                    full_path = f"{base_path.rstrip('/')}{path_key}" if base_path else path_key
                    resolved_url = urljoin(doc_endpoint.url, full_path)
                    resolved_host = urlsplit(resolved_url).hostname or doc_endpoint.host
                    for method_name in operations:
                        if method_name.upper() not in (
                            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
                        ):
                            continue
                        consider(
                            resolved_url, resolved_host, full_path,
                            "api_documentation", 75,
                            method=method_name.upper(),
                            source_artifact=doc_endpoint.url,
                            extra_evidence={"declared_in": doc_endpoint.url},
                        )

        output.api_endpoints = list(found.values())[: ctx.limits.max_urls]

        by_type: dict[str, int] = {}
        for record in output.api_endpoints:
            by_type[record.api_type.value] = by_type.get(record.api_type.value, 0) + 1

        output.data["summary"] = {
            "total_endpoints": len(output.api_endpoints),
            "by_api_type": by_type,
            "documentation_files_retrieved": doc_findings,
        }
        return output
