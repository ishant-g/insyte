"""URL Intelligence - the unified URL database.

Web Surface Collection, JavaScript Intelligence and the sitemap/robots
parsers each discover URLs as a side effect of their own job, in their own
shape. This module is the one place that pulls every one of those trails
together, canonicalises each reference through `canonical_url()`, and
produces the single deduplicated inventory the rest of the Web Surface
pipeline (API discovery, indexed exposure, document intelligence) reads
from instead of re-parsing HTML and JavaScript themselves.

A URL here is either "retrieved" - Web Surface Collection actually issued a
GET for it - or merely "referenced": seen in an href, a script src, a CSS
`url()`, or a JavaScript-extracted endpoint, but never fetched. That
distinction is preserved on every record rather than collapsed, because a
referenced-but-unfetched admin panel is a different kind of finding than
one Insyte confirmed still exists.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from app.core.canonical import CanonicalUrl, canonical_url
from app.core.contracts import ModuleOutput, UrlRecord
from app.core.target import TargetType
from app.models.enums import ModuleCategory, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext

_CSS_URL_RE = re.compile(r"""url\(['"]?([^'")]+)['"]?\)""")


class UrlCollectionModule(IntelligenceModule):
    id = "url_collection"
    name = "URL Intelligence"
    description = (
        "Builds the unified, deduplicated URL inventory from every page, "
        "script, stylesheet, JavaScript-discovered endpoint, and "
        "robots/sitemap entry Web Surface Collection encountered - the "
        "database every other Web Surface module reads from."
    )
    category = ModuleCategory.WEB_SURFACE
    mode_support = (ScanMode.WEB_SURFACE,)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("web_surface", "javascript_intelligence")
    timeout = 60.0
    order = 76

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        target_host = ctx.target.value

        surface_output = ctx.output_of("web_surface")
        js_output = ctx.output_of("javascript_intelligence")
        bodies = ctx.data_of("web_surface", "bodies", {}) or {}

        surface_by_url: dict[str, UrlRecord] = {}
        if surface_output is not None:
            for record in surface_output.urls:
                surface_by_url[record.normalized_url] = record

        canonical_map: dict[str, CanonicalUrl] = {}

        def add(raw: str | None, base: str | None) -> None:
            if not raw:
                return
            canon = canonical_url(raw, base=base, target_host=target_host)
            if canon is None:
                return
            canonical_map.setdefault(canon.hash, canon)

        for page_url, html in bodies.items():
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:  # noqa: BLE001 - malformed HTML is not fatal
                continue
            for tag in soup.find_all("a"):
                add(tag.get("href"), page_url)
            for tag in soup.find_all("link"):
                add(tag.get("href"), page_url)
            for tag in soup.find_all("script"):
                add(tag.get("src"), page_url)
            # Web Surface Collection does not keep standalone .css bodies
            # in memory, so CSS url() extraction only sees what survives in
            # the HTML itself: inline style attributes and <style> blocks.
            for tag in soup.find_all(style=True):
                for match in _CSS_URL_RE.finditer(tag["style"] or ""):
                    add(match.group(1), page_url)
            for tag in soup.find_all("style"):
                for match in _CSS_URL_RE.finditer(tag.get_text() or ""):
                    add(match.group(1), page_url)

        if js_output is not None:
            for js_record in js_output.javascript:
                for endpoint in js_record.endpoints:
                    add(endpoint, js_record.url)
            for api in js_output.api_endpoints:
                add(api.url, None)

        if surface_output is not None:
            for record in surface_output.urls:
                add(record.url, None)

        budget = ctx.limits.max_urls
        for canon in sorted(canonical_map.values(), key=lambda c: c.normalized):
            if len(output.urls) >= budget:
                break
            existing = surface_by_url.get(canon.normalized)
            retrieved = existing is not None
            output.urls.append(
                UrlRecord(
                    url=canon.original,
                    normalized_url=canon.normalized,
                    host=canon.host,
                    path=canon.path,
                    scheme=canon.scheme,
                    classification=canon.classification,
                    extension=canon.extension,
                    query_keys=list(canon.query_keys),
                    status_code=existing.status_code if existing else None,
                    content_type=existing.content_type if existing else None,
                    retrieved=retrieved,
                    in_scope=canon.in_scope,
                    confidence=92 if retrieved else 55,
                    sources=["url_collection"],
                )
            )

        by_classification: dict[str, int] = {}
        in_scope_count = 0
        out_of_scope_count = 0
        retrieved_count = 0
        for record in output.urls:
            key = record.classification.value
            by_classification[key] = by_classification.get(key, 0) + 1
            if record.in_scope:
                in_scope_count += 1
            else:
                out_of_scope_count += 1
            if record.retrieved:
                retrieved_count += 1

        output.data["summary"] = {
            "total_urls": len(output.urls),
            "by_classification": by_classification,
            "in_scope": in_scope_count,
            "out_of_scope": out_of_scope_count,
            "retrieved": retrieved_count,
            "referenced_only": len(output.urls) - retrieved_count,
        }
        output.metrics["urls_catalogued"] = len(output.urls)
        return output
