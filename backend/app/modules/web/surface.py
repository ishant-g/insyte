"""Web Surface Collection - the core HTTP retrieval module.

Everything else in `modules/web/` reads what this module fetched rather
than making its own requests, so there is exactly one place that decides
what pages get retrieved, and exactly one place enforces the page/JS/CSS
budgets from the brief (max pages, max JS files, max sitemap depth,
max URLs). Bodies are handed to downstream modules in memory via
`ctx.data_of("web_surface", ...)`; only metadata is persisted as `Artifact`
rows - see `models.intelligence.Artifact` for why.

This module now runs in **both** modes, at two different footprints:

* **Passive mode** - exactly one GET per resource, no recursion and no
  crawl: the homepage, `robots.txt`, the top-level `sitemap.xml` (its
  `<loc>` entries are read as evidence, not followed), and the
  `.well-known`/well-known-path set. This is what "Passive Intelligence"
  means since the mode's own redefinition: a single unauthenticated GET
  per well-known resource is in scope, an open-ended crawl is not.
* **Web Surface Collection mode** - the above, plus same-origin pages
  linked from the homepage (up to `max_pages`) and the JavaScript/CSS they
  reference (up to their own budgets), and sitemap recursion up to
  `max_sitemap_depth`.

Every fetch goes through `ctx.http` - the SSRF-guarded, byte-capped
client - so nothing here can reach a private address, use a POST, or
download an unbounded body, in either mode.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.core.canonical import canonical_url
from app.core.contracts import ArtifactRecord, ModuleOutput, UrlRecord
from app.core.net import HttpError, SSRFBlocked
from app.core.target import TargetType
from app.models.enums import ArtifactKind, ModuleCategory, ScanMode, UrlClassification
from app.modules.base import IntelligenceModule, ModuleContext

WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/webfinger",
    "/manifest.json",
    "/site.webmanifest",
    "/browserconfig.xml",
    "/ads.txt",
    "/app-ads.txt",
    "/humans.txt",
    "/favicon.ico",
)

_KIND_BY_EXTENSION = {
    "xml": ArtifactKind.XML,
    "json": ArtifactKind.JSON,
    "yaml": ArtifactKind.YAML,
    "yml": ArtifactKind.YAML,
    "txt": ArtifactKind.TEXT,
    "js": ArtifactKind.JAVASCRIPT,
    "css": ArtifactKind.STYLESHEET,
    "map": ArtifactKind.SOURCE_MAP,
}


class WebSurfaceModule(IntelligenceModule):
    id = "web_surface"
    name = "Homepage & Well-Known Resources"
    description = (
        "Read-only HTTP GET of the homepage, robots.txt, sitemap.xml and "
        "well-known resources - one request per resource, no crawling. Feeds "
        "technology fingerprinting, security headers and WAF/CDN detection "
        "in both modes; Web Surface Collection additionally crawls linked "
        "pages and their JavaScript/CSS."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    timeout = 120.0
    order = 60

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        origin = ctx.target.http_origin

        bodies: dict[str, str] = {}
        headers: dict[str, dict[str, str]] = {}
        js_links: set[str] = set()
        css_links: set[str] = set()
        page_links: set[str] = set()
        well_known_found: dict[str, bool] = {}

        # 1. Homepage - try https first, then fall back to http.
        home = self._fetch(ctx, output, origin + "/", UrlClassification.PAGE, collect_error=True)
        homepage_error = output.errors[-1] if output.errors else None
        if home is None and origin.startswith("https://"):
            origin = "http://" + origin[len("https://") :]
            home = self._fetch(ctx, output, origin + "/", UrlClassification.PAGE, collect_error=True)
            if home is None and output.errors:
                homepage_error = output.errors[-1]

        if home is not None:
            bodies[home["url"]] = home["text"]
            headers[home["url"]] = home["headers"]
            js_links, css_links, page_links = self._extract_links(
                home["text"], home["url"]
            )
        elif homepage_error:
            # The homepage never loaded; keep the reason so the terminal
            # state below can report it instead of an empty success.
            output.data["homepage_error"] = homepage_error

        # 2. Well-known resources.
        for path in WELL_KNOWN_PATHS:
            ctx.check_cancelled()
            fetched = self._fetch(
                ctx, output, urljoin(origin, path), UrlClassification.WELL_KNOWN
            )
            well_known_found[path] = fetched is not None
            if fetched is not None:
                bodies[fetched["url"]] = fetched["text"]

        # 3. Sitemap. Passive mode reads only the top-level document - its
        # <loc> entries become evidence, not fetch targets - so a chain of
        # nested sitemap indexes never turns one GET into a crawl.
        sitemap_depth = ctx.limits.max_sitemap_depth if ctx.mode is ScanMode.WEB_SURFACE else 1
        sitemap_urls = self._collect_sitemaps(ctx, output, origin, bodies, max_depth=sitemap_depth)

        page_budget = ctx.limits.max_pages
        js_bodies: dict[str, str] = {}

        if ctx.mode is ScanMode.WEB_SURFACE:
            # 4. Same-origin pages linked from the homepage - Web Surface
            # Collection only; Passive mode stops at the resources already
            # fetched above.
            target_host = ctx.target.value
            visited = set(bodies.keys())
            for link in sorted(page_links | set(sitemap_urls)):
                if len(visited) >= page_budget:
                    break
                ctx.check_cancelled()
                canon = canonical_url(link, target_host=target_host)
                if canon is None or not canon.in_scope or canon.normalized in visited:
                    continue
                if canon.classification not in (UrlClassification.PAGE, UrlClassification.UNKNOWN):
                    continue
                fetched = self._fetch(ctx, output, canon.normalized, UrlClassification.PAGE)
                if fetched is None:
                    continue
                visited.add(canon.normalized)
                bodies[fetched["url"]] = fetched["text"]
                headers[fetched["url"]] = fetched["headers"]
                more_js, more_css, _ = self._extract_links(fetched["text"], fetched["url"])
                js_links |= more_js
                css_links |= more_css

            # 5. JavaScript files, up to budget. CSS is recorded as URLs but
            # not deeply analysed - that engine lives in
            # modules/web/javascript.py, itself Web-Surface-only for the
            # same crawl-depth reason.
            js_budget = ctx.limits.max_js_files
            for link in sorted(js_links)[:js_budget]:
                ctx.check_cancelled()
                fetched = self._fetch(
                    ctx, output, link, UrlClassification.JAVASCRIPT, accept="*/*"
                )
                if fetched is not None:
                    js_bodies[fetched["url"]] = fetched["text"]

            for link in sorted(css_links)[: max(20, page_budget)]:
                ctx.check_cancelled()
                self._fetch(ctx, output, link, UrlClassification.STYLESHEET, accept="text/css,*/*")

        output.data["bodies"] = bodies
        output.data["headers"] = headers
        output.data["js_bodies"] = js_bodies
        output.data["well_known"] = well_known_found
        output.data["sitemap_urls"] = sorted(sitemap_urls)[:500]
        output.data["origin"] = origin
        output.data["pages_fetched"] = len(bodies)
        output.data["js_fetched"] = len(js_bodies)
        output.metrics["urls_fetched"] = len(output.urls)
        output.metrics["artifacts_fetched"] = len(output.artifacts)

        # Zero pages fetched means the target never responded - report a
        # failure with the reason, never a clean-looking empty success.
        if not bodies:
            reason = output.data.get("homepage_error") or "no pages could be fetched"
            output.errors.append(
                f"Web fetch produced no page content ({reason}); "
                "downstream web analysis modules were skipped."
            )
            output.success = False
        return output

    # -- fetching ----------------------------------------------------------

    def _fetch(
        self,
        ctx: ModuleContext,
        output: ModuleOutput,
        url: str,
        classification: UrlClassification,
        *,
        accept: str | None = None,
        collect_error: bool = False,
    ) -> dict | None:
        if len(output.urls) >= ctx.limits.max_urls:
            return None
        try:
            response = ctx.http.get(url, accept=accept)
        except SSRFBlocked as exc:
            ctx.event(self.id, "collection_blocked", f"{url}: {exc.reason}", level="WARNING")
            if collect_error:
                output.errors.append(f"Homepage fetch blocked: {url}: {exc.reason}")
            return None
        except HttpError as exc:
            ctx.event(self.id, "collection_failed", f"{url}: {exc}", level="INFO")
            if collect_error:
                output.errors.append(f"Homepage fetch failed: {url}: {exc}")
            return None

        canon = canonical_url(response.final_url or url, target_host=ctx.target.value)
        normalized = canon.normalized if canon else url
        extension = canon.extension if canon else None

        output.urls.append(
            UrlRecord(
                url=url,
                normalized_url=normalized,
                host=canon.host if canon else urlsplit(url).hostname or "",
                path=canon.path if canon else "/",
                scheme=canon.scheme if canon else "https",
                classification=canon.classification if canon else classification,
                extension=extension,
                query_keys=list(canon.query_keys) if canon else [],
                status_code=response.status_code,
                content_type=response.content_type,
                retrieved=True,
                in_scope=canon.in_scope if canon else True,
                confidence=95,
                sources=["web_surface"],
                evidence={"remote_address": response.remote_address},
            )
        )

        kind = _KIND_BY_EXTENSION.get(extension or "", ArtifactKind.OTHER)
        if classification is UrlClassification.PAGE and kind is ArtifactKind.OTHER:
            kind = ArtifactKind.HTML
        elif "robots.txt" in url:
            kind = ArtifactKind.ROBOTS
        elif "sitemap" in url:
            kind = ArtifactKind.SITEMAP
        elif "manifest" in url:
            kind = ArtifactKind.MANIFEST
        elif "/.well-known/" in url:
            kind = ArtifactKind.WELL_KNOWN

        output.artifacts.append(
            ArtifactRecord(
                url=url,
                kind=kind,
                status_code=response.status_code,
                content_type=response.content_type,
                content_sha256=response.sha256,
                size=response.size,
                truncated=response.truncated,
                headers=dict(list(response.headers.items())[:40]),
                redirect_chain=response.redirect_chain,
                remote_address=response.remote_address,
                fetched_at=response.fetched_at,
            )
        )

        if not response.ok:
            return None

        return {
            "url": response.final_url or url,
            "text": response.text,
            "headers": response.headers,
            "status": response.status_code,
        }

    # -- parsing -------------------------------------------------------

    def _extract_links(
        self, html: str, base_url: str
    ) -> tuple[set[str], set[str], set[str]]:
        js_links: set[str] = set()
        css_links: set[str] = set()
        page_links: set[str] = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:  # noqa: BLE001 - malformed HTML is not fatal
            return js_links, css_links, page_links

        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                resolved = urljoin(base_url, src)
                if resolved.startswith(("http://", "https://")):
                    js_links.add(resolved)

        for tag in soup.find_all("link"):
            rel = " ".join(tag.get("rel") or []).lower()
            href = tag.get("href")
            if not href:
                continue
            resolved = urljoin(base_url, href)
            if not resolved.startswith(("http://", "https://")):
                continue
            if "stylesheet" in rel:
                css_links.add(resolved)
            elif "manifest" in rel:
                page_links.add(resolved)

        for tag in soup.find_all("a"):
            href = tag.get("href")
            if not href:
                continue
            resolved = urljoin(base_url, href)
            if resolved.startswith(("http://", "https://")):
                page_links.add(resolved.split("#", 1)[0])

        return js_links, css_links, page_links

    def _collect_sitemaps(
        self,
        ctx: ModuleContext,
        output: ModuleOutput,
        origin: str,
        bodies: dict[str, str],
        *,
        max_depth: int,
    ) -> set[str]:
        urls: set[str] = set()
        queue = [urljoin(origin, "/sitemap.xml")]

        robots_body = bodies.get(urljoin(origin, "/robots.txt"))
        if robots_body:
            for line in robots_body.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    queue.append(line.split(":", 1)[1].strip())

        seen_sitemaps: set[str] = set()
        depth = 0
        while queue and depth < max_depth:
            ctx.check_cancelled()
            depth += 1
            next_queue: list[str] = []
            for sitemap_url in queue:
                if sitemap_url in seen_sitemaps or len(urls) >= ctx.limits.max_sitemap_urls:
                    continue
                seen_sitemaps.add(sitemap_url)
                fetched = self._fetch(
                    ctx, output, sitemap_url, UrlClassification.FEED, accept="application/xml,text/xml"
                )
                if fetched is None:
                    continue
                bodies[fetched["url"]] = fetched["text"]
                try:
                    soup = BeautifulSoup(fetched["text"], "xml")
                except Exception:  # noqa: BLE001
                    continue
                for loc in soup.find_all("loc"):
                    value = (loc.text or "").strip()
                    if not value:
                        continue
                    if value.endswith(".xml") and "sitemap" in value.lower():
                        next_queue.append(value)
                    else:
                        urls.add(value)
                        if len(urls) >= ctx.limits.max_sitemap_urls:
                            break
            queue = next_queue
        return urls
