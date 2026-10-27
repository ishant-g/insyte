"""Technology Intelligence.

Multi-signal passive fingerprinting: HTTP headers, HTML meta tags and
markup patterns, cookie names, and JavaScript library signatures. Every
detection carries the signal that produced it and a version only when the
signal actually states one - a `Server: nginx` header proves the product,
not a version; an `X-Powered-By: Express 4.18.2` proves both.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from app.core.contracts import ModuleOutput, TechnologyRecord
from app.core.target import TargetType
from app.models.enums import ModuleCategory, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext

#: (header name, value substring, technology, category, version group)
_HEADER_SIGNATURES: tuple[tuple[str, str, str, str], ...] = (
    ("server", "nginx", "nginx", "web_server"),
    ("server", "apache", "Apache HTTP Server", "web_server"),
    ("server", "microsoft-iis", "Microsoft IIS", "web_server"),
    ("server", "cloudflare", "Cloudflare", "cdn"),
    ("server", "litespeed", "LiteSpeed", "web_server"),
    ("server", "caddy", "Caddy", "web_server"),
    ("server", "gunicorn", "Gunicorn", "application_server"),
    ("server", "envoy", "Envoy", "reverse_proxy"),
    ("server", "openresty", "OpenResty", "web_server"),
    ("server", "kestrel", "Kestrel", "application_server"),
    ("x-powered-by", "express", "Express", "backend_framework"),
    ("x-powered-by", "php", "PHP", "backend_framework"),
    ("x-powered-by", "asp.net", "ASP.NET", "backend_framework"),
    ("x-powered-by", "next.js", "Next.js", "frontend_framework"),
    ("x-generator", "wordpress", "WordPress", "cms"),
    ("x-generator", "drupal", "Drupal", "cms"),
    ("x-drupal-cache", "", "Drupal", "cms"),
    ("x-varnish", "", "Varnish", "cache"),
    ("x-vercel-id", "", "Vercel", "hosting_platform"),
    ("x-nf-request-id", "", "Netlify", "hosting_platform"),
    ("x-amz-cf-id", "", "Amazon CloudFront", "cdn"),
    ("x-amz-request-id", "", "Amazon Web Services", "cloud_platform"),
    ("x-served-by", "fastly", "Fastly", "cdn"),
    ("fly-request-id", "", "Fly.io", "hosting_platform"),
    ("x-shopify-stage", "", "Shopify", "cms"),
    ("x-sourcemap", "", "Source Maps Enabled", "build_tooling"),
    ("cf-ray", "", "Cloudflare", "cdn"),
    ("x-github-request-id", "", "GitHub Pages", "hosting_platform"),
)

_META_GENERATOR_MAP: tuple[tuple[str, str, str], ...] = (
    (r"wordpress\s*([\d.]+)?", "WordPress", "cms"),
    (r"drupal\s*([\d.]+)?", "Drupal", "cms"),
    (r"joomla!?\s*([\d.]+)?", "Joomla", "cms"),
    (r"wix\.com", "Wix", "cms"),
    (r"squarespace", "Squarespace", "cms"),
    (r"shopify", "Shopify", "cms"),
    (r"ghost\s*([\d.]+)?", "Ghost", "cms"),
    (r"typo3\s*([\d.]+)?", "TYPO3", "cms"),
    (r"hugo\s*([\d.]+)?", "Hugo", "static_site_generator"),
    (r"gatsby", "Gatsby", "frontend_framework"),
    (r"docusaurus", "Docusaurus", "static_site_generator"),
)

#: (regex over script/link href or inline content, technology, category, version group index)
_MARKUP_SIGNATURES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"react(?:-dom)?[.\-]([\d.]+)?", re.I), "React", "frontend_framework"),
    (re.compile(r"vue(?:\.runtime)?[.\-]([\d.]+)?\.js", re.I), "Vue.js", "frontend_framework"),
    (re.compile(r"angular[.\-]([\d.]+)?", re.I), "Angular", "frontend_framework"),
    (re.compile(r"jquery[.\-]([\d.]+)?\.js", re.I), "jQuery", "javascript_library"),
    (re.compile(r"jquery-ui[.\-]([\d.]+)?", re.I), "jQuery UI", "javascript_library"),
    (re.compile(r"bootstrap[.\-]([\d.]+)?", re.I), "Bootstrap", "css_framework"),
    (re.compile(r"tailwind", re.I), "Tailwind CSS", "css_framework"),
    (re.compile(r"_next/static"), "Next.js", "frontend_framework"),
    (re.compile(r"__nuxt"), "Nuxt.js", "frontend_framework"),
    (re.compile(r"webpack", re.I), "webpack", "build_tooling"),
    (re.compile(r"vite", re.I), "Vite", "build_tooling"),
    (re.compile(r"htmx[.\-]([\d.]+)?", re.I), "htmx", "javascript_library"),
    (re.compile(r"alpinejs|alpine\.js", re.I), "Alpine.js", "javascript_library"),
    (re.compile(r"d3(?:\.v\d+)?[.\-]([\d.]+)?\.js", re.I), "D3.js", "javascript_library"),
    (re.compile(r"stripe\.com/v3|js\.stripe\.com"), "Stripe", "payment_processor"),
    (re.compile(r"google-analytics\.com|googletagmanager\.com"), "Google Analytics", "analytics"),
    (re.compile(r"cdn\.segment\.com"), "Segment", "analytics"),
    (re.compile(r"connect\.facebook\.net"), "Meta Pixel", "analytics"),
    (re.compile(r"hotjar\.com"), "Hotjar", "analytics"),
    (re.compile(r"intercom\.io|intercomcdn"), "Intercom", "customer_support"),
    (re.compile(r"js\.hs-scripts\.com|hubspot"), "HubSpot", "marketing"),
    (re.compile(r"recaptcha"), "reCAPTCHA", "bot_protection"),
    (re.compile(r"hcaptcha"), "hCaptcha", "bot_protection"),
    (re.compile(r"cloudflare\.com/cdn-cgi|challenges\.cloudflare"), "Cloudflare", "cdn"),
    (re.compile(r"fontawesome"), "Font Awesome", "ui_library"),
    (re.compile(r"swagger-ui"), "Swagger UI", "api_tooling"),
    (re.compile(r"graphql"), "GraphQL", "api_technology"),
    (re.compile(r"firebase(?:app|storage|auth)?\.js|firebaseio\.com"), "Firebase", "cloud_platform"),
    (re.compile(r"amazonaws\.com"), "Amazon Web Services", "cloud_platform"),
    (re.compile(r"auth0\.com"), "Auth0", "authentication"),
    (re.compile(r"okta\.com"), "Okta", "authentication"),
)

_COOKIE_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("wordpress_", "WordPress", "cms"),
    ("wp-settings", "WordPress", "cms"),
    ("csrftoken", "Django", "backend_framework"),
    ("django", "Django", "backend_framework"),
    ("laravel_session", "Laravel", "backend_framework"),
    ("phpsessid", "PHP", "backend_framework"),
    ("jsessionid", "Java (Servlet container)", "backend_framework"),
    ("asp.net_sessionid", "ASP.NET", "backend_framework"),
    ("__cfduid", "Cloudflare", "cdn"),
    ("cf_clearance", "Cloudflare", "cdn"),
    ("_shopify_", "Shopify", "cms"),
    ("sails.sid", "Sails.js", "backend_framework"),
    ("connect.sid", "Express (connect)", "backend_framework"),
    ("koa.sess", "Koa", "backend_framework"),
)


class TechnologyIntelligenceModule(IntelligenceModule):
    id = "technology_intelligence"
    name = "Technology Intelligence"
    description = (
        "Multi-signal passive fingerprinting from HTTP headers, HTML markup, "
        "cookies and referenced JavaScript, each detection carrying its "
        "evidence and only a version the signal actually states."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("web_surface",)
    timeout = 30.0
    order = 70

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        bodies = ctx.html_bodies()
        headers_by_url = ctx.response_headers()

        found: dict[tuple[str, str | None], TechnologyRecord] = {}

        def record(name: str, category: str, *, version: str | None, evidence: str, host: str, confidence: int, source: str):
            key = (name, version)
            existing = found.get(key)
            if existing is not None:
                if source not in existing.sources:
                    existing.sources.append(source)
                existing.confidence = min(100, existing.confidence + 4)
                return
            found[key] = TechnologyRecord(
                name=name,
                category=category,
                version=version,
                version_confidence=90 if version else 0,
                version_source=source if version else None,
                confidence=confidence,
                host=host,
                sources=[source],
                evidence={"signal": evidence},
            )

        for url, response_headers in headers_by_url.items():
            host = _host_of(url)
            lowered = {k.lower(): v for k, v in response_headers.items()}
            for header_name, needle, tech, category in _HEADER_SIGNATURES:
                value = lowered.get(header_name, "")
                if not value:
                    continue
                if needle and needle not in value.lower():
                    continue
                version = _extract_version(value)
                record(
                    tech, category,
                    version=version,
                    evidence=f"{header_name}: {value[:120]}",
                    host=host, confidence=82, source="headers",
                )

        for url, html in bodies.items():
            # `bodies` now also carries robots.txt/sitemap.xml/manifest.json
            # and other well-known non-HTML resources - Passive mode fetches
            # those too (see modules/web/surface.py). Meta-generator/cookie
            # signals only ever mean anything on an actual HTML page, and
            # feeding XML/JSON through an HTML parser just produces a
            # BeautifulSoup warning for no benefit.
            content_type = headers_by_url.get(url, {}).get("content-type", "")
            if content_type and "html" not in content_type.lower():
                continue
            host = _host_of(url)
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:  # noqa: BLE001
                continue

            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                content = str(generator["content"])
                for pattern, tech, category in _META_GENERATOR_MAP:
                    match = re.search(pattern, content, re.I)
                    if match:
                        version = match.group(1) if match.groups() else None
                        record(
                            tech, category, version=version,
                            evidence=f"meta generator: {content[:120]}",
                            host=host, confidence=88, source="html",
                        )

            haystacks = [tag.get("src") or "" for tag in soup.find_all("script")]
            haystacks += [tag.get("href") or "" for tag in soup.find_all("link")]
            haystacks.append(html[:20000])
            for text in haystacks:
                for pattern, tech, category in _MARKUP_SIGNATURES:
                    match = pattern.search(text)
                    if match:
                        version = None
                        if match.groups() and match.group(1):
                            version = match.group(1).strip(".")
                        record(
                            tech, category, version=version,
                            evidence=f"markup pattern in {text[:100]}",
                            host=host, confidence=75, source="html",
                        )

        for url, response_headers in headers_by_url.items():
            set_cookie = response_headers.get("set-cookie", "")
            host = _host_of(url)
            for needle, tech, category in _COOKIE_SIGNATURES:
                if needle in set_cookie.lower():
                    record(
                        tech, category, version=None,
                        evidence=f"Set-Cookie: {needle}",
                        host=host, confidence=72, source="headers",
                    )

        output.technologies = list(found.values())
        output.data["summary"] = {
            "total_technologies": len(found),
            "by_category": _by_category(found.values()),
            "with_version": sum(1 for t in found.values() if t.version),
        }
        return output


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or ""


def _extract_version(value: str) -> str | None:
    match = re.search(r"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)", value)
    return match.group(1) if match else None


def _by_category(technologies) -> dict[str, int]:
    out: dict[str, int] = {}
    for tech in technologies:
        category = tech.category or "unknown"
        out[category] = out.get(category, 0) + 1
    return out
