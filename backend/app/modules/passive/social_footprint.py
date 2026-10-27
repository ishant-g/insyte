"""Social Footprint - structured-data profile links and verified anchor links.

Two evidence tiers, both read from HTML the scan already fetched:

* **Structured-data extraction (high confidence).** `<script
  type="application/ld+json">` blocks (schema.org `sameAs`), `<meta
  property="og:...">` tags, and `<link rel="me">` tags (the
  Mastodon/IndieWeb identity-verification convention) are parsed out of
  whatever `ctx.html_bodies()` already holds - at minimum the homepage,
  fetched by `web_surface` in both modes. This performs zero new requests
  to the target; it only reads bodies collected elsewhere. A hostile or
  malformed `<script type="application/ld+json">` block must never crash
  the module, so every parse is wrapped defensively.
* **Anchor-link extraction (medium confidence).** Every `<a href>` on the
  fetched pages is classified against known platform domains. A site that
  links to `github.com/acme` from its own footer is decent evidence that
  profile belongs to the organisation - weaker than an explicit `sameAs`
  claim, but far stronger than guessing a handle from the domain name.

What this module deliberately does NOT do any more: derive a handle from
the registrable domain and probe dozens of platforms for it. That
WhatsMyName-style enumeration produced high false-positive rates (a
`github.com/acme-corp` account existing says nothing about whether it
belongs to the target), and its `status_200_ambiguous` checks treated the
*absence* of a not-found marker as a weak "found" - the weakest possible
signal. The one narrow exception is a deterministic organisation-handle
check: when RDAP registrant data names a real organisation (not redacted),
1-2 handle candidates derived from that name are checked against GitHub
and npm only - both have clean 404 semantics - and the result is labelled
as a guess, never as a confirmed profile.

Every check is a request to a third-party platform, never to the scan
target, and all of it goes through `ctx.http` exclusively (never a raw
client) so the SSRF guard and byte caps apply uniformly. Only GET is ever
used - no login attempt, no form submission, nothing that could be
mistaken for authentication.

Results are report/UI-surfaced structured data (`output.data`), not
assets or observations - the same treatment `domain_intelligence` gives
`output.data["registration"]`. A social profile is contextual evidence
about the organisation, not itself an attack-surface node in the graph.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from app.core.contracts import ModuleOutput
from app.core.target import TargetType, is_subdomain_of
from app.models.enums import ModuleCategory, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext

#: (platform label, hostname needle matched against a candidate URL's
#: host). Used to classify `sameAs`/`og:`/`rel="me"` URLs and plain anchor
#: links found in the page's own markup.
_PLATFORM_DOMAINS: tuple[tuple[str, str], ...] = (
    ("github.com", "GitHub"),
    ("gitlab.com", "GitLab"),
    ("npmjs.com", "npm"),
    ("pypi.org", "PyPI"),
    ("hub.docker.com", "Docker Hub"),
    ("reddit.com", "Reddit"),
    ("medium.com", "Medium"),
    ("youtube.com", "YouTube"),
    ("twitter.com", "Twitter/X"),
    ("x.com", "Twitter/X"),
    ("instagram.com", "Instagram"),
    ("facebook.com", "Facebook"),
    ("linkedin.com", "LinkedIn"),
    ("tiktok.com", "TikTok"),
    ("pinterest.com", "Pinterest"),
    ("twitch.tv", "Twitch"),
    ("producthunt.com", "Product Hunt"),
    ("dev.to", "Dev.to"),
    ("hashnode.com", "Hashnode"),
    ("mastodon.social", "Mastodon"),
    ("keybase.io", "Keybase"),
    ("news.ycombinator.com", "HackerNews"),
    ("behance.net", "Behance"),
    ("dribbble.com", "Dribbble"),
    ("bitbucket.org", "Bitbucket"),
    ("sourceforge.net", "SourceForge"),
    ("codepen.io", "CodePen"),
    ("kaggle.com", "Kaggle"),
    ("quora.com", "Quora"),
    ("patreon.com", "Patreon"),
    ("gravatar.com", "Gravatar"),
    ("flickr.com", "Flickr"),
    ("soundcloud.com", "SoundCloud"),
    ("vimeo.com", "Vimeo"),
    ("tumblr.com", "Tumblr"),
    ("rubygems.org", "RubyGems"),
    ("crates.io", "Crates.io"),
    ("nuget.org", "NuGet"),
    ("codeberg.org", "Codeberg"),
)


def _classify_platform(url: str) -> str | None:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    for needle, label in _PLATFORM_DOMAINS:
        if host == needle or host.endswith("." + needle):
            return label
    return None


def _walk_same_as(node: object) -> list[str]:
    """Depth-first search for a `sameAs` value at any level.

    `sameAs` may appear on the top-level object, nested under
    `@graph`/`author`/`publisher`/etc., and its value may be a bare string
    or a list of strings - schema.org allows all of it, and real sites use
    all of it, so no fixed depth or key path is assumed.
    """
    found: list[str] = []
    if isinstance(node, dict):
        same_as = node.get("sameAs")
        if isinstance(same_as, str):
            found.append(same_as)
        elif isinstance(same_as, list):
            found.extend(v for v in same_as if isinstance(v, str))
        for value in node.values():
            if isinstance(value, (dict, list)):
                found.extend(_walk_same_as(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_same_as(item))
    return found


def _extract_structured_profiles(html: str) -> dict[str, dict[str, object]]:
    """JSON-LD `sameAs`, `og:` meta and `rel="me"` links, classified by platform.

    Never raises: a hostile page is data, and malformed JSON-LD in
    particular is common enough in the wild (trailing commas, HTML
    comments left inside the script body) that failing quietly is the only
    sane behaviour for a passive scanner.
    """
    profiles: dict[str, dict[str, object]] = {}
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001 - malformed markup is data, not a bug
        return profiles

    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        text = tag.string or tag.get_text() or ""
        if not text.strip():
            continue
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            continue
        for url in _walk_same_as(data):
            platform = _classify_platform(url)
            if platform is None:
                continue
            profiles.setdefault(
                platform,
                {
                    "platform": platform,
                    "url": url.strip(),
                    "status": "found",
                    "confidence": 95,
                    "source": "jsonld",
                    "verification": "site_claimed",
                },
            )

    for meta in soup.find_all("meta", attrs={"property": re.compile(r"^og:")}):
        content = meta.get("content")
        if not content:
            continue
        platform = _classify_platform(content)
        if platform:
            profiles.setdefault(
                platform,
                {
                    "platform": platform,
                    "url": str(content).strip(),
                    "status": "found",
                    "confidence": 85,
                    "source": "opengraph",
                    "verification": "site_claimed",
                },
            )

    for link in soup.find_all("link", attrs={"rel": True}):
        rels = link.get("rel")
        rels = rels if isinstance(rels, list) else [rels]
        if "me" not in [str(r).lower() for r in rels if r]:
            continue
        href = link.get("href")
        if not href:
            continue
        platform = _classify_platform(href)
        if platform:
            profiles.setdefault(
                platform,
                {
                    "platform": platform,
                    "url": str(href).strip(),
                    "status": "found",
                    "confidence": 90,
                    "source": "rel_me",
                    "verification": "site_claimed",
                },
            )

    return profiles


def _extract_anchor_links(
    html: str, scope: str | None
) -> dict[str, dict[str, object]]:
    """Plain `<a href>` links to known platforms, classified by platform.

    A link from the target's own page to a platform profile is weaker than
    an explicit `sameAs` claim (footers link to all sorts of things) but
    far stronger than a guessed handle. Links to the target's own domain
    are ignored, as are non-HTTP(S) hrefs. Never raises.
    """
    profiles: dict[str, dict[str, object]] = {}
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001 - malformed markup is data, not a bug
        return profiles

    for tag in soup.find_all("a", href=True):
        href = str(tag.get("href") or "").strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        try:
            host = (urlsplit(href).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if scope and (host == scope or is_subdomain_of(host, scope)):
            continue
        platform = _classify_platform(href)
        if platform is None:
            continue
        profiles.setdefault(
            platform,
            {
                "platform": platform,
                "url": href,
                "status": "found",
                "confidence": 70,
                "source": "anchor_link",
                "verification": "linked_from_site",
            },
        )
    return profiles


#: Corporate suffixes stripped when deriving a handle candidate from an
#: organisation name - "Acme Corp Inc" and "Acme" should produce the same
#: candidate, not three different guesses.
_ORG_SUFFIXES: frozenset[str] = frozenset(
    {
        "inc", "incorporated", "llc", "ltd", "limited", "corp",
        "corporation", "co", "company", "gmbh", "pty", "plc",
        "sarl", "bv", "ab", "sas", "spa", "sro",
    }
)


def _org_handle_candidates(org_name: str) -> list[str]:
    """1-2 deterministic handle candidates from a verified org name.

    Returns [] when nothing sane can be derived. This is the only
    handle-guessing left in the module, and it only runs when RDAP named
    a real (non-redacted) organisation.
    """
    cleaned = re.sub(r"[^a-z0-9 ]", "", (org_name or "").lower()).strip()
    words = [w for w in cleaned.split() if w and w not in _ORG_SUFFIXES]
    if not words:
        return []
    candidates: list[str] = []
    nospace = "".join(words)
    if nospace and len(nospace) >= 2:
        candidates.append(nospace)
    hyphenated = "-".join(words)
    if hyphenated != nospace and len(hyphenated) >= 2:
        candidates.append(hyphenated)
    return candidates[:2]


#: The only platforms still probed with a derived handle, and only with a
#: verified org name. Both answer a clean HTTP 404 for a missing account,
#: which is the only check semantics trustworthy enough to keep - every
#: `status_200_ambiguous` platform was removed because "no not-found
#: marker on a 200 page" is not evidence of anything.
_ORG_HANDLE_CHECKS: tuple[tuple[str, str], ...] = (
    ("GitHub", "https://github.com/{handle}"),
    ("npm", "https://www.npmjs.com/~{handle}"),
)


def _probe_handle(ctx: ModuleContext, url: str) -> str:
    """Check one derived-handle URL. Returns found / not_found / uncertain."""
    response = ctx.http.try_get(url, accept="text/html")
    if response is None:
        return "uncertain"
    if response.status_code == 404:
        return "not_found"
    if response.status_code == 200:
        return "found"
    return "uncertain"


def _verified_org_name(ctx: ModuleContext) -> str | None:
    """Organisation name from RDAP, only when it was not redacted.

    A redacted registrant tells us nothing; falling back to the domain
    string here is exactly the guessing this rewrite removes.
    """
    registration = ctx.data_of("domain_intelligence", "registration", {}) or {}
    if registration.get("registrant_redacted"):
        return None
    registrant = registration.get("registrant")
    if not isinstance(registrant, dict):
        return None
    org = registrant.get("org") or registrant.get("fn")
    org = str(org or "").strip()
    return org or None


class SocialFootprintModule(IntelligenceModule):
    id = "social_footprint"
    name = "Social Footprint"
    description = (
        "Extracts schema.org sameAs / og: / rel=me profile links and "
        "platform anchor links from the target's own markup, plus a narrow "
        "deterministic handle check (GitHub/npm) only when RDAP names a "
        "real organisation. No domain-derived handle guessing."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    dependencies = ("web_surface",)
    timeout = 90.0
    order = 47

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        scope = ctx.target.registrable or ctx.target.value

        structured: dict[str, dict[str, object]] = {}
        anchored: dict[str, dict[str, object]] = {}
        for html in ctx.html_bodies().values():
            for platform, info in _extract_structured_profiles(html).items():
                structured.setdefault(platform, info)
            for platform, info in _extract_anchor_links(html, scope).items():
                # Structured claims outrank plain links for the same platform.
                if platform not in structured:
                    anchored.setdefault(platform, info)

        org_name = _verified_org_name(ctx)
        handle_results: list[dict[str, object]] = []
        checks_run = 0
        if org_name:
            for handle in _org_handle_candidates(org_name):
                for platform, template in _ORG_HANDLE_CHECKS:
                    ctx.check_cancelled()
                    url = template.format(handle=handle)
                    checks_run += 1
                    status = _probe_handle(ctx, url)
                    handle_results.append(
                        {
                            "platform": platform,
                            "url": url,
                            "status": status,
                            "confidence": 60 if status == "found" else 0,
                            "source": "org_handle_check",
                            "verification": "handle_guess",
                            "derived_from": org_name,
                        }
                    )

        merged: dict[str, dict[str, object]] = {}
        merged.update(structured)
        for platform, info in anchored.items():
            merged.setdefault(platform, info)
        for entry in handle_results:
            if entry["status"] == "found":
                # A guessed handle that exists is still a guess - it never
                # outranks site-claimed evidence for the same platform.
                merged.setdefault(str(entry["platform"]), entry)

        output.data["social_profiles"] = sorted(
            merged.values(), key=lambda p: str(p["platform"])
        )
        output.data["summary"] = {
            "org_name_used": org_name,
            "handle_checks_run": checks_run,
            "confirmed_via_structured_data": len(structured),
            "found_via_anchor_links": len(anchored),
            "found_via_handle_check": sum(
                1 for e in handle_results if e["status"] == "found"
            ),
            "note": (
                "Handle-check hits are guesses against a derived name, not "
                "confirmed profiles - verify before treating them as the "
                "target's accounts."
            ),
        }
        output.metrics["profiles_found"] = len(merged)
        return output
