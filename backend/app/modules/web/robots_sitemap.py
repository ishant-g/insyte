"""Robots.txt & Sitemap.xml Intelligence.

`web_surface` already fetches `robots.txt` (once, in both modes) and the
top-level `sitemap.xml` - this module is what actually *reads* them rather
than treating them as opaque bytes. Two things make robots.txt worth a
dedicated pass: its `Sitemap:` directives are the canonical way to
discover a site's real sitemap location (already handled upstream), and
its `Disallow:` directives are a classic, entirely passive information
leak - an operator who did not want a path indexed by search engines has,
by writing it into a public file, told every reader exactly which paths
they consider sensitive. Reading that list is not brute-forcing; it is
reading what the site published.

Sitemap `<loc>` entries get the same treatment at a lower severity ceiling,
because a sitemap's whole purpose is public discoverability - a sensitive
path *should* almost never appear there, which is precisely why one that
does is worth flagging.

No request beyond what `web_surface` already made. Everything here is text
parsing of bodies already sitting in `ctx.data_of("web_surface", ...)`.
"""

from __future__ import annotations

import re

from app.core.canonical import canonical_url
from app.core.contracts import ExposureRecord, FindingRecord, ModuleOutput, UrlRecord
from app.core.target import TargetType
from app.models.enums import (
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext
from app.modules.web.indexed_exposure import _classify, _severity

_DIRECTIVE_RE = re.compile(r"^\s*([A-Za-z\-]+)\s*:\s*(.*?)\s*$")


class RobotsSitemapIntelligenceModule(IntelligenceModule):
    id = "robots_sitemap_intelligence"
    name = "Robots.txt & Sitemap Intelligence"
    description = (
        "Parses robots.txt Disallow/Allow directives and sitemap.xml "
        "entries already fetched by web_surface, flagging paths an "
        "operator explicitly tried to keep out of search indexes."
    )
    category = ModuleCategory.EXPOSURE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("web_surface",)
    timeout = 15.0
    order = 78

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        blocker = ctx.web_fetch_blocker()
        if blocker is not None:
            return ModuleOutput(module_id=self.id, skip_reason=blocker)
        output = ModuleOutput(module_id=self.id)
        surface = ctx.output_of("web_surface")
        target_host = ctx.target.value
        origin = (surface.data.get("origin") if surface else None) or ctx.target.http_origin

        robots_body = self._find_body(ctx, "/robots.txt")
        disallow_hits = 0
        allow_hits = 0
        sensitive_disallow = 0
        groups: list[dict] = []
        crawl_delays: list[float] = []
        sitemap_directives: list[str] = []

        if robots_body:
            groups, crawl_delays, sitemap_directives = _parse_robots(robots_body)
            for group in groups:
                for kind, path in group["rules"]:
                    if kind == "disallow":
                        disallow_hits += 1
                    else:
                        allow_hits += 1
                    if path in ("", "/"):
                        continue
                    resolved = canonical_url(path, base=origin, target_host=target_host)
                    if resolved is None:
                        continue
                    match = _classify(resolved.path)
                    output.urls.append(
                        UrlRecord(
                            url=path,
                            normalized_url=resolved.normalized,
                            host=resolved.host,
                            path=resolved.path,
                            scheme=resolved.scheme,
                            classification=resolved.classification,
                            extension=resolved.extension,
                            retrieved=False,
                            in_scope=resolved.in_scope,
                            confidence=80,
                            sources=["robots_txt"],
                            evidence={
                                "discovery": f"robots.txt {kind.capitalize()} directive",
                                "user_agent": group["user_agent"],
                            },
                        )
                    )
                    if match is not None:
                        exposure_type, tier = match
                        severity = _severity(tier, "observed")
                        if tier == "sensitive":
                            sensitive_disallow += 1
                        output.exposures.append(
                            ExposureRecord(
                                exposure_type=exposure_type,
                                url=resolved.normalized,
                                observation_class="observed",
                                host=resolved.host,
                                path=resolved.path,
                                severity=severity,
                                confidence=78,
                                retrievable=False,
                                sources=["robots_txt"],
                                evidence={
                                    "directive": kind,
                                    "user_agent": group["user_agent"],
                                    "raw_path": path,
                                },
                            )
                        )
                        if severity.rank >= Severity.MEDIUM.rank:
                            output.findings.append(
                                FindingRecord(
                                    module_id=self.id,
                                    category=FindingCategory.INDEXED_ARTIFACT,
                                    severity=severity,
                                    title=f"robots.txt discloses a sensitive-looking path: {path}",
                                    description=(
                                        f"robots.txt's {kind.capitalize()} directive for "
                                        f"user-agent '{group['user_agent']}' names {path}, "
                                        f"which matches the '{exposure_type}' pattern. "
                                        "Disallowing a path from search indexing does not "
                                        "restrict access to it - it only asks well-behaved "
                                        "crawlers not to list it."
                                    ),
                                    recommendation=(
                                        "If this path must stay unlisted, enforce that with "
                                        "authentication or network controls, not robots.txt "
                                        "alone - robots.txt is advisory and publicly readable."
                                    ),
                                    location=resolved.normalized,
                                    confidence=75,
                                    exposure=ExposureLevel.INFERRED,
                                    sources=["robots_txt"],
                                    evidence={"directive": kind, "path": path},
                                )
                            )

        sitemap_urls = list((surface.data.get("sitemap_urls") if surface else None) or [])
        sensitive_sitemap = 0
        for raw_url in sitemap_urls:
            resolved = canonical_url(raw_url, target_host=target_host)
            if resolved is None:
                continue
            match = _classify(resolved.path)
            if match is None:
                continue
            exposure_type, tier = match
            # A sitemap's job is public discoverability, so a match here is
            # capped one severity band below the same match in robots.txt -
            # it usually means "unusually named public page", not "leak".
            severity = _severity(tier, "observed")
            if severity is Severity.HIGH:
                severity = Severity.MEDIUM
            elif severity is Severity.MEDIUM:
                severity = Severity.LOW
            if tier == "sensitive":
                sensitive_sitemap += 1
            output.exposures.append(
                ExposureRecord(
                    exposure_type=exposure_type,
                    url=resolved.normalized,
                    observation_class="indexed",
                    host=resolved.host,
                    path=resolved.path,
                    severity=severity,
                    confidence=55,
                    retrievable=False,
                    sources=["sitemap_xml"],
                    evidence={"discovery": "sitemap.xml <loc> entry"},
                )
            )
            if severity.rank >= Severity.MEDIUM.rank:
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.INDEXED_ARTIFACT,
                        severity=severity,
                        title=f"sitemap.xml lists a sensitive-looking path: {resolved.path}",
                        description=(
                            f"sitemap.xml includes {raw_url}, which matches the "
                            f"'{exposure_type}' pattern - unusual for a file whose purpose "
                            "is public search-engine discovery."
                        ),
                        recommendation=(
                            "Confirm this URL is meant to be publicly indexed; remove it "
                            "from the sitemap if not."
                        ),
                        location=resolved.normalized,
                        confidence=55,
                        exposure=ExposureLevel.INDEXED,
                        sources=["sitemap_xml"],
                    )
                )

        output.data["robots_txt"] = {
            "present": bool(robots_body),
            "user_agent_groups": [
                {"user_agent": g["user_agent"], "disallow": g["disallow_count"], "allow": g["allow_count"]}
                for g in groups
            ],
            "crawl_delay": crawl_delays[0] if crawl_delays else None,
            "sitemap_directives": sitemap_directives,
        }
        output.data["summary"] = {
            "robots_present": bool(robots_body),
            "disallow_count": disallow_hits,
            "allow_count": allow_hits,
            "sensitive_disallow_matches": sensitive_disallow,
            "sitemap_urls_total": len(sitemap_urls),
            "sensitive_sitemap_matches": sensitive_sitemap,
        }
        return output

    def _find_body(self, ctx: ModuleContext, suffix: str) -> str | None:
        surface = ctx.output_of("web_surface")
        bodies: dict[str, str] = (surface.data.get("bodies") if surface else None) or {}
        for url, body in bodies.items():
            if url.split("?", 1)[0].endswith(suffix):
                return body
        return None


def _parse_robots(body: str) -> tuple[list[dict], list[float], list[str]]:
    """Parse robots.txt into per-user-agent rule groups.

    Follows the de-facto format (RFC 9309): a group is one or more
    `User-agent:` lines followed by `Disallow`/`Allow`/`Crawl-delay` lines,
    terminated by a blank line or the next `User-agent:` block.
    """
    groups: list[dict] = []
    crawl_delays: list[float] = []
    sitemap_directives: list[str] = []
    current_agents: list[str] = []
    current_rules: dict[str, list[tuple[str, str]]] = {}

    def flush() -> None:
        for agent in current_agents:
            rules = current_rules.get(agent, [])
            groups.append(
                {
                    "user_agent": agent,
                    "rules": rules,
                    "disallow_count": sum(1 for k, _ in rules if k == "disallow"),
                    "allow_count": sum(1 for k, _ in rules if k == "allow"),
                }
            )

    pending_agents: list[str] = []
    seen_rule_since_agent = False
    for raw_line in body.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _DIRECTIVE_RE.match(line)
        if not match:
            continue
        directive, value = match.group(1).lower(), match.group(2)

        if directive == "user-agent":
            if seen_rule_since_agent:
                pending_agents = []
                seen_rule_since_agent = False
            pending_agents.append(value)
            current_agents = pending_agents
            for agent in pending_agents:
                current_rules.setdefault(agent, [])
        elif directive in ("disallow", "allow") and current_agents:
            seen_rule_since_agent = True
            for agent in current_agents:
                current_rules[agent].append((directive, value))
        elif directive == "crawl-delay":
            try:
                crawl_delays.append(float(value))
            except ValueError:
                pass
        elif directive == "sitemap":
            sitemap_directives.append(value)

    flush()
    return groups, crawl_delays, sitemap_directives
