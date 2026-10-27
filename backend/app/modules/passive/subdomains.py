"""Subdomain Intelligence.

Aggregates every provider that can answer "subdomains" - Certificate
Transparency, passive DNS, historical archives, and whichever keyed
providers are configured - into one deduplicated set with full source
attribution. This is the module the brief's example
("api.example.com / Sources: CT, URLScan, Common Crawl / Confidence: 96%")
describes directly: cross-source corroboration is what pushes confidence
up, and that logic is what `merge_observations` implements.

DNS resolution of newly-discovered names is *not* done here - that would
make a Passive-mode scan look up dozens of names it has no evidence for,
and it is redundant with what `dns_intelligence` already does for the
target itself. Subdomains this module discovers are recon evidence; whether
they currently resolve is left to the reader rather than asserted.
"""

from __future__ import annotations

from app.core.contracts import ModuleOutput
from app.core.target import TargetType, is_subdomain_of
from app.models.enums import AssetType, ModuleCategory, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext, dedupe_observations
from app.services.correlation.merge import merge_observations


class SubdomainIntelligenceModule(IntelligenceModule):
    id = "subdomain_intelligence"
    name = "Subdomain Intelligence"
    description = (
        "Aggregates subdomains from Certificate Transparency, passive DNS, "
        "historical archives, and any configured external providers, with "
        "full per-source attribution and confidence scoring."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    dependencies = ("certificate_intelligence",)
    providers = (
        "crtsh", "certspotter", "hackertarget", "rapiddns", "otx",
        "wayback", "commoncrawl", "urlscan",
        "virustotal", "shodan", "censys", "securitytrails", "github", "chaos",
    )
    timeout = 90.0
    order = 40

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target = ctx.target
        domain = target.registrable or target.value

        observations, statuses = self.gather(
            ctx, "subdomains", limit=ctx.limits.max_subdomains
        )
        output.providers.extend(statuses)

        # Certificate SANs from the upstream module are additional evidence
        # for the same set of names - fold them in rather than re-querying.
        cert_output = ctx.output_of("certificate_intelligence")
        if cert_output is not None:
            observations.extend(
                o for o in cert_output.observations
                if o.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
            )

        observations = [
            o
            for o in dedupe_observations(observations)
            if o.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
            and is_subdomain_of(o.value, domain)
        ]

        merged = merge_observations(observations)
        merged = merged[: ctx.limits.max_subdomains]

        for asset in merged:
            output.assets.append(asset)
            output.observations.extend(
                o for o in observations if o.hash == asset.hash
            )

        by_source: dict[str, int] = {}
        for observation in observations:
            by_source[observation.source] = by_source.get(observation.source, 0) + 1

        output.data["summary"] = {
            "total_subdomains": len(merged),
            "apex_included": any(a.normalized == target.value for a in merged),
            "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
            "multi_source_count": sum(1 for a in merged if a.attributes.get("source_count", 1) > 1),
        }
        output.metrics["subdomains_found"] = len(merged)
        return output
