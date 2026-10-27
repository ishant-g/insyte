"""Subdomain Takeover Risk Detection (DNS-only).

Reads the CNAME records `dns_intelligence` already collected and checks
each target two ways: whether it still resolves at all (a CNAME pointing
at a name that no longer exists is dangling, the classic takeover
precondition), and whether it matches a known-takeoverable third-party
service pattern (GitHub Pages, Heroku, S3 and friends, per the
community-maintained can-i-take-over-xyz list).

DNS alone cannot prove a takeover is possible - that needs the service's
HTTP fingerprint, which would be active probing. So every finding here
says "probable" or "potential" and tells the operator exactly how to
verify. No finding here ever claims a confirmed takeover.
"""

from __future__ import annotations

import fnmatch

from app.core.contracts import FindingRecord, ModuleOutput, ObservationRecord
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ObservationStatus,
    ScanMode,
    Severity,
    SourceKind,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: CNAME suffix patterns for services with a known subdomain-takeover
#: history, curated from can-i-take-over-xyz and current practitioner
#: references (verified 2026-09-27). Matched with fnmatch against the
#: lowercased CNAME target.
_TAKEOVER_PATTERNS: tuple[tuple[str, str], ...] = (
    ("*.github.io", "GitHub Pages"),
    ("*.herokuapp.com", "Heroku"),
    ("*.herokudns.com", "Heroku"),
    ("*.s3.amazonaws.com", "AWS S3"),
    ("*.s3-website.*.amazonaws.com", "AWS S3 static website"),
    ("*.azurewebsites.net", "Azure App Service"),
    ("*.cloudapp.azure.com", "Azure"),
    ("*.cloudapp.net", "Azure"),
    ("*.trafficmanager.net", "Azure Traffic Manager"),
    ("*.netlify.app", "Netlify"),
    ("*.vercel.app", "Vercel"),
    ("*.surge.sh", "Surge.sh"),
    ("*.ghost.io", "Ghost"),
    ("*.fly.dev", "Fly.io"),
    ("*.pantheonsite.io", "Pantheon"),
    ("*.tumblr.com", "Tumblr"),
    ("*.wordpress.com", "WordPress.com"),
    ("*.zendesk.com", "Zendesk"),
    ("*.myshopify.com", "Shopify"),
    ("*.unbouncepages.com", "Unbounce"),
    ("*.bitbucket.io", "Bitbucket"),
    ("*.readthedocs.io", "Read the Docs"),
    ("*.global.fastly.net", "Fastly"),
)


def match_takeover_service(cname_target: str) -> str | None:
    """Return the service name if `cname_target` matches a known-takeoverable
    pattern, else None. Pure function, unit-testable."""
    target = (cname_target or "").lower().rstrip(".")
    for pattern, service in _TAKEOVER_PATTERNS:
        if fnmatch.fnmatchcase(target, pattern):
            return service
    return None


class TakeoverModule(IntelligenceModule):
    id = "subdomain_takeover"
    name = "Subdomain Takeover Risk"
    description = (
        "Checks CNAME records from DNS intelligence for dangling targets "
        "and known-takeoverable third-party services. DNS-only: findings "
        "are flagged probable or potential, never confirmed."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE,)
    input_types = (TargetType.DOMAIN,)
    dependencies = ("dns_intelligence",)
    timeout = 60.0
    order = 23

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)

        cnames = self._collect_cnames(ctx)
        output.data["cnames_checked"] = len(cnames)
        if not cnames:
            output.data["note"] = "no CNAME records found upstream"
            return output

        try:
            import dns.exception
            import dns.resolver

            from app.modules.passive.dns_intel import RESOLVERS
        except ImportError:
            output.data["skip_reason"] = "dnspython is not installed"
            return output

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(RESOLVERS)
        resolver.timeout = 4.0
        resolver.lifetime = 6.0

        for source_host, target in sorted(cnames):
            ctx.check_cancelled()
            resolves = self._resolves(resolver, target)
            service = match_takeover_service(target)

            if not resolves:
                output.observations.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.DOMAIN,
                        value=target,
                        source_type=SourceKind.PASSIVE,
                        confidence=85,
                        status=ObservationStatus.OBSERVED,
                        evidence={
                            "discovery": "CNAME target does not resolve (dangling)",
                            "cname_source": source_host,
                        },
                    )
                )
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.DNS_CONFIGURATION,
                        severity=Severity.HIGH,
                        title=f"Dangling CNAME record (probable takeover): {source_host}",
                        description=(
                            f"{source_host} has a CNAME pointing at {target}, "
                            "which no longer resolves. The external name is "
                            "gone while the pointer remains, which is the "
                            "classic precondition for a subdomain takeover. "
                            "This is DNS evidence only: it shows the pointer "
                            "is dangling, not that the name is claimable."
                        ),
                        recommendation=(
                            "Remove the CNAME if the service is retired, or "
                            "re-claim the external resource under your own "
                            "account. Verify claimability on the service "
                            "itself before reporting it as a vulnerability."
                        ),
                        confidence=80,
                        exposure=ExposureLevel.INFERRED,
                        sources=[self.id, "dns_intelligence"],
                        evidence={"cname_source": source_host, "cname_target": target},
                    )
                )
            elif service:
                output.observations.append(
                    ObservationRecord(
                        source=self.id,
                        asset_type=AssetType.DOMAIN,
                        value=target,
                        source_type=SourceKind.PASSIVE,
                        confidence=60,
                        status=ObservationStatus.OBSERVED,
                        evidence={
                            "discovery": "CNAME points at a potentially "
                            "claimable third-party service",
                            "cname_source": source_host,
                            "service": service,
                        },
                    )
                )
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.DNS_CONFIGURATION,
                        severity=Severity.MEDIUM,
                        title=f"CNAME points at third-party service ({service}): {source_host}",
                        description=(
                            f"{source_host} points at {target}, hosted on "
                            f"{service} - a service with a known history of "
                            "subdomain takeovers. The target still resolves, "
                            "so this is a potential risk only: confirm the "
                            "resource is still claimed by the target's owner "
                            "before treating it as vulnerable."
                        ),
                        recommendation=(
                            "Check the service dashboard that the resource "
                            "behind this hostname is still owned by you. If "
                            "it was deleted or never claimed, reclaim or "
                            "remove the CNAME."
                        ),
                        confidence=55,
                        exposure=ExposureLevel.INFERRED,
                        sources=[self.id, "dns_intelligence"],
                        evidence={
                            "cname_source": source_host,
                            "cname_target": target,
                            "service": service,
                        },
                    )
                )

        output.metrics["takeover_findings"] = len(output.findings)
        return output

    def _collect_cnames(self, ctx: ModuleContext) -> set[tuple[str, str]]:
        """(source host, cname target) pairs from upstream DNS data."""
        out: set[tuple[str, str]] = set()
        single = ctx.data_of("dns_intelligence", "cname_target")
        if isinstance(single, str) and single.strip():
            out.add((ctx.target.value, single.strip().lower().rstrip(".")))
        upstream = ctx.output_of("dns_intelligence")
        records = getattr(upstream, "dns_records", None) or []
        for record in records:
            if getattr(record, "record_type", "").upper() != "CNAME":
                continue
            value = str(getattr(record, "value", "") or "").strip().lower().rstrip(".")
            name = str(getattr(record, "name", "") or "").strip().lower().rstrip(".")
            if value and value != ctx.target.value.lower():
                out.add((name or ctx.target.value, value))
        return out

    @staticmethod
    def _resolves(resolver, target: str) -> bool:
        import dns.exception
        import dns.resolver

        for rtype in ("A", "AAAA"):
            try:
                answer = resolver.resolve(target, rtype, raise_on_no_answer=False)
                if answer:
                    return True
            except dns.resolver.NXDOMAIN:
                return False
            except dns.exception.DNSException:
                continue
            except Exception:  # noqa: BLE001 - treat lookup errors as unknown
                continue
        return False
