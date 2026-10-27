"""IP / ASN Intelligence.

For every IP address discovered so far (the target itself if it is an IP,
or every address the DNS module resolved), this module establishes network
context: announcing ASN, netblock, organisation, and reverse DNS. Every
attribution is evidence-based - an ASN name and a routing announcement, not
a geolocation guess - which is the distinction the brief draws explicitly
("Never claim ownership solely from geolocation").
"""

from __future__ import annotations

import ipaddress
from datetime import UTC

from app.core.contracts import (
    AssetRecord,
    FindingRecord,
    ModuleOutput,
    ObservationRecord,
    RelationshipRecord,
)
from app.core.target import TargetType, is_subdomain_of, normalize_hostname
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ObservationStatus,
    RelationType,
    ScanMode,
    Severity,
    SourceKind,
)
from app.modules.base import IntelligenceModule, ModuleContext
from app.providers import ProviderQuery, get_provider

#: AbuseIPDB confidence above this is worth surfacing as a finding rather
#: than just data - below it, a handful of stale reports is normal noise.
_ABUSE_FINDING_THRESHOLD = 50

#: ASNs where a reverse-IP lookup is noise, not signal. These are
#: hyperscaler, CDN and serverless-platform ranges where one address hosts
#: thousands of unrelated tenants - dumping all of them into the report as
#: "domains" produced hundreds of irrelevant assets (the classic shared-IP
#: problem). Reverse-IP enumeration is skipped entirely for these; the
#: skip is logged so it is visible, not silent.
_SHARED_HOSTING_ASNS = {
    13335, 209242,  # Cloudflare
    16509, 14618, 8987,  # Amazon / AWS
    15169, 396982, 36040,  # Google / GCP
    8075, 35995,  # Microsoft / Azure
    54113,  # Fastly
    16625, 20940, 34164,  # Akamai
    73914,  # Netlify
    55002,  # Vercel (own range, where announced directly)
    394699,  # Vercel (additional)
}
_SHARED_HOSTING_NAME_HINTS = (
    "cloudflare",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "fastly",
    "akamai",
    "netlify",
    "vercel",
    "cloudfront",
)

#: Even off shared hosting, a reverse-IP lookup can return a long tail of
#: stale or parked names. Cap what enters the graph; the rest is noise.
_REVERSE_IP_CAP = 40


def _is_shared_hosting_asn(asn_value: str | None, asn_holder: str | None) -> bool:
    """True when the ASN is a hyperscaler/CDN where reverse-IP is meaningless."""
    if asn_value:
        try:
            if int(asn_value.upper().removeprefix("AS")) in _SHARED_HOSTING_ASNS:
                return True
        except ValueError:
            pass
    if asn_holder:
        holder = asn_holder.lower()
        return any(hint in holder for hint in _SHARED_HOSTING_NAME_HINTS)
    return False


class IpAsnIntelligenceModule(IntelligenceModule):
    id = "ip_asn_intelligence"
    name = "IP / ASN Intelligence"
    description = (
        "Network context for every discovered IP address: announcing ASN, "
        "netblock, organisation, reverse DNS, abuse reputation and other "
        "domains sharing the same address, from RDAP, RIPEstat, AbuseIPDB, "
        "GreyNoise and HackerTarget."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    dependencies = ("dns_intelligence",)
    providers = ("rdap", "ripestat", "bgp_origin", "abuseipdb", "greynoise", "hackertarget")
    timeout = 60.0
    order = 50

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        addresses = ctx.known_ips()[:100]
        if not addresses:
            output.data["addresses"] = []
            return output

        ripestat = get_provider("ripestat")
        abuseipdb = get_provider("abuseipdb")
        greynoise = get_provider("greynoise")
        hackertarget = get_provider("hackertarget")
        per_address: list[dict] = []
        asn_seen: dict[str, dict] = {}
        domain_scope = ctx.target.registrable or ctx.target.value

        for address in addresses:
            ctx.check_cancelled()
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue

            asset_attributes: dict = {}
            asset_sources = ["dns"]

            if abuseipdb is not None:
                abuse = abuseipdb.abuse_lookup(address)
                if abuse is not None:
                    asset_attributes["abuseipdb"] = abuse
                    asset_sources.append("abuseipdb")
                    score = abuse.get("abuse_confidence_score")
                    if isinstance(score, int) and score > _ABUSE_FINDING_THRESHOLD:
                        output.findings.append(
                            FindingRecord(
                                module_id=self.id,
                                category=FindingCategory.NETWORK_REPUTATION,
                                severity=Severity.MEDIUM if score < 80 else Severity.HIGH,
                                title=f"{address} has a high AbuseIPDB confidence score ({score}%)",
                                description=(
                                    f"AbuseIPDB reports {abuse.get('total_reports')} abuse "
                                    f"report(s) for this address in the last 90 days, with an "
                                    f"abuse confidence score of {score}%. This does not mean "
                                    "the target itself is compromised - shared hosting and "
                                    "CDN/proxy addresses often carry reputational history from "
                                    "unrelated tenants."
                                ),
                                recommendation=(
                                    "Confirm this address is dedicated to the target before "
                                    "acting on it, and check with the hosting provider if it "
                                    "is shared infrastructure."
                                ),
                                confidence=70,
                                exposure=ExposureLevel.INFERRED,
                                sources=["abuseipdb"],
                                evidence={"address": address, **abuse},
                                asset_type=AssetType.IP,
                                asset_value=address,
                            )
                        )

            if greynoise is not None:
                classification = greynoise.classify(address)
                if classification is not None:
                    asset_attributes["greynoise_classification"] = classification.get(
                        "classification"
                    )
                    asset_attributes["greynoise_noise"] = classification.get("noise")
                    asset_attributes["greynoise_riot"] = classification.get("riot")
                    asset_sources.append("greynoise")

            # Reverse-IP enumeration happens after ASN discovery below,
            # where shared-hosting addresses are skipped outright.

            output.assets.append(
                AssetRecord(
                    asset_type=AssetType.IP,
                    value=address,
                    confidence=97,
                    sources=asset_sources,
                    is_target=(ctx.target.is_ip and ctx.target.value == address),
                    attributes=asset_attributes,
                )
            )

            entry: dict = {"address": address, "netblock": None, "asn": None, "asn_name": None, "ptr": None}

            netblock = None
            asn_value = None
            asn_holder = None

            if ripestat is not None:
                result = ripestat.collect(
                    ProviderQuery(target=ctx.target, intent="network", value=address)
                )
                if result.status is not None:
                    output.providers.append(result.status)
                observations = list(result.observations)
                # Fallback chain for routing data: RIPEstat is authoritative
                # for announced routing, but when it yields nothing
                # (rate-limit, outage, stale data) the bgp_origin provider
                # answers the same question from a public BGP looking glass,
                # and only if that is empty too does RDAP allocation data
                # stand in for netblock and origin AS. Each step is consulted
                # only when everything before it came up empty, so the
                # stronger source always wins.
                if not any(
                    o.asset_type in (AssetType.NETBLOCK, AssetType.ASN)
                    for o in observations
                ):
                    bgp = get_provider("bgp_origin")
                    if bgp is not None:
                        bgp_result = bgp.collect(
                            ProviderQuery(
                                target=ctx.target, intent="network", value=address
                            )
                        )
                        if bgp_result.status is not None:
                            output.providers.append(bgp_result.status)
                        if bgp_result.observations:
                            ctx.event(
                                self.id,
                                "asn_fallback_bgp_origin",
                                f"RIPEstat returned no routing data for {address}; "
                                f"used BGP looking glass data instead",
                                level="INFO",
                            )
                        observations.extend(bgp_result.observations)
                if not any(
                    o.asset_type in (AssetType.NETBLOCK, AssetType.ASN)
                    for o in observations
                ):
                    rdap = get_provider("rdap")
                    if rdap is not None:
                        rdap_result = rdap.collect(
                            ProviderQuery(
                                target=ctx.target, intent="network", value=address
                            )
                        )
                        if rdap_result.status is not None:
                            output.providers.append(rdap_result.status)
                        if rdap_result.observations:
                            ctx.event(
                                self.id,
                                "asn_fallback_rdap",
                                f"RIPEstat returned no routing data for {address}; "
                                f"used RDAP allocation data instead",
                                level="INFO",
                            )
                        observations.extend(rdap_result.observations)
                for observation in observations:
                    if observation.asset_type is AssetType.NETBLOCK:
                        netblock = observation.value
                        output.assets.append(
                            AssetRecord(
                                asset_type=AssetType.NETBLOCK,
                                value=observation.value,
                                confidence=observation.confidence,
                                sources=[observation.source],
                                evidence=observation.evidence,
                            )
                        )
                        output.relationships.append(
                            RelationshipRecord(
                                relation=RelationType.HOSTED_BY,
                                source_type=AssetType.IP,
                                source_value=address,
                                target_type=AssetType.NETBLOCK,
                                target_value=observation.value,
                                confidence=observation.confidence,
                                sources=[observation.source],
                            )
                        )
                    elif observation.asset_type is AssetType.ASN:
                        asn_value = observation.value
                        asn_holder = observation.attributes.get("holder")
                        if asn_value not in asn_seen:
                            asn_seen[asn_value] = {
                                "asn": asn_value,
                                "holder": asn_holder,
                                "addresses": [],
                            }
                            output.assets.append(
                                AssetRecord(
                                    asset_type=AssetType.ASN,
                                    value=asn_value,
                                    confidence=observation.confidence,
                                    sources=[observation.source],
                                    label=asn_holder,
                                    evidence=observation.evidence,
                                )
                            )
                        asn_seen[asn_value]["addresses"].append(address)
                        output.relationships.append(
                            RelationshipRecord(
                                relation=RelationType.BELONGS_TO_ASN,
                                source_type=AssetType.IP,
                                source_value=address,
                                target_type=AssetType.ASN,
                                target_value=asn_value,
                                confidence=observation.confidence,
                                sources=[observation.source],
                            )
                        )
                ptr_records = ripestat.reverse_dns(address)
                if ptr_records:
                    entry["ptr"] = ptr_records[0]
                    for ptr in ptr_records:
                        output.observations.append(
                            _ptr_observation(address, ptr)
                        )

            entry["netblock"] = netblock
            entry["asn"] = asn_value
            entry["asn_name"] = asn_holder

            # Reverse-IP co-hosted domains. On hyperscaler/CDN/shared-hosting
            # addresses this returns thousands of unrelated tenants, so it
            # is skipped there entirely; elsewhere the results are capped.
            if hackertarget is not None:
                if _is_shared_hosting_asn(asn_value, asn_holder):
                    ctx.event(
                        self.id,
                        "reverse_ip_skipped_shared_hosting",
                        f"Skipped reverse-IP lookup for {address}: "
                        f"{asn_value or 'unknown ASN'} "
                        f"({asn_holder or 'unknown holder'}) is shared "
                        f"hosting/CDN infrastructure, co-hosted names would be noise",
                        level="INFO",
                    )
                    entry["reverse_ip_skipped"] = "shared_hosting"
                else:
                    cohosted = hackertarget.reverse_ip(address) or []
                    skipped_tail = max(0, len(cohosted) - _REVERSE_IP_CAP)
                    for other_host in cohosted[:_REVERSE_IP_CAP]:
                        host = normalize_hostname(other_host)
                        if not host or is_subdomain_of(host, domain_scope):
                            continue
                        output.observations.append(
                            ObservationRecord(
                                source="hackertarget",
                                asset_type=AssetType.DOMAIN,
                                value=host,
                                source_type=SourceKind.PASSIVE,
                                confidence=55,
                                status=ObservationStatus.OBSERVED,
                                evidence={
                                    "discovery": "reverse IP lookup - other domain hosted on this address",
                                    "address": address,
                                },
                            )
                        )
                    entry["reverse_ip_capped"] = skipped_tail or None
                    if skipped_tail:
                        output.metrics["reverse_ip_truncated"] = (
                            output.metrics.get("reverse_ip_truncated", 0) + skipped_tail
                        )
            per_address.append(entry)

        output.data["addresses"] = per_address
        output.data["distinct_asns"] = sorted(asn_seen.keys())
        output.data["asn_summary"] = list(asn_seen.values())
        output.metrics["addresses_enriched"] = len(per_address)
        return output


def _ptr_observation(address: str, ptr_hostname: str):
    from datetime import datetime

    from app.core.contracts import ObservationRecord
    from app.models.enums import ObservationStatus, SourceKind

    return ObservationRecord(
        source="ripestat",
        asset_type=AssetType.DNS_RECORD,
        value=f"{address} PTR {ptr_hostname}",
        source_type=SourceKind.PASSIVE,
        confidence=85,
        status=ObservationStatus.OBSERVED,
        observed_at=datetime.now(UTC),
        evidence={"discovery": "reverse DNS lookup", "address": address, "ptr": ptr_hostname},
        attributes={"address": address, "ptr": ptr_hostname},
    )
