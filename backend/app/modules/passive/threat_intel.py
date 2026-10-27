"""Threat Intelligence - abuse.ch reputation for the target.

Gathers the `threat_intel` intent from the ThreatFox and URLhaus
providers (both matched locally against keyless bulk exports) and turns
matches into NETWORK_REPUTATION findings. A match means the target
currently appears in circulating threat feeds - shared infrastructure can
carry someone else's reputation, so findings say exactly which feed and
indicator matched rather than declaring the target compromised.
"""

from __future__ import annotations

from app.core.contracts import FindingRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

_MAX_FINDINGS = 20

_HIGH_THREAT_TYPES = {"botnet_cc", "c2", "malware"}


class ThreatIntelligenceModule(IntelligenceModule):
    id = "threat_intelligence"
    name = "Threat Intelligence"
    description = (
        "Checks the target against ThreatFox and URLhaus threat feeds "
        "(matched locally from keyless bulk exports) and flags active "
        "malware, C2 or malicious-URL associations."
    )
    category = ModuleCategory.EXTERNAL
    mode_support = (ScanMode.PASSIVE,)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    providers = ("threatfox", "urlhaus")
    timeout = 90.0
    order = 30

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)

        observations, statuses = self.gather(ctx, "threat_intel", limit=50)
        output.providers.extend(statuses)

        matched = [o for o in observations if o.is_valid]
        output.observations.extend(matched)
        output.data["matches"] = len(matched)
        output.metrics["threat_matches"] = len(matched)

        for observation in matched[:_MAX_FINDINGS]:
            finding = self._to_finding(observation)
            if finding is not None:
                output.findings.append(finding)
        if len(matched) > _MAX_FINDINGS:
            output.data["findings_capped"] = True
        return output

    def _to_finding(self, observation) -> FindingRecord | None:
        evidence = observation.evidence or {}
        if observation.source == "threatfox":
            return self._threatfox_finding(observation, evidence)
        if observation.source == "urlhaus":
            return self._urlhaus_finding(observation, evidence)
        return None

    def _threatfox_finding(self, observation, evidence: dict) -> FindingRecord:
        threat_type = str(evidence.get("threat_type") or "unknown")
        malware = str(evidence.get("malware") or "unknown")
        severity = (
            Severity.HIGH if threat_type in _HIGH_THREAT_TYPES else Severity.MEDIUM
        )
        return FindingRecord(
            module_id=self.id,
            category=FindingCategory.NETWORK_REPUTATION,
            severity=severity,
            title=f"Target flagged in ThreatFox: {malware} ({threat_type})",
            description=(
                f"The indicator {observation.value} appears in the ThreatFox "
                f"recent-IOC feed as {threat_type} linked to {malware}. This "
                "means the target is currently associated with circulating "
                "threat infrastructure - on shared hosting or CDN addresses "
                "the reputation may belong to another tenant."
            ),
            recommendation=(
                "Confirm the indicator is dedicated to the target, then "
                "investigate the flagged host or address for compromise and "
                "check the ThreatFox reference for context."
            ),
            confidence=observation.confidence,
            exposure=ExposureLevel.INFERRED,
            sources=["threatfox"],
            evidence=dict(evidence),
            asset_type=AssetType.EXPOSURE,
            asset_value=observation.value,
        )

    def _urlhaus_finding(self, observation, evidence: dict) -> FindingRecord:
        url_status = str(evidence.get("url_status") or "unknown")
        threat = str(evidence.get("threat") or "malware")
        severity = Severity.MEDIUM if url_status == "online" else Severity.LOW
        return FindingRecord(
            module_id=self.id,
            category=FindingCategory.NETWORK_REPUTATION,
            severity=severity,
            title=f"Malware URL hosted on target (URLhaus): {observation.value[:80]}",
            description=(
                f"URLhaus lists {observation.value} as a {threat} distribution "
                f"URL on this target (status: {url_status}). A live listing "
                "means the host is actively serving or has recently served "
                "malware."
            ),
            recommendation=(
                "Take the URL down, investigate how it got there, and "
                "request delisting from URLhaus once clean."
            ),
            confidence=observation.confidence,
            exposure=ExposureLevel.INFERRED,
            sources=["urlhaus"],
            evidence=dict(evidence),
            asset_type=AssetType.URL,
            asset_value=observation.value,
        )
