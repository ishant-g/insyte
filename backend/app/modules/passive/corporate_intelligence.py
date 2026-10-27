"""Corporate Intelligence - corroborated organisation matching only.

There is no reliable way to turn a domain into a legal entity without a
paid, disambiguated corporate registry API, and Insyte does not have one.
What it does have is three free-tier name-search providers that will
happily return a plausible-looking wrong answer for a generic label like
"apple" or "delta".

This module therefore applies a strict evidence bar:

* A candidate becomes a **finding** only when it is corroborated -
  currently that means the Wikidata provider's official-website claim
  (P856) resolves to the scanned domain itself, reported at confidence
  80+. A name match alone is never a finding.
* Everything else is reported as **unverified name-match candidates**,
  explicitly labelled as informational guesses that must not be treated
  as proof of ownership. They stay in `output.data` (report/UI-surfaced)
  and are deliberately kept out of assets and the graph, because an
  `AssetRecord` implies a verified fact.

A guess presented as a finding is worse than no data at all - this module
would rather report one corroborated match than ten plausible ones.
"""

from __future__ import annotations

from app.core.contracts import FindingRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import (
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: Confidence at or above which a candidate counts as corroborated rather
#: than a name-only guess. Today only the Wikidata official-website match
#: reaches this bar.
_VERIFIED_CONFIDENCE = 80


class CorporateIntelligenceModule(IntelligenceModule):
    id = "corporate_intelligence"
    name = "Corporate Intelligence"
    description = (
        "Organisation name matching against OpenCorporates, SEC EDGAR and "
        "Wikidata. Only corroborated matches (e.g. the entity's official "
        "website is the scanned domain) become findings; name-only matches "
        "are reported as explicitly unverified informational candidates."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    dependencies = ("domain_intelligence",)
    providers = ("opencorporates", "sec_edgar", "wikidata")
    timeout = 60.0
    order = 58

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)

        query_used = ctx.target.registrable or ctx.target.value
        registration = ctx.data_of("domain_intelligence", "registration", {}) or {}
        registrant = registration.get("registrant")
        query_from_verified_org = False
        if isinstance(registrant, dict) and not registration.get("registrant_redacted"):
            org_name = registrant.get("org") or registrant.get("fn")
            if org_name:
                query_used = str(org_name)
                query_from_verified_org = True

        observations, statuses = self.gather(ctx, "corporate", value=query_used)
        output.providers.extend(statuses)

        verified: list[dict] = []
        unverified: list[dict] = []
        for observation in observations:
            name = (
                observation.attributes.get("name")
                or observation.attributes.get("matched_name")
                or observation.evidence.get("matched_name")
            )
            corroborated = bool(
                observation.confidence >= _VERIFIED_CONFIDENCE
                or observation.evidence.get("official_website_match")
            )
            candidate = {
                "source": observation.source,
                "name": name,
                "confidence": observation.confidence,
                "url": observation.attributes.get("url")
                or observation.attributes.get("wikidata_url"),
                "verification": (
                    "corroborated"
                    if corroborated
                    else "unverified_name_match"
                ),
                "verification_note": (
                    "Entity's official website resolves to the scanned domain."
                    if corroborated
                    else (
                        "Name similarity only - this is a guess, not proof "
                        "that this organisation owns or operates the target."
                    )
                ),
                "detail": observation.attributes,
            }
            (verified if corroborated else unverified).append(candidate)

        verified.sort(key=lambda c: -c["confidence"])
        unverified.sort(key=lambda c: -c["confidence"])

        for candidate in verified:
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.INFORMATIONAL,
                    severity=Severity.INFORMATIONAL,
                    title=f"Corroborated organisation match: {candidate['name']}",
                    description=(
                        f"{candidate['source']} matched '{candidate['name']}' and the "
                        f"entity's official website resolves to the scanned "
                        f"domain ({candidate['url'] or 'see evidence'}). This is "
                        f"corroborated contextual evidence, not a vulnerability."
                    ),
                    recommendation=(
                        "Useful for scoping and reporting; still confirm "
                        "ownership through an authoritative channel before "
                        "acting on it."
                    ),
                    confidence=candidate["confidence"],
                    exposure=ExposureLevel.INFERRED,
                    sources=[candidate["source"]],
                    evidence={
                        "matched_name": candidate["name"],
                        "verification": "corroborated",
                        "url": candidate["url"],
                    },
                )
            )

        output.data["corporate_intelligence"] = {
            "query_used": query_used,
            "query_from_verified_org": query_from_verified_org,
            "verified_matches": verified,
            "unverified_candidates": unverified,
            "note": (
                "Unverified candidates are name-similarity guesses only. Do "
                "not treat them as proof of ownership."
            ),
        }
        output.metrics["candidates_found"] = len(verified) + len(unverified)
        output.metrics["verified_matches"] = len(verified)
        return output
