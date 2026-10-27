"""Email OSINT - harvested addresses and their known-breach history.

Three sources feed the harvest, in order of trust: Hunter.io's domain
search (already domain-scoped by construction), emails
`javascript_intelligence` already regex-extracted from retrieved JS (Web
Surface mode only), and a non-redacted RDAP abuse/registrant contact.
Anything not ending in the target's own registrable domain is dropped
unless Hunter itself vouched for it as domain-scoped - a JS-extracted
`someone@gmail.com` is noise, not a finding.

Have I Been Pwned is then consulted, if configured, for each harvested
email. This is the one deliberate ethical boundary of the whole feature:
HIBP's API returns breach *metadata only* - a breach's name, date, and
which categories of data it exposed ("email addresses, passwords") - and
never an actual password or credential value. There is no code path in
this module, or in `providers.osint.HibpProvider`, that could display one
even if HIBP's API somehow returned it, because HIBP's API does not have
one. Insyte never queries DeHashed, LeakCheck, IntelX or any other service
built around raw leaked-credential search; that line is intentional.

HIBP's authenticated tier is rate-limited, so a scan that harvested many
emails does not chase all of them: `MAX_EMAILS_CHECKED_FOR_BREACHES` caps
the per-scan lookup count, and the module says so in its output rather
than silently truncating.
"""

from __future__ import annotations

from typing import Any

from app.core.contracts import AssetRecord, FindingRecord, ModuleOutput
from app.core.target import TargetType, is_subdomain_of
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext
from app.providers import get_provider


class EmailOsintModule(IntelligenceModule):
    id = "email_osint"
    name = "Email OSINT"
    description = (
        "Harvests in-scope email addresses from Hunter.io, JavaScript "
        "extraction and RDAP contacts, and checks each against Have I Been "
        "Pwned's breach-metadata database - never passwords, only which "
        "named breaches an address appears in. "
        "Requires at least one configured API key (Hunter.io and/or HIBP); "
        "without keys the module skips with a clear reason instead of "
        "reporting an empty success."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    dependencies = ()
    providers = ("hunterio", "hibp")
    #: Both live providers are credential-gated and the remaining sources
    #: (JS extraction, RDAP contacts) are opportunistic at best - RDAP
    #: contacts are redacted for most domains and the JS path only exists
    #: in Web Surface mode. Without at least one configured key this module
    #: cannot do its job, so it skips visibly with a reason instead of
    #: completing with zero records and a misleading green checkmark.
    requires_api_key = True
    timeout = 60.0
    order = 46

    #: HIBP's authenticated tier is rate-limited (conservatively assumed
    #: ~10 req/min here - see `providers.osint.HibpProvider.rate_limit`).
    #: A scan that harvested 200 emails making 200 sequential lookups would
    #: be both slow and a poor use of a paid quota, so only the first N
    #: (alphabetically, for reproducibility) get a per-email check.
    MAX_EMAILS_CHECKED_FOR_BREACHES = 15

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target = ctx.target
        domain = target.registrable or target.value

        candidates: dict[str, dict[str, Any]] = {}

        def add(value: str, source: str, confidence: int, *, domain_scoped: bool = False) -> None:
            value = value.strip().lower()
            if not value or "@" not in value:
                return
            entry = candidates.setdefault(
                value, {"sources": set(), "confidence": 0, "domain_scoped": False}
            )
            entry["sources"].add(source)
            entry["confidence"] = max(entry["confidence"], confidence)
            entry["domain_scoped"] = entry["domain_scoped"] or domain_scoped

        email_pattern: str | None = None
        hunter_observations, hunter_statuses = self.gather(ctx, "emails", limit=100)
        output.providers.extend(hunter_statuses)
        for observation in hunter_observations:
            if observation.asset_type is not AssetType.EMAIL:
                continue
            add(
                observation.value,
                observation.source,
                observation.confidence,
                domain_scoped=bool(observation.attributes.get("domain_scoped")),
            )
            if email_pattern is None:
                email_pattern = observation.attributes.get("email_pattern")

        # Web Surface only - `javascript_intelligence` does not run in
        # Passive mode, so this is naturally absent there.
        js_output = ctx.output_of("javascript_intelligence")
        if js_output is not None:
            for record in js_output.javascript:
                for value in record.emails:
                    add(value, "javascript_intelligence", 55)

        # Soft dependency: `dependencies=()` so a wave-scheduling miss just
        # means this source contributes nothing, not a module failure.
        registration = ctx.data_of("domain_intelligence", "registration", {}) or {}
        if registration.get("available") and not registration.get("registrant_redacted"):
            abuse_contact = registration.get("abuse_contact")
            if abuse_contact and "@" in str(abuse_contact):
                add(str(abuse_contact), "rdap", 70)

        harvested: dict[str, dict[str, Any]] = {}
        for email, info in candidates.items():
            email_domain = email.rsplit("@", 1)[-1]
            if not info["domain_scoped"] and not is_subdomain_of(email_domain, domain):
                continue
            harvested[email] = info

        for email, info in sorted(harvested.items()):
            output.assets.append(
                AssetRecord(
                    asset_type=AssetType.EMAIL,
                    value=email,
                    confidence=info["confidence"],
                    sources=sorted(info["sources"]),
                    evidence={"discovery": "email OSINT harvest"},
                )
            )

        emails_checked = 0
        capped = len(harvested) > self.MAX_EMAILS_CHECKED_FOR_BREACHES
        hibp = get_provider("hibp")
        if hibp is not None and hibp.unavailable_reason() is None:
            checklist = sorted(harvested)[: self.MAX_EMAILS_CHECKED_FOR_BREACHES]
            for email in checklist:
                ctx.check_cancelled()
                breaches = hibp.breaches_for_email(email)
                emails_checked += 1
                if not breaches:
                    continue
                data_classes = sorted(
                    {dc for breach in breaches for dc in breach.get("data_classes") or []}
                )
                breach_summary = ", ".join(
                    f"{b.get('title') or b.get('name') or 'unnamed breach'} "
                    f"({b.get('breach_date') or 'date unknown'})"
                    for b in breaches
                )
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.EMAIL_SECURITY,
                        # A breach hit on a harvested corporate email is
                        # common and expected, not itself a critical
                        # failure - HIGH is reserved for something Insyte
                        # can show is actually, currently exploitable.
                        severity=Severity.MEDIUM,
                        title=f"{email} appears in {len(breaches)} known data breach(es)",
                        description=(
                            f"Have I Been Pwned lists {email} in: {breach_summary}. "
                            "Only breach metadata is reported here - names, dates "
                            "and exposed data categories. HIBP's API does not "
                            "return, and Insyte never displays, actual passwords "
                            "or other credential values."
                        ),
                        recommendation=(
                            "Confirm the account owner has rotated any credentials "
                            "reused since these breaches and has multi-factor "
                            "authentication enabled."
                        ),
                        location=email,
                        # Authoritative breach-database hit, not a
                        # heuristic - high confidence is warranted.
                        confidence=90,
                        exposure=ExposureLevel.DIRECT,
                        sources=["hibp"],
                        evidence={
                            "breaches": breaches,
                            "data_classes_exposed": data_classes,
                        },
                        asset_type=AssetType.EMAIL,
                        asset_value=email,
                    )
                )
            output.providers.append(hibp.status_snapshot(result_count=emails_checked))

            domain_breaches = hibp.domain_breaches(domain)
            if domain_breaches is not None:
                output.data["domain_breaches"] = {
                    "alias_count": len(domain_breaches),
                    "breach_names": sorted(
                        {name for names in domain_breaches.values() for name in names}
                    ),
                }
            else:
                output.data["domain_breaches"] = None
        else:
            capped = False
            output.data["domain_breaches"] = None

        if email_pattern:
            output.data["email_pattern"] = email_pattern

        output.data["emails_checked_for_breaches"] = emails_checked
        output.data["emails_capped"] = capped
        output.data["summary"] = {
            "emails_harvested": len(harvested),
            "emails_checked_for_breaches": emails_checked,
            "emails_capped": capped,
        }
        return output
