"""Email Security Intelligence.

Turns the raw SPF/DMARC/DNSSEC data `dns_intelligence` already collected
into graded findings. Kept as a separate module (rather than folding
finding-generation into the DNS module) because the brief lists email
security as its own intelligence category with its own MTA-STS/TLS-RPT/BIMI
checks, and because a user selecting "recommended modules" should see it as
a distinct, individually-selectable item.
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


class EmailSecurityModule(IntelligenceModule):
    id = "email_security"
    name = "Email Security Intelligence"
    description = (
        "Grades SPF, DMARC, DNSSEC, MTA-STS, TLS-RPT and BIMI posture from "
        "the records dns_intelligence already collected."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    dependencies = ("dns_intelligence",)
    timeout = 20.0
    order = 21

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        posture = ctx.data_of("dns_intelligence", "email_security", {}) or {}
        spf = posture.get("spf", {})
        dmarc = posture.get("dmarc", {})
        dnssec = bool(posture.get("dnssec_signed"))
        accepts_mail = bool(posture.get("accepts_mail"))
        domain = ctx.target.value

        mta_sts = self._resolve_txt(f"_mta-sts.{domain}")
        tls_rpt = self._resolve_txt(f"_smtp._tls.{domain}")
        bimi = self._resolve_txt(f"default._bimi.{domain}")

        if accepts_mail:
            if not spf.get("present"):
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.EMAIL_SECURITY,
                        severity=Severity.MEDIUM,
                        title="No SPF record published",
                        description=(
                            f"{domain} accepts mail but publishes no SPF record, "
                            "so receivers have no authorized-sender list to check "
                            "against for this domain."
                        ),
                        recommendation="Publish an SPF TXT record ending in -all.",
                        location=domain,
                        confidence=95,
                        exposure=ExposureLevel.DIRECT,
                        sources=["dns"],
                    )
                )
            elif spf.get("all_qualifier") in ("neutral", "pass"):
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.EMAIL_SECURITY,
                        severity=Severity.MEDIUM,
                        title="SPF record does not enforce a strict fail policy",
                        description=(
                            f"The SPF record's 'all' mechanism is '{spf.get('all_qualifier')}', "
                            "which does not instruct receivers to reject unauthorized senders."
                        ),
                        recommendation="Change the SPF 'all' mechanism to -all (hard fail).",
                        location=domain,
                        confidence=90,
                        exposure=ExposureLevel.DIRECT,
                        sources=["dns"],
                        evidence={"record": spf.get("record")},
                    )
                )
            if spf.get("multiple_records"):
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.DNS_CONFIGURATION,
                        severity=Severity.LOW,
                        title="Multiple SPF records published",
                        description=(
                            "RFC 7208 requires exactly one SPF record; multiple "
                            "records cause SPF evaluation to fail (permerror) for "
                            "all mail from this domain."
                        ),
                        recommendation="Consolidate into a single SPF TXT record.",
                        location=domain,
                        confidence=92,
                        exposure=ExposureLevel.DIRECT,
                        sources=["dns"],
                    )
                )

            if not dmarc.get("present"):
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.EMAIL_SECURITY,
                        severity=Severity.MEDIUM,
                        title="No DMARC record published",
                        description=(
                            f"{domain} accepts mail but publishes no DMARC policy, "
                            "so spoofed mail claiming to be from this domain is not "
                            "consistently rejected or quarantined by receivers."
                        ),
                        recommendation=(
                            "Publish a DMARC TXT record at _dmarc; start with "
                            "p=quarantine while monitoring reports, then move to "
                            "p=reject."
                        ),
                        location=domain,
                        confidence=95,
                        exposure=ExposureLevel.DIRECT,
                        sources=["dns"],
                    )
                )
            elif dmarc.get("policy") == "none":
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.EMAIL_SECURITY,
                        severity=Severity.LOW,
                        title="DMARC policy is monitor-only (p=none)",
                        description=(
                            "The published DMARC policy takes no action on mail "
                            "that fails alignment; it only requests reports."
                        ),
                        recommendation="Move the DMARC policy to p=quarantine or p=reject once reports look clean.",
                        location=domain,
                        confidence=93,
                        exposure=ExposureLevel.DIRECT,
                        sources=["dns"],
                        evidence={"record": dmarc.get("record")},
                    )
                )

        if not dnssec:
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.DNS_CONFIGURATION,
                    severity=Severity.INFORMATIONAL,
                    title="DNSSEC is not enabled",
                    description=(
                        f"{domain} has no DS/DNSKEY records, so its DNS "
                        "responses are not cryptographically signed."
                    ),
                    recommendation="Enable DNSSEC signing at the registrar and nameservers.",
                    location=domain,
                    confidence=90,
                    exposure=ExposureLevel.DIRECT,
                    sources=["dns"],
                )
            )

        output.data["posture"] = {
            "spf": spf,
            "dmarc": dmarc,
            "dnssec_signed": dnssec,
            "accepts_mail": accepts_mail,
            "mta_sts": {"present": mta_sts is not None, "record": mta_sts},
            "tls_rpt": {"present": tls_rpt is not None, "record": tls_rpt},
            "bimi": {"present": bimi is not None, "record": bimi},
            "mail_providers": posture.get("mail_providers", []),
        }
        return output

    def _resolve_txt(self, name: str) -> str | None:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.timeout = 4.0
        resolver.lifetime = 6.0
        try:
            answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return None
        if answer is None:
            return None
        for rdata in answer:
            text = rdata.to_text().strip('"').replace('" "', "")
            if text:
                return text
        return None
