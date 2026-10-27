"""Certificate Intelligence.

Combines a live TLS handshake (SSRF-guarded, one connection to the target
itself - this is the one Passive-mode module that touches the target
directly, because reading the certificate a server presents is
indistinguishable from a normal TLS client connecting to it, and the
predecessor project treated it the same way) with Certificate Transparency
log correlation from `providers/ct.py`.

Every SAN observed - live or historical - becomes a `CERTIFICATE_COVERS`
relationship candidate and a subdomain observation, which is what makes
certificates one of the highest-yield sources for subdomain discovery.
"""

from __future__ import annotations

from app.core.contracts import CertificateRecord, ModuleOutput, ObservationRecord
from app.core.net.ssrf import SSRFBlocked
from app.core.net.tls import TlsError, describe_certificate, fetch_certificate
from app.core.target import TargetType, is_subdomain_of, normalize_hostname
from app.models.enums import AssetType, ModuleCategory, ObservationStatus, ScanMode, SourceKind
from app.modules.base import IntelligenceModule, ModuleContext


class CertificateIntelligenceModule(IntelligenceModule):
    id = "certificate_intelligence"
    name = "Certificate Intelligence"
    description = (
        "Live TLS certificate handshake plus Certificate Transparency log "
        "correlation: issuer, validity, key strength and every SAN observed."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    providers = ("crtsh", "certspotter")
    timeout = 60.0
    order = 30

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target = ctx.target
        domain = target.registrable or target.value

        live_sans: set[str] = set()
        live = self._fetch_live(ctx, output, target.value)
        if live is not None:
            live_sans = set(live.sans)

        ct_hosts: set[str] = set()
        observations, statuses = self.gather(ctx, "certificates", limit=ctx.limits.max_subdomains)
        output.providers.extend(statuses)

        for observation in observations:
            host = observation.value
            if host not in ct_hosts:
                ct_hosts.add(host)
            output.observations.append(observation)

        all_sans = live_sans | ct_hosts
        for raw in sorted(all_sans):
            host = normalize_hostname(raw.removeprefix("*."))
            if not host or not is_subdomain_of(host, domain):
                continue
            output.observations.append(
                ObservationRecord(
                    source="tls" if raw in live_sans else "certificate_transparency",
                    asset_type=(
                        AssetType.DOMAIN if host == target.value else AssetType.SUBDOMAIN
                    ),
                    value=host,
                    source_type=SourceKind.PASSIVE,
                    confidence=94 if raw in live_sans else 88,
                    status=ObservationStatus.OBSERVED,
                    evidence={
                        "discovery": (
                            "SAN on the live-served certificate"
                            if raw in live_sans
                            else "SAN on a certificate logged in Certificate Transparency"
                        ),
                    },
                )
            )

        output.data["san_summary"] = {
            "total_unique_sans": len(all_sans),
            "in_scope_sans": sorted(
                h for h in all_sans if is_subdomain_of(h.removeprefix("*."), domain)
            )[:200],
            "certificate_transparency_entries": len(ct_hosts),
        }
        # CT-logged hostnames never carried full certificate details, so
        # they never became CertificateRecords and the report's Certificates
        # section stayed empty even when CT found real subdomains. Emit one
        # aggregate record for the CT coverage so the report shows what was
        # actually observed. No fingerprint is fabricated: fingerprint stays
        # None and the record is flagged from_ct_log.
        ct_in_scope = sorted(
            h for h in ct_hosts if is_subdomain_of(h.removeprefix("*."), domain)
        )
        if ct_in_scope:
            output.certificates.append(
                CertificateRecord(
                    sans=ct_in_scope,
                    ct_logged=True,
                    ct_entries=[
                        {"source": s.provider, "host_count": len(ct_hosts)}
                        for s in statuses
                        if s.available
                    ],
                    from_ct_log=True,
                    confidence=88,
                    sources=sorted({s.provider for s in statuses if s.available}),
                    evidence={
                        "discovery": (
                            "Hostnames observed on certificates logged in "
                            "Certificate Transparency; full certificate details "
                            "were not retrieved, so fingerprint and validity "
                            "are unavailable for this record."
                        ),
                    },
                )
            )
        output.metrics["certificates_found"] = len(output.certificates)
        return output

    def _fetch_live(
        self, ctx: ModuleContext, output: ModuleOutput, hostname: str
    ) -> CertificateRecord | None:
        try:
            handshake = fetch_certificate(hostname, timeout=10.0)
        except SSRFBlocked as exc:
            ctx.event(self.id, "tls_blocked", exc.reason, level="WARNING")
            output.errors.append(f"TLS handshake refused by policy: {exc.reason}")
            return None
        except TlsError as exc:
            ctx.event(
                self.id, "tls_unavailable", str(exc), level="INFO"
            )
            output.data["live_certificate"] = {"available": False, "reason": str(exc)}
            return None

        parsed = describe_certificate(handshake.certificate)
        record = CertificateRecord(
            fingerprint_sha256=parsed["fingerprint_sha256"],
            serial_number=parsed["serial_number"],
            subject_cn=parsed["subject_cn"],
            subject=parsed["subject"],
            issuer_cn=parsed["issuer_cn"],
            issuer_org=parsed["issuer_org"],
            issuer=parsed["issuer"],
            sans=parsed["sans"],
            not_before=parsed["not_before"],
            not_after=parsed["not_after"],
            signature_algorithm=parsed["signature_algorithm"],
            public_key_algorithm=parsed["public_key_algorithm"],
            public_key_size=parsed["public_key_size"],
            tls_version=handshake.tls_version,
            from_ct_log=False,
            confidence=99,
            sources=["tls"],
            evidence={"remote_address": handshake.remote_address},
        )
        output.certificates.append(record)
        output.data["live_certificate"] = {
            "available": True,
            "fingerprint_sha256": parsed["fingerprint_sha256"],
            "subject_cn": parsed["subject_cn"],
            "issuer_cn": parsed["issuer_cn"],
            "issuer_org": parsed["issuer_org"],
            "not_before": parsed["not_before"].isoformat() if parsed["not_before"] else None,
            "not_after": parsed["not_after"].isoformat() if parsed["not_after"] else None,
            "is_expired": parsed["is_expired"],
            "days_until_expiry": parsed["days_until_expiry"],
            "signature_algorithm": parsed["signature_algorithm"],
            "public_key_algorithm": parsed["public_key_algorithm"],
            "public_key_size": parsed["public_key_size"],
            "tls_version": handshake.tls_version,
            "san_count": parsed["san_count"],
            "has_wildcard": parsed["has_wildcard"],
        }
        return record
