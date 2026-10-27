"""Domain Intelligence - registration, lifecycle and registrar data.

Built on RDAP (see `providers/registration.py`) rather than the predecessor's
`python-whois`, which shells out to a `whois` binary that is often absent
from a container and whose text format varies by registry. Privacy
redaction is reported as redaction, not filled in with a guess.
"""

from __future__ import annotations

from datetime import UTC

from app.core.contracts import AssetRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import AssetType, ModuleCategory, ObservationStatus, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext
from app.providers import get_provider, parse_rdap_domain


class DomainIntelligenceModule(IntelligenceModule):
    id = "domain_intelligence"
    name = "Domain Intelligence"
    description = (
        "Registrable domain, TLD, registrar, registration lifecycle and "
        "nameserver delegation via RDAP."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    providers = ("rdap",)
    timeout = 30.0
    order = 10

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target = ctx.target

        output.assets.append(
            AssetRecord(
                asset_type=AssetType.DOMAIN,
                value=target.value,
                confidence=100,
                sources=["insyte"],
                is_target=True,
                status=ObservationStatus.CURRENT_OBSERVATION,
                attributes={
                    "registrable_domain": target.registrable,
                    "public_suffix": target.suffix,
                    "tld": target.tld,
                    "subdomain": target.subdomain,
                    "is_apex": target.is_apex,
                    "unicode": target.unicode_value,
                },
            )
        )

        provider = get_provider("rdap")
        if provider is None:
            output.data["registration"] = {"available": False}
            return output

        from app.providers import ProviderQuery

        raw = provider.fetch_raw(ProviderQuery(target=target, intent="registration"))
        status = provider.status_snapshot(result_count=1 if raw else 0)
        output.providers.append(status)

        if raw is None:
            output.data["registration"] = {
                "available": False,
                "reason": status.reason or "no RDAP record published for this registry",
            }
            ctx.event(
                self.id,
                "no_rdap_record",
                status.reason or "RDAP lookup returned nothing",
            )
            return output

        record = parse_rdap_domain(raw)
        record["available"] = True
        output.data["registration"] = _jsonable(record)

        for ns in record.get("nameservers") or []:
            output.assets.append(
                AssetRecord(
                    asset_type=AssetType.NAMESERVER,
                    value=ns,
                    confidence=95,
                    sources=["rdap"],
                    evidence={"discovery": "RDAP nameserver delegation"},
                )
            )

        age_days = None
        reg_date = record.get("registration_date")
        if reg_date is not None:
            from datetime import datetime

            age_days = (datetime.now(UTC) - reg_date).days
        output.data["domain_age_days"] = age_days

        output.metrics["rdap_calls"] = provider.calls
        return output


def _jsonable(record: dict) -> dict:
    """Render datetimes to ISO strings for the JSONB `data` column."""
    out = {}
    for key, value in record.items():
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out
