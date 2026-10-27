"""DNS Intelligence.

Direct DNS resolution against public resolvers. This sits inside Passive
mode because querying DNS is asking a third party (the resolver) a
question about public records, not interacting with infrastructure the
target operates - the same distinction the brief draws for RDAP and CT
logs.

Every answer is reduced to a `DnsRecordRecord`; type-specific parsing
(SPF terms, DMARC policy, CAA tag/value, SOA fields) lives in `parsed`
rather than being re-derived by every consumer.
"""

from __future__ import annotations

import ipaddress
import json

import dns.exception
import dns.rdatatype
import dns.resolver
import dns.reversename

from app.core.contracts import AssetRecord, DnsRecordRecord, ModuleOutput, ObservationRecord
from app.core.target import TargetType, normalize_hostname
from app.models.enums import AssetType, ModuleCategory, ObservationStatus, ScanMode, SourceKind
from app.modules.base import IntelligenceModule, ModuleContext

#: Public resolvers, queried in order until one answers. Two independent
#: operators so a single resolver outage does not blank a DNS module.
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

#: DNS-over-HTTPS fallback, used only when direct UDP/53 resolution yields
#: nothing at all (egress-filtered networks, captive resolvers). Keyless,
#: via the same SSRF-guarded client every module uses.
_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
#: record type -> DNS numeric type in the DoH JSON "Answer" section.
_DOH_TYPES: tuple[tuple[str, int], ...] = (("A", 1), ("AAAA", 28))

RECORD_TYPES = (
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA",
    "SRV", "NAPTR", "DS", "DNSKEY", "TLSA",
)

_NAMESERVER_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("cloudflare.com", "Cloudflare"),
    ("awsdns", "Amazon Route 53"),
    ("azure-dns", "Azure DNS"),
    ("googledomains.com", "Google Domains"),
    ("google.com", "Google Cloud DNS"),
    ("ns.godaddy.com", "GoDaddy"),
    ("domaincontrol.com", "GoDaddy"),
    ("dnsmadeeasy.com", "DNS Made Easy"),
    ("nsone.net", "NS1"),
    ("digitalocean.com", "DigitalOcean"),
    ("namecheaphosting.com", "Namecheap"),
    ("registrar-servers.com", "Namecheap"),
    ("dynect.net", "Oracle Dyn"),
    ("ultradns", "Neustar UltraDNS"),
    ("akam.net", "Akamai"),
)

_MAIL_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("google.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("zoho.com", "Zoho Mail"),
    ("yandex.net", "Yandex Mail"),
    ("qq.com", "Tencent QQ Mail"),
    ("amazonses.com", "Amazon SES"),
)


def _hint(value: str, table: tuple[tuple[str, str], ...]) -> str | None:
    lowered = value.lower()
    for needle, label in table:
        if needle in lowered:
            return label
    return None


class DnsIntelligenceModule(IntelligenceModule):
    id = "dns_intelligence"
    name = "DNS Intelligence"
    description = (
        "Full DNS record enumeration (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV/"
        "NAPTR/DS/DNSKEY/TLSA) with SPF/DMARC/DNSSEC/wildcard analysis."
    )
    category = ModuleCategory.CORE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    timeout = 45.0
    order = 20

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(RESOLVERS)
        resolver.timeout = 5.0
        resolver.lifetime = 8.0
        return resolver

    def _query(self, resolver: dns.resolver.Resolver, name: str, rtype: str):
        try:
            return resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return None
        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return None

    def _doh_fallback(self, ctx: ModuleContext, name: str) -> list[DnsRecordRecord]:
        """Resolve A/AAAA over HTTPS when direct DNS is unavailable.

        Limited to address records on purpose: the goal is keeping the
        IP/ASN/cloud chain alive, not replicating full enumeration over a
        fallback path. Never raises - an empty list just means the
        fallback failed too.
        """
        out: list[DnsRecordRecord] = []
        for rtype, qtype in _DOH_TYPES:
            ctx.check_cancelled()
            response = ctx.http.try_get(
                f"{_DOH_ENDPOINT}?name={name}&type={rtype}",
                accept="application/dns-json",
            )
            if response is None or not response.ok:
                continue
            try:
                payload = json.loads(response.text)
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            for answer in payload.get("Answer", []) or []:
                if not isinstance(answer, dict) or answer.get("type") != qtype:
                    continue
                value = str(answer.get("data", "")).strip().rstrip(".")
                if not value:
                    continue
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                out.append(
                    DnsRecordRecord(
                        name=name,
                        record_type=rtype,
                        value=value,
                        ttl=answer.get("TTL"),
                        resolver="doh:cloudflare-dns.com",
                        parsed={"fallback": "dns_over_https"},
                    )
                )
        return out

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target = ctx.target
        name = target.value
        resolver = self._resolver()

        records: list[DnsRecordRecord] = []
        resolved_ips: list[str] = []
        cname_target: str | None = None
        nameservers: list[str] = []
        mail_servers: list[str] = []
        txt_values: list[str] = []
        dnssec_signed = False

        for rtype in RECORD_TYPES:
            ctx.check_cancelled()
            answer = self._query(resolver, name, rtype)
            if answer is None:
                continue
            for rdata in answer:
                record = self._to_record(name, rtype, rdata, answer.rrset.ttl if answer.rrset else None)
                if record is None:
                    continue
                records.append(record)
                if rtype in ("A", "AAAA"):
                    resolved_ips.append(record.value)
                elif rtype == "CNAME":
                    cname_target = record.value
                elif rtype == "NS":
                    nameservers.append(record.value)
                    hint = _hint(record.value, _NAMESERVER_PROVIDERS)
                    if hint:
                        record.provider_hint = {"provider": hint, "kind": "dns"}
                elif rtype == "MX":
                    # RFC 7505 "null MX" (priority 0, target ".") declares
                    # the domain accepts no mail at all - not a mail server.
                    if record.value:
                        mail_servers.append(record.value)
                        hint = _hint(record.value, _MAIL_PROVIDERS)
                        if hint:
                            record.provider_hint = {"provider": hint, "kind": "mail"}
                elif rtype == "TXT":
                    txt_values.append(record.value)
                elif rtype in ("DS", "DNSKEY"):
                    dnssec_signed = True

        output.dns_records.extend(records)

        # Total DNS failure (not NXDOMAIN - that returns per-type Nones that
        # still leave `records` empty too, and DoH will agree with it) most
        # often means UDP/53 egress is blocked. DNS-over-HTTPS keeps the
        # A/AAAA chain - and everything downstream of it (IP/ASN, cloud
        # detection) - alive. Records from this path are attributed
        # "dns_doh" so the report is honest about provenance.
        if not records:
            ctx.event(
                self.id,
                "dns_doh_fallback",
                "Direct DNS resolution yielded no records; trying DNS-over-HTTPS",
                level="WARNING",
            )
            for record in self._doh_fallback(ctx, name):
                records.append(record)
                output.dns_records.append(record)
                if record.record_type in ("A", "AAAA"):
                    resolved_ips.append(record.value)

        # Wildcard DNS: a random label under this name that still resolves.
        wildcard = self._check_wildcard(resolver, name)
        output.data["wildcard_dns"] = wildcard

        spf = _parse_spf(txt_values)
        dmarc = self._fetch_dmarc(resolver, name)
        output.data["email_security"] = {
            "spf": spf,
            "dmarc": dmarc,
            "dnssec_signed": dnssec_signed,
            "accepts_mail": bool(mail_servers),
            "mail_providers": sorted({_hint(m, _MAIL_PROVIDERS) or m for m in mail_servers}),
        }
        output.data["nameserver_providers"] = sorted(
            {_hint(n, _NAMESERVER_PROVIDERS) for n in nameservers if _hint(n, _NAMESERVER_PROVIDERS)}
        )
        output.data["cname_target"] = cname_target
        output.data["record_counts"] = {
            rtype: sum(1 for r in records if r.record_type == rtype)
            for rtype in RECORD_TYPES
            if any(r.record_type == rtype for r in records)
        }

        # Emit assets for resolved IPs and NS/MX hosts, and observations for
        # any CNAME target so the correlation stage can chain to it.
        for ip in sorted(set(resolved_ips)):
            output.assets.append(
                AssetRecord(
                    asset_type=AssetType.IP,
                    value=ip,
                    confidence=98,
                    sources=["dns"],
                    evidence={"discovery": f"A/AAAA record for {name}"},
                )
            )
        for ns in sorted(set(nameservers)):
            host = normalize_hostname(ns)
            if host:
                output.assets.append(
                    AssetRecord(
                        asset_type=AssetType.NAMESERVER,
                        value=host,
                        confidence=95,
                        sources=["dns"],
                    )
                )
        for mx in sorted(set(mail_servers)):
            host = normalize_hostname(mx)
            if host:
                output.assets.append(
                    AssetRecord(
                        asset_type=AssetType.MAIL_SERVER,
                        value=host,
                        confidence=95,
                        sources=["dns"],
                    )
                )
        if cname_target:
            host = normalize_hostname(cname_target)
            if host:
                output.observations.append(
                    ObservationRecord(
                        source="dns",
                        asset_type=AssetType.DOMAIN,
                        value=host,
                        source_type=SourceKind.PASSIVE,
                        confidence=90,
                        status=ObservationStatus.OBSERVED,
                        evidence={"discovery": f"CNAME target of {name}"},
                    )
                )

        output.metrics["record_count"] = len(records)
        return output

    def _to_record(self, name: str, rtype: str, rdata, ttl: int | None) -> DnsRecordRecord | None:
        try:
            text = rdata.to_text()
        except Exception:  # noqa: BLE001 - a malformed rdata is not fatal
            return None

        parsed: dict = {}
        value = text
        priority = None

        if rtype in ("MX",):
            parts = text.split(None, 1)
            if len(parts) == 2:
                priority = _safe_int(parts[0])
                value = parts[1].rstrip(".")
        elif rtype in ("NS", "CNAME"):
            value = text.rstrip(".")
        elif rtype == "SOA":
            fields = text.split()
            if len(fields) >= 7:
                parsed = {
                    "mname": fields[0].rstrip("."),
                    "rname": fields[1].rstrip("."),
                    "serial": _safe_int(fields[2]),
                    "refresh": _safe_int(fields[3]),
                    "retry": _safe_int(fields[4]),
                    "expire": _safe_int(fields[5]),
                    "minimum": _safe_int(fields[6]),
                }
        elif rtype == "CAA":
            fields = text.split(None, 2)
            if len(fields) == 3:
                parsed = {
                    "flags": _safe_int(fields[0]),
                    "tag": fields[1],
                    "value": fields[2].strip('"'),
                }
        elif rtype == "SRV":
            fields = text.split()
            if len(fields) == 4:
                parsed = {
                    "priority": _safe_int(fields[0]),
                    "weight": _safe_int(fields[1]),
                    "port": _safe_int(fields[2]),
                    "target": fields[3].rstrip("."),
                }
        elif rtype == "NAPTR":
            fields = text.split(None, 5)
            if len(fields) == 6:
                parsed = {
                    "order": _safe_int(fields[0]),
                    "preference": _safe_int(fields[1]),
                    "flags": fields[2].strip('"'),
                    "service": fields[3].strip('"'),
                    "regexp": fields[4].strip('"'),
                    "replacement": fields[5].rstrip("."),
                }
        elif rtype == "TXT":
            value = text.strip('"').replace('" "', "")
        elif rtype in ("A", "AAAA"):
            try:
                value = str(ipaddress.ip_address(text))
            except ValueError:
                return None

        return DnsRecordRecord(
            name=name,
            record_type=rtype,
            value=value,
            ttl=ttl,
            priority=priority,
            parsed=parsed,
        )

    def _check_wildcard(self, resolver: dns.resolver.Resolver, name: str) -> bool:
        import secrets

        probe = f"insyte-wildcard-check-{secrets.token_hex(6)}.{name}"
        answer = self._query(resolver, probe, "A")
        if answer is not None:
            return True
        return self._query(resolver, probe, "AAAA") is not None

    def _fetch_dmarc(self, resolver: dns.resolver.Resolver, name: str) -> dict:
        answer = self._query(resolver, f"_dmarc.{name}", "TXT")
        if answer is None:
            return {"present": False}
        for rdata in answer:
            text = rdata.to_text().strip('"').replace('" "', "")
            if text.lower().startswith("v=dmarc1"):
                return {"present": True, **_parse_dmarc(text)}
        return {"present": False}


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_spf(txt_values: list[str]) -> dict:
    spf_records = [v for v in txt_values if v.lower().startswith("v=spf1")]
    if not spf_records:
        return {"present": False}
    record = spf_records[0]
    terms = record.split()[1:]
    mechanisms = [t for t in terms if not t.startswith(("redirect=", "exp="))]
    qualifier = "neutral"
    for term in reversed(mechanisms):
        if term in ("-all", "~all", "?all", "+all"):
            qualifier = {"-all": "fail", "~all": "softfail", "?all": "neutral", "+all": "pass"}[term]
            break
    return {
        "present": True,
        "record": record,
        "mechanisms": mechanisms,
        "all_qualifier": qualifier,
        "multiple_records": len(spf_records) > 1,
    }


def _parse_dmarc(record: str) -> dict:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return {
        "record": record,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "percentage": _safe_int(tags.get("pct", "")) if tags.get("pct") else None,
        "reporting_uri_aggregate": tags.get("rua"),
        "reporting_uri_forensic": tags.get("ruf"),
        "alignment_spf": tags.get("aspf", "r"),
        "alignment_dkim": tags.get("adkim", "r"),
    }
