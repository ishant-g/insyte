"""RDAP and network-registry providers.

RDAP replaces the WHOIS port-43 protocol with a JSON API over HTTPS. The
predecessor used `python-whois`, which shells out to a `whois` binary that
is usually absent from a slim container and whose output format varies by
registry. RDAP is structured, works over the same SSRF-guarded HTTP client
as everything else, and is what registries actually recommend.

WHOIS-derived privacy redaction is respected rather than worked around: if
a registrar redacts the registrant, Insyte reports it as redacted. Inventing
unavailable information is worse than admitting the gap.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from app.core.contracts import ObservationRecord
from app.core.net import HttpError
from app.core.ratelimit import RateLimit
from app.core.target import normalize_hostname
from app.models.enums import AssetType, SourceKind
from app.providers.base import Provider, ProviderQuery, parse_timestamp


class RdapProvider(Provider):
    id = "rdap"
    name = "RDAP Registration Data"
    kind = SourceKind.PASSIVE
    homepage = "https://about.rdap.org"
    description = (
        "Registration Data Access Protocol. Structured registrar, lifecycle and "
        "nameserver data for domains, and network allocation data for addresses."
    )
    reliability = 96
    requires_api_key = False
    intents = ("registration", "network")
    rate_limit = RateLimit(requests=20, window=60.0, min_interval=0.4, concurrency=2)
    cache_ttl = 43200
    timeout = 25.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        payload = self.fetch_raw(query)
        if not payload:
            return []
        if query.target.is_domain:
            return self._domain_observations(query, payload)
        return self._network_observations(query, payload)

    # -- raw access -------------------------------------------------------
    # The domain module wants the parsed record, not observations, so the
    # raw fetch is exposed separately and shares the same cache entry.

    def fetch_raw(self, query: ProviderQuery) -> dict[str, Any] | None:
        cache_key = self._cache.key("provider", self.id, "raw", query.target.value)
        cached = self._cache.get(cache_key)
        if isinstance(cached, dict):
            self.cache_hits += 1
            return cached

        if query.target.is_domain:
            url = f"https://rdap.org/domain/{query.target.value}"
        else:
            url = f"https://rdap.org/ip/{query.target.value}"

        try:
            payload = self._http_json(url, accept="application/rdap+json, application/json")
        except HttpError as exc:
            # Many ccTLDs have no RDAP service at all. That is a gap in
            # public data, not a failure of the scan.
            if "404" in str(exc):
                self.errors.append("no RDAP record published for this target")
                return None
            raise
        if not isinstance(payload, dict):
            return None
        self._cache.set(cache_key, payload, self.cache_ttl)
        return payload

    # -- parsing ---------------------------------------------------------

    def _domain_observations(
        self, query: ProviderQuery, payload: dict[str, Any]
    ) -> list[ObservationRecord]:
        out: list[ObservationRecord] = []
        events = _events(payload)
        registered = events.get("registration")
        expires = events.get("expiration")

        for entry in payload.get("nameservers") or []:
            if not isinstance(entry, dict):
                continue
            host = normalize_hostname(str(entry.get("ldhName") or ""))
            if not host:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.NAMESERVER,
                    value=host,
                    source_type=SourceKind.PASSIVE,
                    confidence=96,
                    observed_at=registered,
                    first_seen=registered,
                    last_seen=expires,
                    evidence={"discovery": "RDAP nameserver delegation"},
                )
            )
        return out

    def _network_observations(
        self, query: ProviderQuery, payload: dict[str, Any]
    ) -> list[ObservationRecord]:
        out: list[ObservationRecord] = []
        handle = str(payload.get("handle") or "").strip()
        name = str(payload.get("name") or "").strip()
        start = str(payload.get("startAddress") or "").strip()
        end = str(payload.get("endAddress") or "").strip()

        cidrs = []
        for entry in payload.get("cidr0_cidrs") or []:
            if not isinstance(entry, dict):
                continue
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            length = entry.get("length")
            if prefix and length is not None:
                cidrs.append(f"{prefix}/{length}")

        netblock = cidrs[0] if cidrs else (f"{start} - {end}" if start and end else "")
        if netblock:
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.NETBLOCK,
                    value=netblock,
                    source_type=SourceKind.PASSIVE,
                    confidence=95,
                    evidence={"discovery": "RDAP network allocation"},
                    attributes={
                        "handle": handle,
                        "name": name,
                        "country": payload.get("country"),
                        "type": payload.get("type"),
                        "all_cidrs": cidrs,
                    },
                )
            )

        for autnum in payload.get("arin_originas0_originautnums") or []:
            try:
                number = int(autnum)
            except (TypeError, ValueError):
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.ASN,
                    value=f"AS{number}",
                    source_type=SourceKind.PASSIVE,
                    confidence=92,
                    evidence={"discovery": "RDAP origin AS"},
                    attributes={"netblock": netblock},
                )
            )
        return out


class RipeStatProvider(Provider):
    id = "ripestat"
    name = "RIPEstat"
    kind = SourceKind.PASSIVE
    homepage = "https://stat.ripe.net"
    description = (
        "RIPE NCC's public routing and allocation data. Authoritative for the "
        "announced prefix and origin AS of an address, which is the "
        "evidence-based way to attribute hosting rather than guessing from geo."
    )
    reliability = 94
    requires_api_key = False
    intents = ("network", "asn")
    rate_limit = RateLimit(requests=20, window=60.0, min_interval=0.4, concurrency=2)
    cache_ttl = 43200
    timeout = 25.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        address = query.value or (query.target.value if query.target.is_ip else None)
        if not address:
            return []
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return []

        payload = self._http_json(
            "https://stat.ripe.net/data/prefix-overview/data.json"
            f"?resource={address}"
        )
        if not isinstance(payload, dict):
            return []
        data = payload.get("data")
        if not isinstance(data, dict):
            return []

        out: list[ObservationRecord] = []
        prefix = str(data.get("resource") or "").strip()
        holder = str(data.get("block", {}).get("desc") or "").strip()

        if prefix:
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.NETBLOCK,
                    value=prefix,
                    source_type=SourceKind.PASSIVE,
                    confidence=94,
                    evidence={
                        "discovery": "announced prefix covering this address",
                        "address": address,
                    },
                    attributes={"block_description": holder or None},
                )
            )

        for entry in data.get("asns") or []:
            if not isinstance(entry, dict):
                continue
            number = entry.get("asn")
            if number is None:
                continue
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.ASN,
                    value=f"AS{number}",
                    source_type=SourceKind.PASSIVE,
                    confidence=94,
                    evidence={
                        "discovery": "origin AS announcing the covering prefix",
                        "address": address,
                        "prefix": prefix,
                    },
                    attributes={
                        "holder": entry.get("holder"),
                        "prefix": prefix,
                    },
                )
            )
        return out

    def reverse_dns(self, address: str) -> list[str]:
        """PTR records for an address, from RIPEstat's DNS data call."""
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return []
        try:
            payload = self._http_json(
                "https://stat.ripe.net/data/reverse-dns-ip/data.json"
                f"?resource={address}"
            )
        except HttpError:
            return []
        if not isinstance(payload, dict):
            return []
        result = payload.get("data", {}).get("result")
        if isinstance(result, str) and result:
            return [result.strip(".").lower()]
        if isinstance(result, list):
            return [str(item).strip(".").lower() for item in result if item]
        return []


def _events(payload: dict[str, Any]) -> dict[str, Any]:
    """Index an RDAP `events` array by action name."""
    out: dict[str, Any] = {}
    for event in payload.get("events") or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").strip().lower()
        parsed = parse_timestamp(event.get("eventDate"))
        if action and parsed:
            out[action] = parsed
    return out


def parse_rdap_domain(payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce an RDAP domain response to Insyte's domain-intelligence shape.

    Redaction is preserved: a registrar that publishes
    "REDACTED FOR PRIVACY" is reported as redacted, and a missing field is
    reported as unavailable rather than filled with a plausible guess.
    """
    events = _events(payload)
    entities = payload.get("entities") or []

    registrar = None
    registrar_iana = None
    abuse_contact = None
    registrant: dict[str, Any] = {}
    redacted = False

    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in entity.get("roles") or []]
        vcard = _vcard(entity.get("vcardArray"))
        if "registrar" in roles:
            registrar = vcard.get("fn") or entity.get("handle")
            registrar_iana = entity.get("publicIds")
            for nested in entity.get("entities") or []:
                if not isinstance(nested, dict):
                    continue
                if "abuse" in [str(r).lower() for r in nested.get("roles") or []]:
                    nested_card = _vcard(nested.get("vcardArray"))
                    abuse_contact = nested_card.get("email") or nested_card.get("tel")
        if "registrant" in roles:
            registrant = vcard
            joined = " ".join(str(v) for v in vcard.values()).lower()
            if "redacted" in joined or "privacy" in joined or "data protected" in joined:
                redacted = True

    if not registrant:
        redacted = True

    statuses = [str(s) for s in payload.get("status") or []]

    return {
        "domain": str(payload.get("ldhName") or "").lower() or None,
        "handle": payload.get("handle"),
        "registrar": registrar,
        "registrar_ids": registrar_iana,
        "abuse_contact": abuse_contact,
        "registration_date": events.get("registration"),
        "expiration_date": events.get("expiration"),
        "last_changed": events.get("last changed") or events.get("last update of rdap database"),
        "transfer_date": events.get("transfer"),
        "statuses": statuses,
        "nameservers": sorted(
            {
                normalize_hostname(str(ns.get("ldhName") or "")) or ""
                for ns in payload.get("nameservers") or []
                if isinstance(ns, dict)
            }
            - {""}
        ),
        "dnssec_signed": bool(payload.get("secureDNS", {}).get("delegationSigned"))
        if isinstance(payload.get("secureDNS"), dict)
        else None,
        "registrant": registrant or None,
        "registrant_redacted": redacted,
        "source": "rdap",
    }


def _vcard(vcard_array: Any) -> dict[str, str]:
    """Flatten an RDAP jCard into a plain dict."""
    out: dict[str, str] = {}
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return out
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        key = str(entry[0]).lower()
        value = entry[3]
        if isinstance(value, list):
            value = " ".join(str(part) for part in value if part)
        if value:
            out[key] = str(value)[:255]
    return out
