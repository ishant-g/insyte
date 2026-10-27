"""BGP origin lookup via bgp.bortzmeyer.org.

Slot-in replacement for the dead BGPView: announced prefix and origin AS
for an IP address, keyless, from Stephane Bortzmeyer's public BGP looking
glass. Response is plain text with one "<prefix> <asn>" line per match,
verified live 2026-09-27 (api.bgpview.io was NXDOMAIN the same day).
"""

from __future__ import annotations

import ipaddress

from app.models.enums import AssetType, SourceKind
from app.providers.base import ObservationRecord, Provider, ProviderQuery, RateLimit


class BgpOriginProvider(Provider):
    id = "bgp_origin"
    name = "BGP Origin (bortzmeyer.org)"
    kind = SourceKind.PASSIVE
    homepage = "https://bgp.bortzmeyer.org"
    description = (
        "Origin AS and announced prefix for an IP address from a public "
        "BGP looking glass. Keyless fallback used when RIPEstat has no "
        "routing data for an address."
    )
    reliability = 85
    requires_api_key = False
    intents = ("network",)
    rate_limit = RateLimit(requests=20, window=60.0, min_interval=0.5, concurrency=2)
    cache_ttl = 86400
    timeout = 25.0

    def fetch(self, query: ProviderQuery) -> list[ObservationRecord]:
        address = query.value or (query.target.value if query.target.is_ip else None)
        if not address:
            return []
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return []

        text = self._http_text(f"https://bgp.bortzmeyer.org/{address}")
        if not text:
            return []

        out: list[ObservationRecord] = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            prefix_text, asn_text = parts[0], parts[1].lstrip("ASas")
            try:
                network = ipaddress.ip_network(prefix_text, strict=False)
                asn = int(asn_text)
            except ValueError:
                continue
            if parsed not in network:
                continue
            prefix = str(network)
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.NETBLOCK,
                    value=prefix,
                    source_type=SourceKind.PASSIVE,
                    confidence=85,
                    evidence={
                        "discovery": "announced prefix covering this address",
                        "address": address,
                    },
                )
            )
            out.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.ASN,
                    value=f"AS{asn}",
                    source_type=SourceKind.PASSIVE,
                    confidence=85,
                    evidence={
                        "discovery": "origin AS announcing the covering prefix",
                        "address": address,
                        "prefix": prefix,
                    },
                )
            )
            break
        return out
