"""Historical Web Intelligence.

Turns the raw archive observations `wayback`, `commoncrawl` and `urlscan`
already know how to fetch into a timeline: what did the public Internet
see on this target, and when. This is the module that makes the retired
API version and the subdomain that no longer resolves visible, rather than
leaving them buried inside three separate providers' observation lists.

Every event here is `ObservationStatus.HISTORICAL` - evidence that a URL or
host existed at some point, never a claim that it exists now. A subdomain
this module finds that is not in `ctx.known_hosts()` is flagged as a
historical-only discovery specifically so the report can say "this stopped
resolving" rather than implying it is part of the live attack surface.
"""

from __future__ import annotations

from app.core.contracts import HistoricalEventRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import AssetType, ModuleCategory, ObservationStatus, ScanMode
from app.modules.base import IntelligenceModule, ModuleContext

#: Report readability cap - a busy target can have tens of thousands of
#: archived URLs in a single year, and a report section is not the place
#: to enumerate all of them.
_MAX_PER_YEAR = 50


class HistoricalIntelligenceModule(IntelligenceModule):
    id = "historical_intelligence"
    name = "Historical Web Intelligence"
    description = (
        "Reconstructs a timeline of the target's public web presence from "
        "the Wayback Machine, Common Crawl and URLScan - historical URLs "
        "and hosts that a live crawl would never see."
    )
    category = ModuleCategory.HISTORICAL
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN,)
    providers = ("wayback", "commoncrawl", "urlscan")
    timeout = 90.0
    order = 45

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)

        url_observations, url_statuses = self.gather(ctx, "urls", limit=ctx.limits.max_historical_urls)
        output.providers.extend(url_statuses)

        subdomain_observations, subdomain_statuses = self.gather(
            ctx, "subdomains", limit=ctx.limits.max_subdomains
        )
        output.providers.extend(subdomain_statuses)

        known_hosts = set(ctx.known_hosts())
        events: list[HistoricalEventRecord] = []
        by_source: dict[str, int] = {}

        for observation in url_observations:
            if observation.asset_type is not AssetType.URL:
                continue
            events.append(
                HistoricalEventRecord(
                    asset_type=AssetType.URL,
                    value=observation.value,
                    source=observation.source,
                    status=ObservationStatus.HISTORICAL,
                    observed_at=observation.observed_at,
                    first_seen=observation.first_seen,
                    last_seen=observation.last_seen,
                    attributes=observation.evidence,
                )
            )
            by_source[observation.source] = by_source.get(observation.source, 0) + 1

        new_hosts_seen: set[str] = set()
        for observation in subdomain_observations:
            if observation.asset_type not in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                continue
            host = observation.normalized
            if not host or host in known_hosts or host in new_hosts_seen:
                continue
            new_hosts_seen.add(host)
            events.append(
                HistoricalEventRecord(
                    asset_type=observation.asset_type,
                    value=host,
                    source=observation.source,
                    status=ObservationStatus.HISTORICAL,
                    observed_at=observation.observed_at,
                    first_seen=observation.first_seen,
                    last_seen=observation.last_seen,
                    attributes={**observation.evidence, "historical_only_discovery": True},
                )
            )
            by_source[observation.source] = by_source.get(observation.source, 0) + 1

        output.historical = events

        timeline: dict[str, list[dict]] = {}
        for event in events:
            year = str(event.observed_at.year) if event.observed_at else "unknown"
            bucket = timeline.setdefault(year, [])
            if len(bucket) >= _MAX_PER_YEAR:
                continue
            bucket.append(
                {"asset_type": event.asset_type.value, "value": event.value, "source": event.source}
            )
        output.data["timeline"] = timeline

        observed_dates = [e.observed_at for e in events if e.observed_at]
        output.data["summary"] = {
            "total_events": len(events),
            "distinct_years": len({y for y in timeline if y != "unknown"}),
            "oldest_observed_at": min(observed_dates).isoformat() if observed_dates else None,
            "newest_observed_at": max(observed_dates).isoformat() if observed_dates else None,
            "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
            "new_hosts_discovered": len(new_hosts_seen),
        }
        output.metrics["historical_events"] = len(events)
        return output
