"""Wayback Snapshot Diff - what changed between old and recent crawls.

Queries the Wayback CDX index twice with bounded time windows: an old
inventory (first capture per URL before the cutoff, three years back) and
a recent inventory (first capture per URL in the last twelve months).
The diff surfaces newly appeared endpoints and JavaScript files alongside
URLs that stopped being captured - retired API versions, removed pages -
without re-downloading anything.

A URL missing from the recent inventory is reported as "no longer
captured", never as "removed": the crawler may simply not have revisited
it. Findings are informational.
"""

from __future__ import annotations

from datetime import date
from urllib.parse import quote_plus, urlsplit

from app.core.contracts import FindingRecord, ModuleOutput, ObservationRecord
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ObservationStatus,
    ScanMode,
    Severity,
    SourceKind,
)
from app.modules.base import IntelligenceModule, ModuleContext

_CDX_BASE = "https://web.archive.org/cdx/search/cdx"
_LIMIT = 2000
_MAX_OBSERVATIONS_EACH = 30
_CHURN_FINDING_THRESHOLD = 10


def _cdx_url(domain: str, window: str) -> str:
    params = (
        f"url={quote_plus(domain)}&matchType=domain&output=json"
        "&fl=original,timestamp&collapse=urlkey&filter=statuscode:200"
        f"&limit={_LIMIT}&{window}"
    )
    return f"{_CDX_BASE}?{params}"


def _fetch_inventory(ctx: ModuleContext, domain: str, window: str) -> set[str]:
    """One bounded CDX inventory query. Never raises."""
    response = ctx.http.try_get(_cdx_url(domain, window), max_bytes=4 * 1024 * 1024)
    if response is None or not response.ok:
        return set()
    import json

    try:
        rows = json.loads(response.text)
    except Exception:  # noqa: BLE001 - malformed index response
        return set()
    if not isinstance(rows, list):
        return set()
    inventory: set[str] = set()
    for row in rows[1:]:
        if not isinstance(row, list) or not row:
            continue
        inventory.add(_normalize_url(str(row[0])))
    inventory.discard("")
    return inventory


def _normalize_url(raw: str) -> str:
    try:
        parts = urlsplit(raw.strip())
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{parts.hostname.lower()}{path}{query}".lower()


def _interesting(url: str) -> bool:
    lowered = url.lower()
    return lowered.endswith(".js") or "/api/" in lowered


class WaybackDiffModule(IntelligenceModule):
    id = "wayback_diff"
    name = "Wayback Snapshot Diff"
    description = (
        "Diffs old versus recent Wayback Machine inventories to surface "
        "newly appeared endpoints and URLs that stopped being captured."
    )
    category = ModuleCategory.HISTORICAL
    mode_support = (ScanMode.PASSIVE,)
    input_types = (TargetType.DOMAIN,)
    timeout = 90.0
    order = 96

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        domain = ctx.target.registrable or ctx.target.value
        if not domain:
            return output

        year = date.today().year
        old_window = f"to={year - 3}1231235959"
        new_window = f"from={year - 1}0101000000"

        old_inventory = _fetch_inventory(ctx, domain, old_window)
        ctx.check_cancelled()
        new_inventory = _fetch_inventory(ctx, domain, new_window)

        if not old_inventory and not new_inventory:
            output.data["note"] = "Wayback CDX returned no inventory for either window"
            return output

        added = sorted(new_inventory - old_inventory)
        removed = sorted(old_inventory - new_inventory)

        added_js = [u for u in added if _interesting(u)]
        removed_js = [u for u in removed if _interesting(u)]

        for url in (added_js + [u for u in added if u not in added_js])[
            :_MAX_OBSERVATIONS_EACH
        ]:
            output.observations.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.URL,
                    value=url,
                    source_type=SourceKind.PASSIVE,
                    confidence=70,
                    status=ObservationStatus.OBSERVED,
                    evidence={
                        "discovery": "URL captured recently but not in the old inventory",
                        "old_window": f"before {year - 3}",
                        "recent_window": f"since {year - 1}",
                    },
                )
            )
        for url in (removed_js + [u for u in removed if u not in removed_js])[
            :_MAX_OBSERVATIONS_EACH
        ]:
            output.observations.append(
                ObservationRecord(
                    source=self.id,
                    asset_type=AssetType.URL,
                    value=url,
                    source_type=SourceKind.PASSIVE,
                    confidence=60,
                    status=ObservationStatus.HISTORICAL,
                    evidence={
                        "discovery": "URL in the old inventory but no longer captured",
                        "note": "not captured recently; the crawler may simply "
                        "not have revisited it",
                        "old_window": f"before {year - 3}",
                        "recent_window": f"since {year - 1}",
                    },
                )
            )

        output.data["summary"] = {
            "old_inventory_size": len(old_inventory),
            "recent_inventory_size": len(new_inventory),
            "added": len(added),
            "no_longer_captured": len(removed),
            "added_js_or_api": len(added_js),
            "removed_js_or_api": len(removed_js),
        }
        output.data["added_sample"] = added[:200]
        output.data["removed_sample"] = removed[:200]
        output.metrics["wayback_added"] = len(added)
        output.metrics["wayback_removed"] = len(removed)

        if len(added) + len(removed) >= _CHURN_FINDING_THRESHOLD:
            output.findings.append(
                FindingRecord(
                    module_id=self.id,
                    category=FindingCategory.HISTORICAL_EXPOSURE,
                    severity=Severity.INFORMATIONAL,
                    title=f"Historical URL churn: {len(added)} new, {len(removed)} no longer captured",
                    description=(
                        f"Comparing Wayback inventories before {year - 3} with "
                        f"captures since {year - 1} shows {len(added)} URLs "
                        f"that appeared and {len(removed)} that stopped being "
                        "captured. New endpoints may widen the attack surface; "
                        "URLs that stopped being captured sometimes point at "
                        "retired functionality worth confirming offline."
                    ),
                    recommendation=(
                        "Review the new endpoints for unintended exposure and "
                        "confirm retired ones are actually gone rather than "
                        "just uncrawled."
                    ),
                    confidence=65,
                    exposure=ExposureLevel.INFERRED,
                    sources=[self.id],
                    evidence=dict(output.data["summary"]),
                )
            )
        return output
