"""Indexed Exposure Intelligence.

Matches known-exposure path patterns - `.env`, `.git/`, backup archives,
configuration dumps, and administrative/staging path segments - against
URLs Insyte already knows about, from whatever source knows about them:
the current scan's URL inventory, historical archives, or (in Passive
mode, where there is no URL inventory at all) whatever `known_urls()`
already holds.

This is deliberately not directory brute-forcing. Every candidate path
matched here was already discovered - linked from a page, referenced in
JavaScript, or seen by an archive - never guessed and fetched to see what
answers. `url_collection` is an optional dependency rather than a required
one specifically so this module still has something to check in Passive
mode, where `url_collection` never runs at all.
"""

from __future__ import annotations

from app.core.canonical import canonical_url
from app.core.contracts import ExposureRecord, FindingRecord, ModuleOutput
from app.core.target import TargetType
from app.models.enums import (
    AssetType,
    ExposureLevel,
    FindingCategory,
    ModuleCategory,
    ScanMode,
    Severity,
)
from app.modules.base import IntelligenceModule, ModuleContext

#: (needle, exposure_type). Checked first and most specifically - these are
#: the patterns that mean "credential or infrastructure dump", not "someone
#: has an admin panel".
_SENSITIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (".env", "environment_file"),
    (".git", "version_control"),
    ("docker-compose.yml", "container_config"),
    ("dockerfile", "container_config"),
    ("backup.sql", "database_backup"),
    ("database.sql", "database_backup"),
    ("dump.sql", "database_backup"),
    ("backup.zip", "backup_archive"),
    ("backup.tar.gz", "backup_archive"),
    ("secrets.json", "secrets_file"),
)

#: Generic configuration/backup shapes - worth flagging, but nowhere near
#: as immediately damaging as the sensitive tier above.
_GENERIC_PATTERNS: tuple[tuple[str, str], ...] = (
    (".gitignore", "version_control"),
    ("config.json", "configuration_file"),
    ("config.yml", "configuration_file"),
    ("config.yaml", "configuration_file"),
    ("settings.json", "configuration_file"),
    ("schema.json", "configuration_file"),
    (".map", "source_map"),
    (".log", "log_file"),
    (".bak", "backup_file"),
    (".old", "backup_file"),
    (".tmp", "temp_file"),
    (".sql", "database_backup"),
)

#: Path segments that are only ever a soft hint on their own - an "admin"
#: segment with no sensitive-file match is not evidence of anything beyond
#: "there is an admin panel", which most sites have on purpose.
_CONTEXTUAL_SEGMENTS: frozenset[str] = frozenset(
    {"admin", "internal", "staging", "dev", "debug", "backup", "old", "legacy", "private"}
)


def _classify(path: str) -> tuple[str, str] | None:
    """Return (exposure_type, tier) for a path, or None if nothing matches."""
    lowered = path.lower()
    for needle, exposure_type in _SENSITIVE_PATTERNS:
        if needle in lowered:
            return exposure_type, "sensitive"
    for needle, exposure_type in _GENERIC_PATTERNS:
        if needle in lowered:
            return exposure_type, "generic"
    for segment in (s for s in lowered.split("/") if s):
        # Real-world paths compound the hint word rather than isolating it
        # ("wp-admin", "staging-server", "old_backups") - checking the
        # whole segment as a substring, not just an exact token match,
        # is what actually catches those; it stays low-noise because the
        # word list itself is short and curated.
        for word in _CONTEXTUAL_SEGMENTS:
            if word in segment:
                return f"contextual_path:{word}", "contextual"
    return None


def _severity(tier: str, observation_class: str) -> Severity:
    if tier == "sensitive":
        return Severity.HIGH if observation_class == "directly_retrievable" else Severity.MEDIUM
    if tier == "generic":
        return Severity.LOW
    return Severity.INFORMATIONAL


class IndexedExposureModule(IntelligenceModule):
    id = "indexed_exposure"
    name = "Indexed Exposure Intelligence"
    description = (
        "Matches known-exposure path patterns - .env, .git, backup "
        "archives, configuration dumps - against URLs Insyte already "
        "knows about. Never brute-forces a path to find out."
    )
    category = ModuleCategory.EXPOSURE
    mode_support = (ScanMode.PASSIVE, ScanMode.WEB_SURFACE)
    input_types = (TargetType.DOMAIN, TargetType.IPV4, TargetType.IPV6)
    # Declared (not merely opportunistic) because the historical-URL
    # expansion below is this module's main input in Passive mode - without
    # ordering, `ctx.output_of("historical_intelligence")` is usually None
    # and the module starves on a handful of known URLs.
    dependencies = ("historical_intelligence",)
    timeout = 30.0
    order = 79

    def execute(self, ctx: ModuleContext) -> ModuleOutput:
        output = ModuleOutput(module_id=self.id)
        target_host = ctx.target.value

        candidates: dict[str, dict] = {}

        url_output = ctx.output_of("url_collection")
        if url_output is not None:
            for record in url_output.urls:
                candidates[record.normalized_url] = {
                    "url": record.url,
                    "host": record.host,
                    "path": record.path,
                    "status_code": record.status_code,
                    "retrieved": record.retrieved,
                    "source": "url_collection",
                    "historical": False,
                }
        else:
            for raw in ctx.known_urls():
                canon = canonical_url(raw, target_host=target_host)
                if canon is None:
                    continue
                candidates.setdefault(
                    canon.normalized,
                    {
                        "url": canon.original,
                        "host": canon.host,
                        "path": canon.path,
                        "status_code": None,
                        "retrieved": False,
                        "source": "known_urls",
                        "historical": False,
                    },
                )

        historical_output = ctx.output_of("historical_intelligence")
        if historical_output is not None:
            for event in historical_output.historical:
                if event.asset_type is not AssetType.URL:
                    continue
                canon = canonical_url(event.value, target_host=target_host)
                if canon is None:
                    continue
                entry = candidates.setdefault(
                    canon.normalized,
                    {
                        "url": canon.original,
                        "host": canon.host,
                        "path": canon.path,
                        "status_code": None,
                        "retrieved": False,
                        "source": event.source,
                        "historical": True,
                    },
                )
                entry["historical"] = True

        exposures_by_type: dict[str, int] = {}
        by_observation_class: dict[str, int] = {}

        for info in candidates.values():
            match = _classify(info["path"])
            if match is None:
                continue
            exposure_type, tier = match

            directly_retrievable = bool(info["retrieved"]) and info["status_code"] == 200
            if directly_retrievable:
                observation_class = "directly_retrievable"
            elif info["historical"]:
                observation_class = "indexed"
            else:
                observation_class = "observed"

            severity = _severity(tier, observation_class)
            exposures_by_type[exposure_type] = exposures_by_type.get(exposure_type, 0) + 1
            by_observation_class[observation_class] = by_observation_class.get(observation_class, 0) + 1

            confidence = 85 if directly_retrievable else (60 if observation_class == "indexed" else 50)
            exposure = ExposureRecord(
                exposure_type=exposure_type,
                url=info["url"],
                observation_class=observation_class,
                host=info["host"],
                path=info["path"],
                severity=severity,
                confidence=confidence,
                retrievable=directly_retrievable,
                sources=[info["source"]],
                evidence={"status_code": info["status_code"]},
            )
            output.exposures.append(exposure)

            if severity.rank >= Severity.MEDIUM.rank:
                exposure_level = (
                    ExposureLevel.DIRECT
                    if observation_class == "directly_retrievable"
                    else (ExposureLevel.HISTORICAL if info["historical"] else ExposureLevel.INDEXED)
                )
                # Honesty labeling: anything not actually fetched is an
                # unverified pattern match, not a confirmed exposure. The
                # title stays stable for fingerprinting; the description and
                # evidence carry the verification state explicitly.
                if directly_retrievable:
                    verification = "verified_retrievable"
                    verification_note = (
                        "Confirmed: this path was fetched during the scan "
                        "and returned HTTP 200."
                    )
                else:
                    verification = "unverified_pattern_match"
                    verification_note = (
                        "UNVERIFIED pattern match - this path was NOT "
                        "fetched and its existence is NOT confirmed. Treat "
                        "as a lead for manual review, not as a confirmed "
                        "exposure."
                    )
                output.findings.append(
                    FindingRecord(
                        module_id=self.id,
                        category=FindingCategory.INDEXED_ARTIFACT,
                        severity=severity,
                        title=f"Potentially sensitive path indexed: {exposure_type.replace('_', ' ')}",
                        description=(
                            f"{verification_note} {info['url']} matches a "
                            f"known-exposure pattern ({exposure_type}) and is "
                            f"{observation_class.replace('_', ' ')}."
                        ),
                        recommendation=(
                            "Confirm whether this path should be publicly "
                            "accessible; remove or restrict it if not."
                        ),
                        location=info["url"],
                        confidence=confidence,
                        exposure=exposure_level,
                        sources=[info["source"]],
                        evidence={
                            "exposure_type": exposure_type,
                            "observation_class": observation_class,
                            "verification": verification,
                        },
                    )
                )

        output.data["summary"] = {
            "by_exposure_type": exposures_by_type,
            "by_observation_class": by_observation_class,
            "total": len(output.exposures),
            "verification_note": (
                "Findings with observation_class 'indexed' or 'observed' are "
                "unverified pattern matches - the path was not fetched. Only "
                "'directly_retrievable' findings were confirmed with an "
                "HTTP 200 during the scan."
            ),
        }
        return output
