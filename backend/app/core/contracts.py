"""The normalized data contract every module and provider must speak.

The predecessor let each module invent its own result shape and dumped the
lot into a per-module JSON column. That made correlation impossible: there
was no common notion of "a thing that was observed, by whom, when, and how
confidently". These dataclasses are that notion.

A module never touches the database. It returns a `ModuleOutput`; the
persistence layer (`services/scan/persistence.py`) is the only thing that
writes. That boundary is what makes modules unit-testable without a
database and what stops a module from corrupting a scan half-way through.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.canonical import canonical_value, fingerprint, value_hash
from app.models.enums import (
    ApiType,
    ArtifactKind,
    AssetType,
    ExposureLevel,
    FindingCategory,
    ObservationStatus,
    RelationType,
    Severity,
    SourceKind,
    UrlClassification,
)


@dataclass(slots=True)
class ObservationRecord:
    """One source asserting one fact at one time.

    This is the universal currency of the pipeline. Providers emit these,
    modules emit these, and the correlation stage folds them into assets.
    Every field that matters for provenance is required rather than
    optional, because an observation without a source is not evidence.
    """

    source: str
    asset_type: AssetType
    value: str
    source_type: SourceKind = SourceKind.PASSIVE
    confidence: int = 50
    status: ObservationStatus = ObservationStatus.OBSERVED
    observed_at: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.value = (self.value or "").strip()
        self.confidence = max(0, min(100, int(self.confidence)))

    @property
    def normalized(self) -> str:
        return canonical_value(self.asset_type.value, self.value)

    @property
    def hash(self) -> str:
        return value_hash(self.normalized)

    @property
    def is_valid(self) -> bool:
        return bool(self.value) and len(self.value) <= 2048


@dataclass(slots=True)
class AssetRecord:
    """An asset a module wants in the graph.

    Modules emit these for things they can state directly (the target
    itself, an IP a DNS answer resolved to). Everything else arrives as an
    observation and the correlation stage promotes it. Both paths converge
    on the same `assets` rows.
    """

    asset_type: AssetType
    value: str
    confidence: int = 50
    sources: list[str] = field(default_factory=list)
    label: str | None = None
    status: ObservationStatus = ObservationStatus.OBSERVED
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_target: bool = False
    in_scope: bool = True

    @property
    def normalized(self) -> str:
        return canonical_value(self.asset_type.value, self.value)

    @property
    def hash(self) -> str:
        return value_hash(self.normalized)

    @property
    def key(self) -> tuple[str, str]:
        return (self.asset_type.value, self.hash)


@dataclass(slots=True)
class RelationshipRecord:
    """A proposed graph edge, expressed by asset *values* not ids.

    Modules do not know database ids, so edges are declared between
    (type, value) pairs and resolved to ids at persistence time. An edge
    whose endpoints were never emitted as assets is dropped rather than
    silently creating a phantom node.
    """

    relation: RelationType
    source_type: AssetType
    source_value: str
    target_type: AssetType
    target_value: str
    confidence: int = 70
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def source_key(self) -> tuple[str, str]:
        return (
            self.source_type.value,
            value_hash(canonical_value(self.source_type.value, self.source_value)),
        )

    @property
    def target_key(self) -> tuple[str, str]:
        return (
            self.target_type.value,
            value_hash(canonical_value(self.target_type.value, self.target_value)),
        )


@dataclass(slots=True)
class FindingRecord:
    """A security-relevant conclusion.

    `severity` and `confidence` are independent inputs, and `exposure`
    records how reachable the thing actually is. The risk engine combines
    all three; no single one of them is the answer.
    """

    module_id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str | None = None
    recommendation: str | None = None
    location: str | None = None
    confidence: int = 70
    exposure: ExposureLevel = ExposureLevel.INFERRED
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    #: Optional link to an asset, by (type, value).
    asset_type: AssetType | None = None
    asset_value: str | None = None

    def __post_init__(self) -> None:
        self.confidence = max(0, min(100, int(self.confidence)))
        self.title = (self.title or "").strip()[:255]

    @property
    def fingerprint(self) -> str:
        """Identity of the issue, stable across scans of the same target."""
        return fingerprint(
            self.module_id,
            self.category.value,
            self.title.lower(),
            (self.location or "").lower(),
        )


@dataclass(slots=True)
class TechnologyRecord:
    """A technology detection with its evidence and version certainty."""

    name: str
    category: str | None = None
    version: str | None = None
    #: 0 means "no version evidence". Anything below the configured floor
    #: prevents CVE correlation from asserting a match.
    version_confidence: int = 0
    version_source: str | None = None
    confidence: int = 60
    vendor: str | None = None
    cpe: str | None = None
    host: str | None = None
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def __post_init__(self) -> None:
        self.name = (self.name or "").strip()
        self.confidence = max(0, min(100, int(self.confidence)))
        self.version_confidence = max(0, min(100, int(self.version_confidence)))
        if self.version:
            self.version = self.version.strip() or None

    @property
    def normalized_name(self) -> str:
        return canonical_value("technology", self.name)


@dataclass(slots=True)
class DnsRecordRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    parsed: dict[str, Any] = field(default_factory=dict)
    provider_hint: dict[str, Any] = field(default_factory=dict)
    resolver: str | None = None


@dataclass(slots=True)
class CertificateRecord:
    #: SHA-256 fingerprint of the DER bytes. None for CT-log-derived
    #: records, where only the logged hostnames were observed.
    fingerprint_sha256: str | None = None
    serial_number: str | None = None
    subject_cn: str | None = None
    subject: dict[str, Any] = field(default_factory=dict)
    issuer_cn: str | None = None
    issuer_org: str | None = None
    issuer: dict[str, Any] = field(default_factory=dict)
    sans: list[str] = field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    tls_version: str | None = None
    chain: list[dict[str, Any]] = field(default_factory=list)
    ct_logged: bool = False
    ct_entries: list[dict[str, Any]] = field(default_factory=list)
    from_ct_log: bool = False
    confidence: int = 90
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class UrlRecord:
    url: str
    normalized_url: str
    host: str
    path: str
    scheme: str = "https"
    classification: UrlClassification = UrlClassification.UNKNOWN
    extension: str | None = None
    query_keys: list[str] = field(default_factory=list)
    status_code: int | None = None
    content_type: str | None = None
    retrieved: bool = False
    in_scope: bool = True
    confidence: int = 60
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def hash(self) -> str:
        return value_hash(self.normalized_url)


@dataclass(slots=True)
class ApiEndpointRecord:
    url: str
    normalized_url: str
    host: str
    path: str
    api_type: ApiType = ApiType.UNKNOWN
    method: str | None = None
    api_version: str | None = None
    auth_hint: str | None = None
    source_artifact: str | None = None
    parameters: list[str] = field(default_factory=list)
    in_scope: bool = True
    confidence: int = 60
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def hash(self) -> str:
        return value_hash(self.normalized_url)


@dataclass(slots=True)
class JavaScriptRecord:
    url: str
    content_sha256: str | None = None
    size: int | None = None
    is_inline: bool = False
    is_third_party: bool = False
    truncated: bool = False
    libraries: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    cloud_references: list[dict[str, Any]] = field(default_factory=list)
    integrations: list[dict[str, Any]] = field(default_factory=list)
    #: Already masked. A full secret must never reach this list.
    secret_indicators: list[dict[str, Any]] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    config_objects: list[dict[str, Any]] = field(default_factory=list)
    environment_hints: list[str] = field(default_factory=list)
    package_names: list[str] = field(default_factory=list)
    source_map_url: str | None = None
    has_source_map: bool = False
    source_map_retrieved: bool = False
    source_map_detail: dict[str, Any] = field(default_factory=dict)
    confidence: int = 90
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def hash(self) -> str:
        return value_hash(self.url)


@dataclass(slots=True)
class ArtifactRecord:
    url: str
    kind: ArtifactKind = ArtifactKind.OTHER
    status_code: int | None = None
    content_type: str | None = None
    content_sha256: str | None = None
    size: int = 0
    truncated: bool = False
    headers: dict[str, Any] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    remote_address: str | None = None
    storage_path: str | None = None
    fetched_at: datetime | None = None

    @property
    def hash(self) -> str:
        return value_hash(self.url)


@dataclass(slots=True)
class HistoricalEventRecord:
    asset_type: AssetType
    value: str
    source: str
    status: ObservationStatus = ObservationStatus.HISTORICAL
    observed_at: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def hash(self) -> str:
        return value_hash(canonical_value(self.asset_type.value, self.value))


@dataclass(slots=True)
class ExposureRecord:
    """A potentially exposed artifact found through a public index.

    `observation_class` is the honesty control. "indexed" means a search
    index or archive mentions it; "directly_retrievable" means a Web
    Surface GET of an already-linked URL actually returned it. Insyte never
    guesses a path to get from one to the other.
    """

    exposure_type: str
    url: str
    observation_class: str = "indexed"
    host: str | None = None
    path: str | None = None
    severity: Severity = Severity.INFORMATIONAL
    confidence: int = 50
    retrievable: bool = False
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def hash(self) -> str:
        return value_hash(self.url)


@dataclass(slots=True)
class ProviderStatus:
    """Whether a provider was usable, and why not if it was not.

    Surfaced verbatim in the UI and the report appendix. "Unavailable - API
    key not configured" is useful; a missing row that the user has to infer
    is not.
    """

    provider: str
    name: str
    available: bool
    configured: bool
    requires_api_key: bool = False
    reason: str | None = None
    calls: int = 0
    cache_hits: int = 0
    errors: list[str] = field(default_factory=list)
    result_count: int = 0
    rate_limited: bool = False
    duration: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "name": self.name,
            "available": self.available,
            "configured": self.configured,
            "requires_api_key": self.requires_api_key,
            "reason": self.reason,
            "calls": self.calls,
            "cache_hits": self.cache_hits,
            "errors": self.errors[:5],
            "result_count": self.result_count,
            "rate_limited": self.rate_limited,
            "duration": round(self.duration, 3),
        }


@dataclass(slots=True)
class ModuleOutput:
    """Everything one module produced.

    Every collection is optional; a module fills only what it knows about.
    `errors` being non-empty does not by itself mean failure - a module that
    reached four of five providers succeeded partially, and saying so is
    more useful than reporting a binary.
    """

    module_id: str
    success: bool = True
    observations: list[ObservationRecord] = field(default_factory=list)
    assets: list[AssetRecord] = field(default_factory=list)
    relationships: list[RelationshipRecord] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
    technologies: list[TechnologyRecord] = field(default_factory=list)
    dns_records: list[DnsRecordRecord] = field(default_factory=list)
    certificates: list[CertificateRecord] = field(default_factory=list)
    urls: list[UrlRecord] = field(default_factory=list)
    api_endpoints: list[ApiEndpointRecord] = field(default_factory=list)
    javascript: list[JavaScriptRecord] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    historical: list[HistoricalEventRecord] = field(default_factory=list)
    exposures: list[ExposureRecord] = field(default_factory=list)
    #: Structured, module-specific summary shown in the UI (e.g. the parsed
    #: SPF/DMARC posture). Not a dumping ground for raw provider payloads.
    data: dict[str, Any] = field(default_factory=dict)
    providers: list[ProviderStatus] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    #: Set when the module chose not to run. Displayed to the user as-is.
    skip_reason: str | None = None

    @property
    def record_count(self) -> int:
        return (
            len(self.observations)
            + len(self.assets)
            + len(self.technologies)
            + len(self.dns_records)
            + len(self.certificates)
            + len(self.urls)
            + len(self.api_endpoints)
            + len(self.javascript)
            + len(self.historical)
            + len(self.exposures)
        )

    def merge(self, other: ModuleOutput) -> None:
        """Fold another output into this one. Used by composite modules."""
        self.observations.extend(other.observations)
        self.assets.extend(other.assets)
        self.relationships.extend(other.relationships)
        self.findings.extend(other.findings)
        self.technologies.extend(other.technologies)
        self.dns_records.extend(other.dns_records)
        self.certificates.extend(other.certificates)
        self.urls.extend(other.urls)
        self.api_endpoints.extend(other.api_endpoints)
        self.javascript.extend(other.javascript)
        self.artifacts.extend(other.artifacts)
        self.historical.extend(other.historical)
        self.exposures.extend(other.exposures)
        self.providers.extend(other.providers)
        self.errors.extend(other.errors)
        for key, value in other.data.items():
            self.data.setdefault(key, value)
        for key, value in other.metrics.items():
            if isinstance(value, (int, float)) and isinstance(
                self.metrics.get(key), (int, float)
            ):
                self.metrics[key] += value
            else:
                self.metrics[key] = value
        self.success = self.success and other.success
