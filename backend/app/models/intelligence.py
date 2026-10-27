"""Typed intelligence tables.

The predecessor stored each module's output in one of thirteen sparse JSON
columns on `scans`, which made correlation, deduplication and cross-scan
comparison impossible to express in SQL. Everything worth querying now has
real columns; JSONB is used for the genuinely open-ended parts (a parsed
SPF policy, a technology's evidence trail) rather than for the whole record.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import (
    Base,
    JSONBType,
    ProvenanceMixin,
    UUIDPrimaryKey,
    UUIDType,
    utcnow,
)
from app.models.enums import ApiType, ArtifactKind, UrlClassification

if TYPE_CHECKING:
    from app.models.scan import Scan


class DnsRecord(Base, UUIDPrimaryKey):
    """One DNS resource record, normalized into a structured object."""

    __tablename__ = "dns_records"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: MX / SRV preference.
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)

    #: Parsed interpretation: SPF terms, DMARC policy, CAA tag/value,
    #: SOA fields, DNSKEY algorithm - whatever the type implies.
    parsed: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    #: Inferred provider, e.g. {"provider": "Cloudflare", "kind": "dns"}.
    provider_hint: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    resolver: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="dns_records")

    __table_args__ = (
        Index("ix_dns_records_scan_name_type", "scan_id", "name", "record_type"),
    )


class Certificate(Base, UUIDPrimaryKey, ProvenanceMixin):
    """A TLS certificate observed live or in a Certificate Transparency log."""

    __tablename__ = "certificates"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)

    subject_cn: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    subject: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)
    issuer_cn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    issuer_org: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    issuer: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)

    #: Subject Alternative Names. These are the certificate's contribution
    #: to subdomain discovery and become CERTIFICATE_COVERS graph edges.
    sans: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    has_wildcard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    san_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    days_until_expiry: Mapped[int | None] = mapped_column(Integer, nullable=True)

    signature_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    public_key_algorithm: Mapped[str | None] = mapped_column(String(32), nullable=True)
    public_key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(24), nullable=True)

    #: Chain metadata only - Insyte never stores or serves certificate bytes.
    chain: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)

    #: Certificate Transparency presence and log observations.
    ct_logged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ct_entries: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)

    #: True when this record came from a CT log rather than a live handshake.
    from_ct_log: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan: Mapped[Scan] = relationship(back_populates="certificates")

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "fingerprint_sha256", name="uq_certificates_scan_fingerprint"
        ),
    )


class Technology(Base, UUIDPrimaryKey, ProvenanceMixin):
    """A detected technology, with the evidence that produced the detection.

    `version` and `version_confidence` are separate on purpose. Reporting a
    CVE against a product family because the family was detected is the
    single most common way recon tooling produces false positives; the CVE
    correlator refuses to map unless `version_confidence` clears a
    configured threshold.
    """

    __tablename__ = "technologies"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    normalized_name: Mapped[str] = mapped_column(String(150), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: 0-100. Zero means "the version string is a guess"; the CVE stage
    #: treats anything below the threshold as version-unknown.
    version_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version_source: Mapped[str | None] = mapped_column(String(64), nullable=True)

    category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Common Platform Enumeration string, when one could be derived.
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: Host the detection applies to, e.g. "api.example.com".
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    scan: Mapped[Scan] = relationship(back_populates="technologies")

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "normalized_name", "version", "host",
            name="uq_technologies_scan_name_version_host",
        ),
        Index("ix_technologies_scan_category", "scan_id", "category"),
    )


class Url(Base, UUIDPrimaryKey, ProvenanceMixin):
    """A discovered URL in the unified URL database."""

    __tablename__ = "urls"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    url: Mapped[str] = mapped_column(Text, nullable=False)
    #: Canonical form used for dedup: tracking parameters stripped, default
    #: port removed, fragment dropped. The original stays in `url` because
    #: the raw string is the evidence.
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    scheme: Mapped[str] = mapped_column(String(8), nullable=False, default="https")
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="/")
    query_keys: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    extension: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)

    classification: Mapped[str] = mapped_column(
        String(24), nullable=False, default=UrlClassification.UNKNOWN.value, index=True
    )
    #: Present only when Insyte actually fetched it. Historical URLs from an
    #: archive have no live status and must not pretend to.
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: True when the URL was retrieved in this scan, not merely referenced.
    retrieved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    scan: Mapped[Scan] = relationship(back_populates="urls")

    __table_args__ = (
        UniqueConstraint("scan_id", "url_hash", name="uq_urls_scan_hash"),
        Index("ix_urls_scan_classification", "scan_id", "classification"),
        Index("ix_urls_scan_host", "scan_id", "host"),
    )


class ApiEndpoint(Base, UUIDPrimaryKey, ProvenanceMixin):
    """A discovered API endpoint.

    `validated` is always False. Insyte discovers endpoints from HTML, JS,
    archives and documentation; confirming one is live would mean sending a
    crafted request to it, which is outside the product boundary. The UI
    labels these "Discovered endpoint - not validated" for that reason.
    """

    __tablename__ = "api_endpoints"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    #: Only set when a source actually stated it (an OpenAPI document, a
    #: fetch() call in JavaScript). Never guessed.
    method: Mapped[str | None] = mapped_column(String(12), nullable=True)

    api_type: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ApiType.UNKNOWN.value, index=True
    )
    api_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    #: e.g. "Bearer token", "API key header", "OAuth2". A hint, not proof.
    auth_hint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: The specific artifact it was found in, e.g. "app.93fa.js".
    source_artifact: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Always False - see the class docstring.
    validated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    parameters: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)

    scan: Mapped[Scan] = relationship(back_populates="api_endpoints")

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "url_hash", "method", name="uq_api_endpoints_scan_hash_method"
        ),
        Index("ix_api_endpoints_scan_type", "scan_id", "api_type"),
    )


class JavaScriptArtifact(Base, UUIDPrimaryKey, ProvenanceMixin):
    """An analysed JavaScript file - Insyte's flagship intelligence surface.

    Note what is *not* stored: the script body. Insyte keeps a hash, a size
    and the structured findings. Retaining hostile JavaScript adds risk and
    buys nothing, and secret indicators are stored masked (see
    `services/artifacts/masking.py`) so a full credential never reaches the
    database, the API or a report.
    """

    __tablename__ = "javascript_artifacts"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: SHA-256 of the retrieved body, for change detection across scans.
    content_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_inline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_third_party: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    libraries: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    endpoints: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    domains: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    ip_addresses: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    emails: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    cloud_references: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    integrations: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    #: Masked. Each entry carries a type, a masked preview and a confidence.
    secret_indicators: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    comments: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    config_objects: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    environment_hints: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    package_names: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)

    source_map_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    has_source_map: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source_map_retrieved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Paths / package names / internal hosts recovered from a source map.
    source_map_detail: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    scan: Mapped[Scan] = relationship(back_populates="javascript_artifacts")

    __table_args__ = (
        UniqueConstraint("scan_id", "url_hash", name="uq_js_artifacts_scan_hash"),
    )


class Artifact(Base, UUIDPrimaryKey):
    """Metadata for something Insyte retrieved during Web Surface Collection.

    Bodies are not stored by default. When `storage_path` is set it points
    at a file inside the configured data directory whose name is derived
    from the content hash - never from a target-supplied string - so no
    filename a target controls can influence a filesystem path.
    """

    __tablename__ = "artifacts"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ArtifactKind.OTHER.value, index=True
    )

    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    headers: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)
    redirect_chain: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    remote_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="artifacts")

    __table_args__ = (
        UniqueConstraint("scan_id", "url_hash", name="uq_artifacts_scan_hash"),
    )


class HistoricalEvent(Base, UUIDPrimaryKey):
    """A normalized historical observation of an asset.

    Status is deliberately conservative. `removed_from_source` means a
    source stopped reporting it, which is not the same as the asset being
    gone, and the UI renders those differently.
    """

    __tablename__ = "historical_events"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    asset_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    source_id: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)

    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Calendar year of first_seen, denormalised for the timeline view.
    year: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="historical_events")

    __table_args__ = (
        Index("ix_historical_scan_type_hash", "scan_id", "asset_type", "value_hash"),
        Index("ix_historical_scan_year", "scan_id", "year"),
    )
