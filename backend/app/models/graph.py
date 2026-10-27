"""The Insyte asset graph: assets, relationships and observations.

These three tables are the product's centre of gravity. Everything a module
discovers becomes an `Observation` (raw, attributed, timestamped), which is
then folded into an `Asset` (deduplicated, confidence-scored) and connected
by `AssetRelationship` rows. The UI graph reads these tables directly, so
there is no way for the visualisation to show an edge that does not exist in
the database.
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
from app.models.enums import ObservationStatus, SourceKind

if TYPE_CHECKING:
    from app.models.scan import Scan


class Source(Base):
    """Catalogue of intelligence sources.

    A static reference table, seeded by migration. It exists so provenance
    is a foreign key rather than a free-form string, and so the UI can show
    "Certificate Transparency" with a reliability weight instead of the
    slug `crtsh`.
    """

    __tablename__ = "sources"

    #: Stable slug, e.g. "crtsh", "wayback", "urlscan".
    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default=SourceKind.PASSIVE.value
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    homepage: Mapped[str | None] = mapped_column(String(255), nullable=True)
    requires_api_key: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    #: 0-100 baseline trust, feeding the confidence engine. A certificate
    #: transparency log is authoritative about certificates; a search index
    #: is a weaker signal about anything.
    reliability: Mapped[int] = mapped_column(Integer, nullable=False, default=70)


class Asset(Base, UUIDPrimaryKey, ProvenanceMixin):
    """A deduplicated thing that exists in the target's public footprint.

    Uniqueness is on `(scan_id, asset_type, normalized_value)`. An asset
    found by five sources is one row with five entries in `sources`, which
    is precisely the behaviour the brief asks for - not five rows.
    """

    __tablename__ = "assets"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    asset_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    #: Display value, e.g. "API.Example.com" as first seen.
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: Canonical dedup key. Lowercased, normalized, tracking params stripped.
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: SHA-256 of normalized_value. PostgreSQL cannot index a 2048-byte
    #: text column reliably at btree page limits, so the unique constraint
    #: and lookups go through this fixed-width digest instead.
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ObservationStatus.OBSERVED.value, index=True
    )

    #: Type-specific detail: for an IP, ASN and geo; for a technology,
    #: version and category; for a URL, its classification.
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    #: How many independent sources corroborated this asset.
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    #: True when this asset is the scan's own target.
    is_target: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: True when the asset is in scope (at or beneath the target's
    #: registrable domain). Out-of-scope assets are kept as context - a
    #: third-party CDN host is worth knowing about - but never reported as
    #: part of the target's attack surface.
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="assets")

    outgoing: Mapped[list[AssetRelationship]] = relationship(
        back_populates="source_asset",
        foreign_keys="AssetRelationship.source_asset_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    incoming: Mapped[list[AssetRelationship]] = relationship(
        back_populates="target_asset",
        foreign_keys="AssetRelationship.target_asset_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    observations: Mapped[list[Observation]] = relationship(
        back_populates="asset", passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "asset_type", "value_hash", name="uq_assets_scan_type_hash"
        ),
        Index("ix_assets_scan_type", "scan_id", "asset_type"),
        Index("ix_assets_scan_confidence", "scan_id", "confidence"),
        Index("ix_assets_scan_scope", "scan_id", "in_scope"),
    )


class AssetRelationship(Base, UUIDPrimaryKey):
    """A directed, evidence-backed edge between two assets."""

    __tablename__ = "asset_relationships"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    relation: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=70)
    sources: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="relationships")
    source_asset: Mapped[Asset] = relationship(
        back_populates="outgoing", foreign_keys=[source_asset_id]
    )
    target_asset: Mapped[Asset] = relationship(
        back_populates="incoming", foreign_keys=[target_asset_id]
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "source_asset_id",
            "target_asset_id",
            "relation",
            name="uq_asset_rel_edge",
        ),
        Index("ix_asset_rel_scan_relation", "scan_id", "relation"),
    )


class Observation(Base, UUIDPrimaryKey):
    """One source saying one thing at one time.

    Observations are append-only and never merged. This is the audit trail
    that lets the UI answer "why do you think this exists?" with a specific
    source and timestamp rather than a confidence number alone.
    """

    __tablename__ = "observations"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: Set once the observation has been folded into an asset.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    source_id: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    module_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    asset_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ObservationStatus.OBSERVED.value
    )

    #: When the *source* observed it, which is not when we asked.
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="observations")
    asset: Mapped[Asset | None] = relationship(back_populates="observations")

    __table_args__ = (
        Index("ix_observations_scan_type_hash", "scan_id", "asset_type", "value_hash"),
        Index("ix_observations_scan_source", "scan_id", "source_id"),
    )
