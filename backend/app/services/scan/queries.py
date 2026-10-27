"""Read-side queries for a scan's collected intelligence.

Every collection endpoint (assets, findings, URLs, APIs, JavaScript,
historical events, CVEs) goes through one of these functions rather than
inline query-building in the route handler, so filtering/pagination/sort
behaviour is consistent and testable without a running server.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.graph import Asset, AssetRelationship
from app.models.intelligence import (
    ApiEndpoint,
    Certificate,
    DnsRecord,
    HistoricalEvent,
    JavaScriptArtifact,
    Technology,
    Url,
)
from app.models.risk import Cve, Finding, IndexedExposure


def _paginate(db: Session, query, limit: int, offset: int) -> tuple[list, int]:
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.limit(limit).offset(offset)).all()
    return list(rows), total


def list_assets(
    db: Session,
    scan_id: uuid.UUID,
    *,
    asset_type: str | None = None,
    in_scope: bool | None = None,
    min_confidence: int | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Asset], int]:
    query = select(Asset).where(Asset.scan_id == scan_id)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if in_scope is not None:
        query = query.where(Asset.in_scope == in_scope)
    if min_confidence is not None:
        query = query.where(Asset.confidence >= min_confidence)
    if search:
        query = query.where(Asset.value.ilike(f"%{search}%"))
    query = query.order_by(Asset.asset_type, Asset.confidence.desc())
    return _paginate(db, query, limit, offset)


def get_asset(db: Session, scan_id: uuid.UUID, asset_id: uuid.UUID) -> Asset | None:
    return db.scalar(
        select(Asset).where(Asset.scan_id == scan_id, Asset.id == asset_id)
    )


def asset_relationships(
    db: Session, scan_id: uuid.UUID, asset_id: uuid.UUID
) -> tuple[list[AssetRelationship], list[AssetRelationship]]:
    outgoing = db.scalars(
        select(AssetRelationship).where(
            AssetRelationship.scan_id == scan_id,
            AssetRelationship.source_asset_id == asset_id,
        )
    ).all()
    incoming = db.scalars(
        select(AssetRelationship).where(
            AssetRelationship.scan_id == scan_id,
            AssetRelationship.target_asset_id == asset_id,
        )
    ).all()
    return list(outgoing), list(incoming)


def full_graph(
    db: Session,
    scan_id: uuid.UUID,
    *,
    max_nodes: int = 2000,
    in_scope: bool | None = None,
    min_confidence: int | None = None,
) -> tuple[list[Asset], list[AssetRelationship]]:
    query = select(Asset).where(Asset.scan_id == scan_id)
    if in_scope is not None:
        query = query.where(Asset.in_scope == in_scope)
    if min_confidence is not None:
        query = query.where(Asset.confidence >= min_confidence)
    nodes = db.scalars(query.order_by(Asset.confidence.desc()).limit(max_nodes)).all()
    node_ids = {n.id for n in nodes}
    edges = db.scalars(
        select(AssetRelationship).where(AssetRelationship.scan_id == scan_id)
    ).all()
    edges = [e for e in edges if e.source_asset_id in node_ids and e.target_asset_id in node_ids]
    return list(nodes), edges


def list_findings(
    db: Session,
    scan_id: uuid.UUID,
    *,
    severity: str | None = None,
    category: str | None = None,
    min_confidence: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Finding], int]:
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if min_confidence is not None:
        query = query.where(Finding.confidence >= min_confidence)
    query = query.order_by(Finding.risk_score.desc())
    return _paginate(db, query, limit, offset)


def list_technologies(
    db: Session, scan_id: uuid.UUID, *, category: str | None = None, limit: int = 200, offset: int = 0
) -> tuple[list[Technology], int]:
    query = select(Technology).where(Technology.scan_id == scan_id)
    if category:
        query = query.where(Technology.category == category)
    query = query.order_by(Technology.confidence.desc())
    return _paginate(db, query, limit, offset)


def list_urls(
    db: Session,
    scan_id: uuid.UUID,
    *,
    classification: str | None = None,
    in_scope: bool | None = None,
    retrieved: bool | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[Url], int]:
    query = select(Url).where(Url.scan_id == scan_id)
    if classification:
        query = query.where(Url.classification == classification)
    if in_scope is not None:
        query = query.where(Url.in_scope == in_scope)
    if retrieved is not None:
        query = query.where(Url.retrieved == retrieved)
    query = query.order_by(Url.host, Url.path)
    return _paginate(db, query, limit, offset)


def list_apis(
    db: Session, scan_id: uuid.UUID, *, api_type: str | None = None, limit: int = 200, offset: int = 0
) -> tuple[list[ApiEndpoint], int]:
    query = select(ApiEndpoint).where(ApiEndpoint.scan_id == scan_id)
    if api_type:
        query = query.where(ApiEndpoint.api_type == api_type)
    query = query.order_by(ApiEndpoint.confidence.desc())
    return _paginate(db, query, limit, offset)


def list_javascript(
    db: Session, scan_id: uuid.UUID, *, has_secrets: bool | None = None, limit: int = 100, offset: int = 0
) -> tuple[list[JavaScriptArtifact], int]:
    query = select(JavaScriptArtifact).where(JavaScriptArtifact.scan_id == scan_id)
    query = query.order_by(JavaScriptArtifact.url)
    rows, total = _paginate(db, query, limit, offset)
    if has_secrets is not None:
        rows = [r for r in rows if bool(r.secret_indicators) == has_secrets]
    return rows, total


def list_historical(
    db: Session, scan_id: uuid.UUID, *, year: int | None = None, limit: int = 300, offset: int = 0
) -> tuple[list[HistoricalEvent], int]:
    query = select(HistoricalEvent).where(HistoricalEvent.scan_id == scan_id)
    if year is not None:
        query = query.where(HistoricalEvent.year == year)
    query = query.order_by(HistoricalEvent.first_seen.desc().nullslast())
    return _paginate(db, query, limit, offset)


def list_indexed_exposures(
    db: Session, scan_id: uuid.UUID, *, limit: int = 200, offset: int = 0
) -> tuple[list[IndexedExposure], int]:
    query = (
        select(IndexedExposure)
        .where(IndexedExposure.scan_id == scan_id)
        .order_by(IndexedExposure.severity.desc())
    )
    return _paginate(db, query, limit, offset)


def list_cves(
    db: Session, scan_id: uuid.UUID, *, definitive_only: bool = False, limit: int = 200, offset: int = 0
) -> tuple[list[Cve], int]:
    query = select(Cve).where(Cve.scan_id == scan_id)
    if definitive_only:
        query = query.where(Cve.definitive.is_(True))
    query = query.order_by(Cve.cvss_score.desc().nullslast())
    return _paginate(db, query, limit, offset)


def list_certificates(db: Session, scan_id: uuid.UUID) -> list[Certificate]:
    return list(
        db.scalars(select(Certificate).where(Certificate.scan_id == scan_id)).all()
    )


def list_dns_records(db: Session, scan_id: uuid.UUID) -> list[DnsRecord]:
    return list(
        db.scalars(
            select(DnsRecord).where(DnsRecord.scan_id == scan_id).order_by(DnsRecord.record_type)
        ).all()
    )
