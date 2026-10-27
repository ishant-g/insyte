"""Read-only collection endpoints over one scan's intelligence."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, verify_scan_owner
from app.core.errors import NotFoundError
from app.schemas.asset import (
    AssetDetailRead,
    AssetRead,
    GraphEdge,
    GraphNode,
    GraphRead,
    RelationshipRead,
)
from app.schemas.common import Page
from app.schemas.finding import (
    CveRead,
    ExposureSummary,
    FindingDetailRead,
    FindingRead,
    TechnologyRead,
)
from app.schemas.target import (
    ApiEndpointRead,
    CertificateRead,
    DnsRecordRead,
    HistoricalEventRead,
    IndexedExposureRead,
    JavaScriptRead,
    UrlRead,
)
from app.services.scan import queries as q
from app.services.scan.diff import compare_scans
from app.services.scan.service import ScanService

router = APIRouter(prefix="/scans", tags=["scan-data"], dependencies=[Depends(verify_scan_owner)])


def _service(db: Session = Depends(get_db)) -> ScanService:
    return ScanService(db)


def _ensure_scan(scan_id: uuid.UUID, svc: ScanService) -> None:
    svc.get(scan_id)


@router.get("/{scan_id}/assets", response_model=Page[AssetRead])
def list_assets(
    scan_id: uuid.UUID,
    asset_type: str | None = None,
    in_scope: bool | None = None,
    min_confidence: int | None = Query(default=None, ge=0, le=100),
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[AssetRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_assets(
        db, scan_id, asset_type=asset_type, in_scope=in_scope,
        min_confidence=min_confidence, search=search, limit=limit, offset=offset,
    )
    return Page(items=[AssetRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/assets/{asset_id}", response_model=AssetDetailRead)
def get_asset(
    scan_id: uuid.UUID, asset_id: uuid.UUID, db: Session = Depends(get_db), svc: ScanService = Depends(_service)
) -> AssetDetailRead:
    _ensure_scan(scan_id, svc)
    asset = q.get_asset(db, scan_id, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    outgoing, incoming = q.asset_relationships(db, scan_id, asset_id)
    data = AssetRead.model_validate(asset).model_dump()
    data["evidence"] = asset.evidence
    data["outgoing"] = [RelationshipRead.model_validate(r) for r in outgoing]
    data["incoming"] = [RelationshipRead.model_validate(r) for r in incoming]
    return AssetDetailRead.model_validate(data)


@router.get("/{scan_id}/graph", response_model=GraphRead)
def get_graph(
    scan_id: uuid.UUID,
    max_nodes: int = Query(default=2000, ge=1, le=5000),
    in_scope: bool | None = None,
    min_confidence: int | None = Query(default=None, ge=0, le=100),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> GraphRead:
    _ensure_scan(scan_id, svc)
    nodes, edges = q.full_graph(
        db, scan_id, max_nodes=max_nodes, in_scope=in_scope,
        min_confidence=min_confidence,
    )
    return GraphRead(
        nodes=[
            GraphNode(
                id=str(n.id), asset_type=n.asset_type, value=n.value,
                confidence=n.confidence, is_target=n.is_target, in_scope=n.in_scope,
                sources=n.sources,
            )
            for n in nodes
        ],
        edges=[
            GraphEdge(
                source=str(e.source_asset_id), target=str(e.target_asset_id),
                relation=e.relation, confidence=e.confidence,
            )
            for e in edges
        ],
    )


@router.get("/{scan_id}/findings", response_model=Page[FindingRead])
def list_findings(
    scan_id: uuid.UUID,
    severity: str | None = None,
    category: str | None = None,
    min_confidence: int | None = Query(default=None, ge=0, le=100),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[FindingRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_findings(
        db, scan_id, severity=severity, category=category, min_confidence=min_confidence,
        limit=limit, offset=offset,
    )
    return Page(items=[FindingRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/findings/{finding_id}", response_model=FindingDetailRead)
def get_finding(
    scan_id: uuid.UUID, finding_id: uuid.UUID, db: Session = Depends(get_db), svc: ScanService = Depends(_service)
) -> FindingDetailRead:
    _ensure_scan(scan_id, svc)
    from app.models.risk import Finding

    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise NotFoundError("Finding not found")
    return FindingDetailRead.model_validate(finding)


@router.get("/{scan_id}/exposure", response_model=ExposureSummary)
def get_exposure(scan_id: uuid.UUID, svc: ScanService = Depends(_service)) -> ExposureSummary:
    scan = svc.get(scan_id)
    severity_counts = (scan.summary or {}).get("findings_by_severity", {})
    return ExposureSummary(
        score=scan.exposure_score or 0,
        band=scan.exposure_band or "minimal",
        severity_counts=severity_counts,
        finding_count=(scan.summary or {}).get("findings_total", 0),
    )


@router.get("/{scan_id}/technologies", response_model=Page[TechnologyRead])
def list_technologies(
    scan_id: uuid.UUID,
    category: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[TechnologyRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_technologies(db, scan_id, category=category, limit=limit, offset=offset)
    return Page(items=[TechnologyRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/cves", response_model=Page[CveRead])
def list_cves(
    scan_id: uuid.UUID,
    definitive_only: bool = False,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[CveRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_cves(db, scan_id, definitive_only=definitive_only, limit=limit, offset=offset)
    return Page(items=[CveRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/urls", response_model=Page[UrlRead])
def list_urls(
    scan_id: uuid.UUID,
    classification: str | None = None,
    in_scope: bool | None = None,
    retrieved: bool | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[UrlRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_urls(
        db, scan_id, classification=classification, in_scope=in_scope, retrieved=retrieved,
        limit=limit, offset=offset,
    )
    return Page(items=[UrlRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/apis", response_model=Page[ApiEndpointRead])
def list_apis(
    scan_id: uuid.UUID,
    api_type: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[ApiEndpointRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_apis(db, scan_id, api_type=api_type, limit=limit, offset=offset)
    return Page(items=[ApiEndpointRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/javascript", response_model=Page[JavaScriptRead])
def list_javascript(
    scan_id: uuid.UUID,
    has_secrets: bool | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[JavaScriptRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_javascript(db, scan_id, has_secrets=has_secrets, limit=limit, offset=offset)
    return Page(items=[JavaScriptRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/historical", response_model=Page[HistoricalEventRead])
def list_historical(
    scan_id: uuid.UUID,
    year: int | None = None,
    limit: int = Query(default=300, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[HistoricalEventRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_historical(db, scan_id, year=year, limit=limit, offset=offset)
    return Page(items=[HistoricalEventRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/indexed-exposures", response_model=Page[IndexedExposureRead])
def list_indexed_exposures(
    scan_id: uuid.UUID,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> Page[IndexedExposureRead]:
    _ensure_scan(scan_id, svc)
    rows, total = q.list_indexed_exposures(db, scan_id, limit=limit, offset=offset)
    return Page(items=[IndexedExposureRead.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/certificates", response_model=list[CertificateRead])
def list_certificates(
    scan_id: uuid.UUID, db: Session = Depends(get_db), svc: ScanService = Depends(_service)
) -> list[CertificateRead]:
    _ensure_scan(scan_id, svc)
    return [CertificateRead.model_validate(r) for r in q.list_certificates(db, scan_id)]


@router.get("/{scan_id}/dns-records", response_model=list[DnsRecordRead])
def list_dns_records(
    scan_id: uuid.UUID, db: Session = Depends(get_db), svc: ScanService = Depends(_service)
) -> list[DnsRecordRead]:
    _ensure_scan(scan_id, svc)
    return [DnsRecordRead.model_validate(r) for r in q.list_dns_records(db, scan_id)]


@router.get("/{scan_id}/changes")
def get_changes(
    scan_id: uuid.UUID,
    compare_to: uuid.UUID,
    db: Session = Depends(get_db),
    svc: ScanService = Depends(_service),
) -> dict:
    _ensure_scan(scan_id, svc)
    _ensure_scan(compare_to, svc)
    diff = compare_scans(db, compare_to, scan_id)
    return diff.as_dict()
