"""Cross-module asset graph correlation.

Runs once per scan, after every module has produced its `ModuleOutput`.
Where `services/correlation/merge.py` deduplicates observations *within* one
module's own output, this stage does it *across* every module - the same
subdomain discovered by `subdomain_intelligence` (from Certificate
Transparency) and independently referenced by `javascript_intelligence`
(from a `fetch()` call) becomes one asset with both sources attached, not
two.

Output is a `CorrelatedGraph`: deduplicated assets keyed by
`(asset_type, value_hash)`, plus relationship edges resolved from the
value-based `RelationshipRecord`s every module emitted into concrete asset
identities. Nothing here writes to the database - `services/scan/persist.py`
turns this into ORM rows inside one transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.core.canonical import value_hash
from app.core.contracts import (
    AssetRecord,
    ModuleOutput,
    ObservationRecord,
    RelationshipRecord,
)
from app.core.target import Target, is_subdomain_of
from app.models.enums import AssetType, ObservationStatus, RelationType
from app.services.correlation.confidence import ConfidenceInput, combine_confidence

_SOURCE_KIND_OVERRIDE = {
    "tls": "web_surface",
    "web_surface": "web_surface",
    "dns": "passive",
    "rdap": "passive",
    "javascript": "web_surface",
    "certificate_transparency": "passive",
}


@dataclass(slots=True)
class MergedAsset:
    """One correlated asset - the graph node."""

    asset_type: AssetType
    value: str
    value_hash: str
    confidence: int
    sources: list[str]
    status: ObservationStatus
    attributes: dict
    evidence: dict
    first_seen: datetime | None
    last_seen: datetime | None
    is_target: bool
    in_scope: bool
    observation_count: int
    label: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.asset_type.value, self.value_hash)


@dataclass(slots=True)
class MergedEdge:
    relation: RelationType
    source_key: tuple[str, str]
    target_key: tuple[str, str]
    confidence: int
    sources: list[str]
    evidence: dict


@dataclass(slots=True)
class CorrelatedGraph:
    assets: dict[tuple[str, str], MergedAsset] = field(default_factory=dict)
    edges: dict[tuple, MergedEdge] = field(default_factory=dict)

    def asset_list(self) -> list[MergedAsset]:
        return sorted(
            self.assets.values(), key=lambda a: (a.asset_type.value, -a.confidence, a.value.lower())
        )

    def edge_list(self) -> list[MergedEdge]:
        return list(self.edges.values())

    def by_type(self, asset_type: AssetType) -> list[MergedAsset]:
        return [a for a in self.assets.values() if a.asset_type is asset_type]


def _reliability_for(source_id: str) -> int:
    from app.providers import get_provider

    provider = get_provider(source_id)
    return provider.reliability if provider is not None else 65


def _kind_for(source_id: str, fallback: str) -> str:
    from app.models.enums import SourceKind

    override = _SOURCE_KIND_OVERRIDE.get(source_id)
    if override:
        return override
    try:
        return SourceKind(fallback).value
    except ValueError:
        return "passive"


def build_graph(
    target: Target, module_outputs: dict[str, ModuleOutput]
) -> CorrelatedGraph:
    """Fold every module's assets and observations into one graph.

    Two kinds of module contribution converge here: `AssetRecord`s a module
    stated directly (the target itself, an IP a DNS answer resolved to) and
    `ObservationRecord`s that need cross-source merging first. Both produce
    the same `MergedAsset` shape so a graph consumer never needs to know
    which path an asset arrived by.
    """
    from app.models.enums import SourceKind

    graph = CorrelatedGraph()
    scope = target.registrable or target.value

    #: (asset_type, hash) -> list of (confidence_input, contributing source)
    votes: dict[tuple[str, str], list[tuple[ConfidenceInput, ObservationRecord | AssetRecord]]] = {}

    def register(
        asset_type: AssetType,
        value: str,
        vhash: str,
        base_confidence: int,
        source: str,
        source_kind: str,
        status: ObservationStatus,
        first_seen: datetime | None,
        last_seen: datetime | None,
        attributes: dict,
        evidence: dict,
        item: ObservationRecord | AssetRecord,
        *,
        is_target: bool = False,
    ) -> None:
        key = (asset_type.value, vhash)
        input_ = ConfidenceInput(
            base_confidence=base_confidence,
            source_reliability=_reliability_for(source),
            source_kind=SourceKind(_kind_for(source, source_kind)),
            status=status,
            last_seen=last_seen,
        )
        votes.setdefault(key, []).append((input_, item))

        existing = graph.assets.get(key)
        in_scope = _scope_of(asset_type, value, scope)
        if existing is None:
            graph.assets[key] = MergedAsset(
                asset_type=asset_type,
                value=value,
                value_hash=vhash,
                confidence=base_confidence,
                sources=[source],
                status=status,
                attributes=dict(attributes),
                evidence={},
                first_seen=first_seen,
                last_seen=last_seen,
                is_target=is_target,
                in_scope=in_scope,
                observation_count=1,
            )
        else:
            if source not in existing.sources:
                existing.sources.append(source)
            existing.observation_count += 1
            existing.is_target = existing.is_target or is_target
            existing.first_seen = _min_dt(existing.first_seen, first_seen)
            existing.last_seen = _max_dt(existing.last_seen, last_seen)
            for attr_key, attr_value in attributes.items():
                existing.attributes.setdefault(attr_key, attr_value)
            if len(value) > len(existing.value) and base_confidence >= existing.confidence:
                existing.value = value

    for output in module_outputs.values():
        for asset in output.assets:
            register(
                asset.asset_type, asset.value, asset.hash, asset.confidence,
                asset.sources[0] if asset.sources else output.module_id,
                "passive", asset.status, asset.first_seen, asset.last_seen,
                asset.attributes, asset.evidence, asset, is_target=asset.is_target,
            )
        for observation in output.observations:
            if not observation.is_valid:
                continue
            register(
                observation.asset_type, observation.value, observation.hash,
                observation.confidence, observation.source, observation.source_type.value,
                observation.status, observation.first_seen, observation.last_seen,
                observation.attributes, observation.evidence, observation,
            )

    for key, vote_list in votes.items():
        inputs = [v[0] for v in vote_list]
        merged = graph.assets[key]
        merged.confidence = combine_confidence(inputs)
        merged.evidence = {
            "per_source": [
                {
                    "source": inp.source_kind.value,
                    "confidence": inp.base_confidence,
                }
                for inp in inputs[:12]
            ]
        }

    _derive_relationships(graph, target)

    for output in module_outputs.values():
        for relationship in output.relationships:
            _add_edge(graph, relationship)

    return graph


def _scope_of(asset_type: AssetType, value: str, scope: str) -> bool:
    if asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return is_subdomain_of(value, scope)
    if asset_type in (
        AssetType.URL, AssetType.API_ENDPOINT, AssetType.JAVASCRIPT,
        AssetType.STYLESHEET, AssetType.SOURCE_MAP,
    ):
        from urllib.parse import urlsplit

        host = urlsplit(value).hostname or ""
        return is_subdomain_of(host, scope) if host else True
    return True


def _derive_relationships(graph: CorrelatedGraph, target: Target) -> None:
    """HAS_SUBDOMAIN edges from the target to every discovered subdomain.

    Explicit rather than left to modules, because every module that finds a
    subdomain would otherwise need to know it must also emit this edge -
    one place doing it once is less error-prone than N places doing it
    consistently.
    """
    target_key = (
        AssetType.DOMAIN.value,
        value_hash(target.value),
    )
    if target_key not in graph.assets:
        return
    for asset in graph.by_type(AssetType.SUBDOMAIN):
        _add_edge(
            graph,
            RelationshipRecord(
                relation=RelationType.HAS_SUBDOMAIN,
                source_type=AssetType.DOMAIN,
                source_value=target.value,
                target_type=AssetType.SUBDOMAIN,
                target_value=asset.value,
                confidence=asset.confidence,
                sources=asset.sources,
            ),
        )


def _add_edge(graph: CorrelatedGraph, relationship: RelationshipRecord) -> None:
    source_key = relationship.source_key
    target_key = relationship.target_key
    if source_key not in graph.assets or target_key not in graph.assets:
        return
    if source_key == target_key:
        return
    edge_key = (relationship.relation.value, source_key, target_key)
    existing = graph.edges.get(edge_key)
    if existing is None:
        graph.edges[edge_key] = MergedEdge(
            relation=relationship.relation,
            source_key=source_key,
            target_key=target_key,
            confidence=relationship.confidence,
            sources=list(dict.fromkeys(relationship.sources)),
            evidence=relationship.evidence,
        )
    else:
        existing.confidence = max(existing.confidence, relationship.confidence)
        for source in relationship.sources:
            if source not in existing.sources:
                existing.sources.append(source)


def _min_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    values = [v for v in (a, b) if v is not None]
    return min(values) if values else None


def _max_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    values = [v for v in (a, b) if v is not None]
    return max(values) if values else None
