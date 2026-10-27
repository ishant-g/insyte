"""Asset, relationship and graph schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_type: str
    value: str
    label: str | None
    status: str
    confidence: int
    sources: list[Any]
    source_count: int
    observation_count: int
    is_target: bool
    in_scope: bool
    attributes: dict[str, Any]
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime


class RelationshipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relation: str
    confidence: int
    sources: list[Any]


class GraphNode(BaseModel):
    id: str
    asset_type: str
    value: str
    confidence: int
    is_target: bool
    in_scope: bool
    sources: list[Any]


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    confidence: int


class GraphRead(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class AssetDetailRead(AssetRead):
    evidence: dict[str, Any]
    outgoing: list[RelationshipRead]
    incoming: list[RelationshipRead]
