"""URL, API, JavaScript, historical and exposure schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class UrlRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    normalized_url: str
    host: str
    classification: str
    extension: str | None
    status_code: int | None
    content_type: str | None
    retrieved: bool
    in_scope: bool
    confidence: int
    sources: list[Any]


class ApiEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    host: str
    path: str
    method: str | None
    api_type: str
    api_version: str | None
    auth_hint: str | None
    source_artifact: str | None
    validated: bool
    confidence: int
    sources: list[Any]


class JavaScriptRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    content_sha256: str | None
    size: int | None
    is_third_party: bool
    libraries: list[Any]
    endpoints: list[Any]
    domains: list[Any]
    integrations: list[Any]
    secret_indicators: list[Any]
    has_source_map: bool
    source_map_url: str | None


class HistoricalEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_type: str
    value: str
    source_id: str
    status: str
    observed_at: datetime | None
    first_seen: datetime | None
    last_seen: datetime | None
    year: int | None


class IndexedExposureRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    exposure_type: str
    url: str
    host: str | None
    observation_class: str
    retrievable: bool
    severity: str
    confidence: int


class CertificateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    fingerprint_sha256: str | None
    subject_cn: str | None
    issuer_cn: str | None
    issuer_org: str | None
    sans: list[Any]
    not_before: datetime | None
    not_after: datetime | None
    is_expired: bool
    days_until_expiry: int | None
    signature_algorithm: str | None
    public_key_algorithm: str | None
    tls_version: str | None


class DnsRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    record_type: str
    value: str
    ttl: int | None
    parsed: dict[str, Any]
