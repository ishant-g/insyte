"""ORM models.

Importing this package registers every mapper, which Alembic autogenerate
and `database.create_all()` both depend on.
"""

from app.database.base import Base
from app.models.enums import (
    ApiType,
    ArtifactKind,
    AssetType,
    ChangeKind,
    ConfidenceBand,
    ExposureLevel,
    FindingCategory,
    FindingStatus,
    ModuleCategory,
    ModuleStatus,
    ObservationStatus,
    RelationType,
    ReportFormat,
    ReportStatus,
    ScanMode,
    ScanStatus,
    Severity,
    SourceKind,
    UrlClassification,
)
from app.models.graph import Asset, AssetRelationship, Observation, Source
from app.models.intelligence import (
    ApiEndpoint,
    Artifact,
    Certificate,
    DnsRecord,
    HistoricalEvent,
    JavaScriptArtifact,
    Technology,
    Url,
)
from app.models.report import Report
from app.models.risk import Cve, Finding, IndexedExposure
from app.models.scan import Scan, ScanLog, ScanModule
from app.models.schedule import ScanSchedule
from app.models.target import Project, ScanTag, Target
from app.models.user import ApiCredential, User

__all__ = [
    "ApiCredential",
    "ApiEndpoint",
    "ApiType",
    "Artifact",
    "ArtifactKind",
    "Asset",
    "AssetRelationship",
    "AssetType",
    "Base",
    "Certificate",
    "ChangeKind",
    "ConfidenceBand",
    "Cve",
    "DnsRecord",
    "ExposureLevel",
    "Finding",
    "FindingCategory",
    "FindingStatus",
    "HistoricalEvent",
    "IndexedExposure",
    "JavaScriptArtifact",
    "ModuleCategory",
    "ModuleStatus",
    "Observation",
    "ObservationStatus",
    "Project",
    "RelationType",
    "Report",
    "ReportFormat",
    "ReportStatus",
    "Scan",
    "ScanLog",
    "ScanMode",
    "ScanModule",
    "ScanSchedule",
    "ScanStatus",
    "ScanTag",
    "Severity",
    "Source",
    "SourceKind",
    "Target",
    "Technology",
    "Url",
    "UrlClassification",
    "User",
]
