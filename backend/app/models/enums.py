"""Domain enumerations shared by models, schemas and the frontend.

These are string enums stored as text rather than PostgreSQL ENUM types:
adding a module category or asset type should not require a migration, and
the values are validated at the Pydantic boundary anyway.
"""

from __future__ import annotations

from enum import Enum


class ScanMode(str, Enum):
    """The two first-class collection postures."""

    #: Third-party and public datasets, plus at most one unauthenticated GET
    #: per well-known resource on the target itself (homepage, robots.txt,
    #: sitemap.xml, `.well-known/*`) - never a crawl, never a second request
    #: for the same resource, never a request that depends on what an
    #: earlier one to the target returned.
    PASSIVE = "passive"
    #: Adds a same-origin crawl: linked pages up to a page budget, and the
    #: JavaScript/CSS those pages reference.
    WEB_SURFACE = "web_surface"

    @property
    def label(self) -> str:
        return {
            ScanMode.PASSIVE: "Passive Intelligence",
            ScanMode.WEB_SURFACE: "Web Surface Collection",
        }[self]

    @property
    def disclosure(self) -> str:
        return {
            ScanMode.PASSIVE: (
                "Sourced primarily from third-party and public records. "
                "May also perform a single read-only GET of the target's "
                "homepage, robots.txt, sitemap.xml and well-known resources "
                "- one request per resource, never a crawl, never a repeat "
                "request, no forms, no brute forcing, no port scanning."
            ),
            ScanMode.WEB_SURFACE: (
                "Opt-in low-impact collection. Read-only HTTP GET of publicly "
                "linked pages and the JavaScript/CSS they reference, beyond "
                "what Passive mode alone retrieves. No POST, no fuzzing, no "
                "brute forcing, no port scanning."
            ),
        }[self]


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    #: Finished, but at least one selected module failed or was skipped.
    PARTIAL = "partial"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (
            ScanStatus.PARTIAL,
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        )


class ModuleStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    #: Not run: unsupported in this mode, missing credential, or a
    #: prerequisite module produced nothing to work from.
    SKIPPED = "skipped"


class ModuleCategory(str, Enum):
    CORE = "core"
    WEB_SURFACE = "web_surface"
    HISTORICAL = "historical"
    EXTERNAL = "external"
    EXPOSURE = "exposure"
    RISK = "risk"

    @property
    def label(self) -> str:
        return {
            ModuleCategory.CORE: "Core Intelligence",
            ModuleCategory.WEB_SURFACE: "Web Surface",
            ModuleCategory.HISTORICAL: "Historical",
            ModuleCategory.EXTERNAL: "External Intelligence",
            ModuleCategory.EXPOSURE: "Exposure",
            ModuleCategory.RISK: "Risk & CVE",
        }[self]


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    NETBLOCK = "netblock"
    URL = "url"
    API_ENDPOINT = "api_endpoint"
    JAVASCRIPT = "javascript"
    STYLESHEET = "stylesheet"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    CLOUD_RESOURCE = "cloud_resource"
    REPOSITORY = "repository"
    DOCUMENT = "document"
    EMAIL = "email"
    SOURCE_MAP = "source_map"
    DNS_RECORD = "dns_record"
    NAMESERVER = "nameserver"
    MAIL_SERVER = "mail_server"
    EXPOSURE = "exposure"
    FINDING = "finding"


class RelationType(str, Enum):
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    HOSTED_BY = "HOSTED_BY"
    USES_CERTIFICATE = "USES_CERTIFICATE"
    CERTIFICATE_COVERS = "CERTIFICATE_COVERS"
    USES_TECHNOLOGY = "USES_TECHNOLOGY"
    REFERENCES = "REFERENCES"
    DISCOVERS = "DISCOVERS"
    CONTAINS_ENDPOINT = "CONTAINS_ENDPOINT"
    FOUND_IN = "FOUND_IN"
    HISTORICALLY_SEEN_ON = "HISTORICALLY_SEEN_ON"
    RELATED_TO = "RELATED_TO"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    USES_CDN = "USES_CDN"
    USES_WAF = "USES_WAF"
    SERVES_MAIL_FOR = "SERVES_MAIL_FOR"
    DELEGATED_TO = "DELEGATED_TO"
    EXPOSES = "EXPOSES"
    AFFECTED_BY = "AFFECTED_BY"


class ObservationStatus(str, Enum):
    """How an observation relates to *now*.

    Deliberately does not include "deleted" or "gone": a source ceasing to
    report an asset is not evidence that the asset was removed, and the
    brief is explicit that Insyte must not claim otherwise.
    """

    OBSERVED = "observed"
    HISTORICAL = "historical"
    CURRENT_OBSERVATION = "current_observation"
    REMOVED_FROM_SOURCE = "removed_from_source"
    UNKNOWN = "unknown"


class SourceKind(str, Enum):
    PASSIVE = "passive"
    WEB_SURFACE = "web_surface"
    HISTORICAL = "historical"
    EXTERNAL = "external"
    DERIVED = "derived"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFORMATIONAL: 1,
        }[self]

    @property
    def base_weight(self) -> int:
        """Contribution to the Insyte exposure score, before modifiers."""
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 12,
            Severity.LOW: 5,
            Severity.INFORMATIONAL: 0,
        }[self]


class FindingCategory(str, Enum):
    SECRET_INDICATOR = "secret_indicator"
    SOURCE_MAP_EXPOSURE = "source_map_exposure"
    VULNERABLE_COMPONENT = "vulnerable_component"
    TLS_CONFIGURATION = "tls_configuration"
    SECURITY_HEADER = "security_header"
    DNS_CONFIGURATION = "dns_configuration"
    EMAIL_SECURITY = "email_security"
    API_DOCUMENTATION_EXPOSURE = "api_documentation_exposure"
    TECHNOLOGY_DISCLOSURE = "technology_disclosure"
    INDEXED_ARTIFACT = "indexed_artifact"
    HISTORICAL_EXPOSURE = "historical_exposure"
    CERTIFICATE = "certificate"
    CLOUD_EXPOSURE = "cloud_exposure"
    ATTACK_SURFACE = "attack_surface"
    NETWORK_REPUTATION = "network_reputation"
    INFORMATIONAL = "informational"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ExposureLevel(str, Enum):
    """How reachable the thing a finding describes actually is."""

    #: Directly retrievable right now over plain HTTP GET.
    DIRECT = "direct"
    #: Present in a public index or archive, not confirmed live.
    INDEXED = "indexed"
    #: Only ever seen historically.
    HISTORICAL = "historical"
    #: Inferred from metadata; not retrieved.
    INFERRED = "inferred"

    @property
    def multiplier(self) -> float:
        return {
            ExposureLevel.DIRECT: 1.0,
            ExposureLevel.INDEXED: 0.75,
            ExposureLevel.HISTORICAL: 0.5,
            ExposureLevel.INFERRED: 0.4,
        }[self]


class ConfidenceBand(str, Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

    @classmethod
    def from_score(cls, score: int) -> ConfidenceBand:
        if score >= 95:
            return cls.VERY_HIGH
        if score >= 80:
            return cls.HIGH
        if score >= 60:
            return cls.MEDIUM
        if score >= 40:
            return cls.LOW
        return cls.VERY_LOW

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()


class UrlClassification(str, Enum):
    PAGE = "page"
    API = "api"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    JAVASCRIPT = "javascript"
    STYLESHEET = "stylesheet"
    IMAGE = "image"
    FONT = "font"
    MEDIA = "media"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    DOWNLOAD = "download"
    AUTHENTICATION = "authentication"
    ADMIN = "admin"
    CONFIGURATION = "configuration"
    SOURCE_MAP = "source_map"
    WELL_KNOWN = "well_known"
    FEED = "feed"
    UNKNOWN = "unknown"


class ApiType(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    OAUTH = "oauth"
    OPENAPI = "openapi"
    SWAGGER = "swagger"
    SOAP = "soap"
    GRPC_WEB = "grpc_web"
    AUTHENTICATION = "authentication"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"


class ArtifactKind(str, Enum):
    HTML = "html"
    JAVASCRIPT = "javascript"
    STYLESHEET = "stylesheet"
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    TEXT = "text"
    ROBOTS = "robots"
    SITEMAP = "sitemap"
    SOURCE_MAP = "source_map"
    MANIFEST = "manifest"
    WELL_KNOWN = "well_known"
    DOCUMENT = "document"
    OTHER = "other"


class ReportFormat(str, Enum):
    PDF = "pdf"
    MARKDOWN = "md"
    JSON = "json"

    @property
    def media_type(self) -> str:
        return {
            ReportFormat.PDF: "application/pdf",
            ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
            ReportFormat.JSON: "application/json",
        }[self]

    @property
    def extension(self) -> str:
        return self.value


class ReportStatus(str, Enum):
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class ChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
