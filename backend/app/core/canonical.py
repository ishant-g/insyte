"""Canonicalisation and hashing - the basis of all deduplication.

Insyte discovers the same URL from five different sources with five
different spellings (trailing slash, `utm_source`, mixed-case host, an
explicit `:443`). Deduplication only works if every module reduces a value
to the same canonical string, so that logic lives here rather than in each
module.

The original string is always preserved alongside the canonical one: the
raw spelling is the evidence, and throwing it away would make a finding
unverifiable.

Ported and extended from the predecessor's `url_collection/normalizer.py`,
which had the right rules; this version adds a stable hash, scope
evaluation against the target, and the fuller classification set the brief
asks for.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit

from app.core.public_suffix import registrable_domain
from app.core.target import is_subdomain_of, normalize_hostname
from app.models.enums import UrlClassification

DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}

#: Query parameters that identify a campaign or a session rather than a
#: resource. Removed from the canonical form so the same page tracked three
#: ways is one URL - but see `CanonicalUrl.original`, which keeps the raw.
TRACKING_PARAMS: frozenset[str] = frozenset(
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_source_platform", "utm_creative_format",
        "utm_marketing_tactic", "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
        "fbclid", "msclkid", "twclid", "igshid", "ttclid", "li_fat_id",
        "mc_cid", "mc_eid", "_ga", "_gl", "yclid", "vero_id", "vero_conv",
        "s_cid", "ref_src", "ref_url", "spm", "scm", "share_source",
        "__hsfp", "__hssc", "__hstc", "hsCtaTracking", "_hsenc", "_hsmi",
        "mkt_tok", "trk", "trkCampaign", "sc_campaign", "sc_channel",
        "sc_content", "sc_medium", "sc_outcome", "sc_geo", "sc_country",
        "epik", "pk_campaign", "pk_kwd", "piwik_campaign", "piwik_kwd",
        "cmpid", "campaignid", "adgroupid", "gad_source",
    }
)

#: Extension → classification.
_EXTENSION_CLASS: dict[str, UrlClassification] = {
    "js": UrlClassification.JAVASCRIPT,
    "mjs": UrlClassification.JAVASCRIPT,
    "cjs": UrlClassification.JAVASCRIPT,
    "jsx": UrlClassification.JAVASCRIPT,
    "ts": UrlClassification.JAVASCRIPT,
    "tsx": UrlClassification.JAVASCRIPT,
    "css": UrlClassification.STYLESHEET,
    "scss": UrlClassification.STYLESHEET,
    "sass": UrlClassification.STYLESHEET,
    "less": UrlClassification.STYLESHEET,
    "map": UrlClassification.SOURCE_MAP,
    "png": UrlClassification.IMAGE,
    "jpg": UrlClassification.IMAGE,
    "jpeg": UrlClassification.IMAGE,
    "gif": UrlClassification.IMAGE,
    "svg": UrlClassification.IMAGE,
    "webp": UrlClassification.IMAGE,
    "avif": UrlClassification.IMAGE,
    "ico": UrlClassification.IMAGE,
    "bmp": UrlClassification.IMAGE,
    "tiff": UrlClassification.IMAGE,
    "woff": UrlClassification.FONT,
    "woff2": UrlClassification.FONT,
    "ttf": UrlClassification.FONT,
    "otf": UrlClassification.FONT,
    "eot": UrlClassification.FONT,
    "mp4": UrlClassification.MEDIA,
    "webm": UrlClassification.MEDIA,
    "mp3": UrlClassification.MEDIA,
    "wav": UrlClassification.MEDIA,
    "ogg": UrlClassification.MEDIA,
    "m3u8": UrlClassification.MEDIA,
    "pdf": UrlClassification.DOCUMENT,
    "doc": UrlClassification.DOCUMENT,
    "docx": UrlClassification.DOCUMENT,
    "xls": UrlClassification.DOCUMENT,
    "xlsx": UrlClassification.DOCUMENT,
    "ppt": UrlClassification.DOCUMENT,
    "pptx": UrlClassification.DOCUMENT,
    "csv": UrlClassification.DOCUMENT,
    "tsv": UrlClassification.DOCUMENT,
    "rtf": UrlClassification.DOCUMENT,
    "odt": UrlClassification.DOCUMENT,
    "ods": UrlClassification.DOCUMENT,
    "zip": UrlClassification.ARCHIVE,
    "tar": UrlClassification.ARCHIVE,
    "gz": UrlClassification.ARCHIVE,
    "tgz": UrlClassification.ARCHIVE,
    "bz2": UrlClassification.ARCHIVE,
    "xz": UrlClassification.ARCHIVE,
    "7z": UrlClassification.ARCHIVE,
    "rar": UrlClassification.ARCHIVE,
    "bak": UrlClassification.ARCHIVE,
    "sql": UrlClassification.CONFIGURATION,
    "env": UrlClassification.CONFIGURATION,
    "yml": UrlClassification.CONFIGURATION,
    "yaml": UrlClassification.CONFIGURATION,
    "ini": UrlClassification.CONFIGURATION,
    "conf": UrlClassification.CONFIGURATION,
    "cfg": UrlClassification.CONFIGURATION,
    "toml": UrlClassification.CONFIGURATION,
    "properties": UrlClassification.CONFIGURATION,
    "log": UrlClassification.CONFIGURATION,
    "xml": UrlClassification.FEED,
    "rss": UrlClassification.FEED,
    "atom": UrlClassification.FEED,
    "html": UrlClassification.PAGE,
    "htm": UrlClassification.PAGE,
    "php": UrlClassification.PAGE,
    "asp": UrlClassification.PAGE,
    "aspx": UrlClassification.PAGE,
    "jsp": UrlClassification.PAGE,
}

_API_PATH_HINTS: tuple[str, ...] = (
    "/api/", "/api.", "/apis/", "/rest/", "/restapi/", "/rpc/", "/jsonrpc",
    "/v1/", "/v2/", "/v3/", "/v4/", "/wp-json/", "/services/", "/service/",
    "/gateway/", "/edge/", "/_next/data/", "/query", "/data/",
)
_GRAPHQL_HINTS: tuple[str, ...] = ("/graphql", "/graphiql", "/gql", "/altair")
_WEBSOCKET_HINTS: tuple[str, ...] = (
    "/socket.io", "/sockjs", "/websocket", "/ws", "/wss", "/hub", "/signalr",
    "/cable", "/live", "/centrifugo",
)
_AUTH_HINTS: tuple[str, ...] = (
    "/oauth", "/oauth2", "/authorize", "/token", "/login", "/signin",
    "/sign-in", "/logout", "/signout", "/sso", "/saml", "/auth/",
    "/session", "/jwks", "/openid", "/connect/", "/mfa", "/2fa",
    "/register", "/signup", "/sign-up", "/password", "/forgot",
)
_ADMIN_HINTS: tuple[str, ...] = (
    "/admin", "/administrator", "/wp-admin", "/dashboard", "/console",
    "/manage", "/management", "/cpanel", "/phpmyadmin", "/adminer",
    "/backend", "/internal", "/staff", "/moderator", "/_admin",
)
_CONFIG_HINTS: tuple[str, ...] = (
    "/.env", "/.git", "/config", "/settings", "/secrets", "/credentials",
    "/docker-compose", "/dockerfile", "/.npmrc", "/.aws", "/web.config",
    "/appsettings", "/application.properties", "/.htaccess", "/.htpasswd",
)
_DOC_HINTS: tuple[str, ...] = (
    "/swagger", "/openapi", "/api-docs", "/apidocs", "/redoc", "/docs/api",
    "/rapidoc", "/scalar", "/stoplight",
)

_MULTI_SLASH = re.compile(r"/{2,}")
_TRAVERSAL = re.compile(r"/\.\.?(?=/|$)")


def value_hash(value: str) -> str:
    """Stable digest used as the dedup key for long values.

    PostgreSQL btree indexes cap at roughly 2704 bytes per entry, so a URL
    column cannot itself carry the unique constraint. Hashing gives a
    fixed-width key and makes lookups index-only.
    """
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def fingerprint(*parts: object) -> str:
    """Stable digest over an ordered tuple of parts.

    Used for finding fingerprints, so the same issue in two scans of the
    same target produces the same value and scan-to-scan diff can match it.
    """
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()


@dataclass(frozen=True, slots=True)
class CanonicalUrl:
    """A URL reduced to canonical form, with its raw spelling preserved."""

    original: str
    normalized: str
    scheme: str
    host: str
    port: int | None
    path: str
    query_keys: tuple[str, ...]
    fragment: str
    extension: str | None
    depth: int
    classification: UrlClassification
    in_scope: bool
    #: True when the URL points at the same registrable domain as the target
    #: but a different host (i.e. a sibling subdomain).
    same_registrable: bool

    @property
    def hash(self) -> str:
        return value_hash(self.normalized)

    @property
    def origin(self) -> str:
        netloc = self.host if self.port is None else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"

    @property
    def is_http(self) -> bool:
        return self.scheme in ("http", "https")


def _collapse_path(path: str) -> str:
    """Collapse duplicate slashes and resolve traversal segments.

    Resolving `..` here is a security property, not cosmetics: an
    un-resolved `/a/../../etc/passwd` would compare unequal to the path it
    actually addresses, which defeats both dedup and scope checks.
    """
    if not path:
        return "/"
    path = _MULTI_SLASH.sub("/", path)
    if not path.startswith("/"):
        path = "/" + path
    if "/." not in path:
        return path
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    resolved = "/" + "/".join(segments)
    if path.endswith("/") and not resolved.endswith("/"):
        resolved += "/"
    return resolved


def _canonical_path(path: str) -> str:
    """Resolve a path to the single string it actually addresses.

    Percent-encoding is unwrapped before traversal is resolved, and
    unwrapped repeatedly (bounded) because `%252e%252e%252f` decodes to
    `%2e%2e%2f`, which decodes again to `../`. Resolving only the outermost
    layer would leave two spellings of the same path comparing unequal,
    which defeats both deduplication and the scope check.

    The result is re-encoded once so the canonical form is a single stable
    encoding. The raw spelling stays on `CanonicalUrl.original`.
    """
    current = path or "/"
    for _ in range(3):
        try:
            decoded = unquote(current)
        except Exception:  # noqa: BLE001 - hostile input is never fatal
            break
        if decoded == current:
            break
        current = decoded
    collapsed = _collapse_path(current)
    return quote(collapsed, safe="/:@!$&'()*+,;=~-._")


def classify_url(host: str, path: str, extension: str | None, scheme: str) -> UrlClassification:
    """Assign a classification from the URL's shape alone.

    Order matters: a `/api/v2/report.pdf` is more usefully an API path than
    a document, and `/swagger.json` is documentation before it is JSON.
    """
    lowered = path.lower()

    if extension == "map" or lowered.endswith(".map"):
        return UrlClassification.SOURCE_MAP
    if lowered.startswith("/.well-known/"):
        return UrlClassification.WELL_KNOWN
    if scheme in ("ws", "wss"):
        return UrlClassification.WEBSOCKET
    if any(hint in lowered for hint in _GRAPHQL_HINTS):
        return UrlClassification.GRAPHQL
    if any(hint in lowered for hint in _DOC_HINTS):
        return UrlClassification.API
    if any(hint in lowered for hint in _CONFIG_HINTS):
        return UrlClassification.CONFIGURATION
    if any(hint in lowered for hint in _AUTH_HINTS):
        return UrlClassification.AUTHENTICATION
    if any(hint in lowered for hint in _ADMIN_HINTS):
        return UrlClassification.ADMIN
    if any(
        lowered == hint.rstrip("/") or lowered.startswith(hint)
        for hint in _WEBSOCKET_HINTS
    ):
        return UrlClassification.WEBSOCKET
    if any(hint in lowered for hint in _API_PATH_HINTS):
        return UrlClassification.API

    if extension and extension in _EXTENSION_CLASS:
        return _EXTENSION_CLASS[extension]

    if lowered in ("/robots.txt", "/security.txt", "/humans.txt", "/ads.txt", "/app-ads.txt"):
        return UrlClassification.WELL_KNOWN
    if "sitemap" in lowered:
        return UrlClassification.FEED
    if not extension:
        return UrlClassification.PAGE
    return UrlClassification.UNKNOWN


def canonical_url(
    raw: str,
    *,
    base: str | None = None,
    target_host: str | None = None,
    keep_query: bool = True,
) -> CanonicalUrl | None:
    """Reduce a raw URL reference to canonical form.

    Returns None for anything that is not a fetchable http(s)/ws(s) URL -
    `mailto:`, `data:`, `javascript:`, `about:`, `blob:` and malformed
    input. Callers that want the discarded values (an email address from a
    `mailto:` link, say) extract them separately; silently coercing them
    into URLs is how `javascript:` payloads end up in an href.
    """
    if not raw or not isinstance(raw, str):
        return None
    candidate = raw.strip().strip('\'"`')
    if not candidate or len(candidate) > 4096:
        return None
    # Control characters in a URL are either a parser trick or corruption.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return None

    lowered = candidate.lower()
    if lowered.startswith(
        ("mailto:", "tel:", "sms:", "data:", "javascript:", "vbscript:",
         "blob:", "about:", "file:", "ftp:", "chrome:", "chrome-extension:",
         "intent:", "market:", "itms-apps:", "#")
    ):
        return None

    if candidate.startswith("//"):
        base_scheme = "https"
        if base:
            base_scheme = urlsplit(base).scheme or "https"
        candidate = f"{base_scheme}:{candidate}"
    elif not lowered.startswith(("http://", "https://", "ws://", "wss://")):
        if not base:
            return None
        try:
            candidate = urljoin(base, candidate)
        except ValueError:
            return None
        if not candidate.lower().startswith(("http://", "https://", "ws://", "wss://")):
            return None

    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https", "ws", "wss"):
        return None

    host = normalize_hostname(parts.hostname or "") or (parts.hostname or "").lower()
    if not host:
        return None
    # An IP literal host will not survive normalize_hostname; accept it as-is.
    host = host.strip("[]").rstrip(".")
    if not host:
        return None

    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None

    path = _canonical_path(parts.path or "/")

    query_keys: tuple[str, ...] = ()
    query_string = ""
    if keep_query and parts.query:
        pairs = [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key.lower() not in TRACKING_PARAMS
        ]
        # Sorted so ?a=1&b=2 and ?b=2&a=1 canonicalise identically.
        pairs.sort()
        query_string = urlencode(pairs, doseq=True)
        query_keys = tuple(sorted({key for key, _ in pairs}))

    netloc = host if port is None else f"{host}:{port}"
    normalized = f"{scheme}://{netloc}{path}"
    if query_string:
        normalized = f"{normalized}?{query_string}"

    segments = [seg for seg in path.split("/") if seg]
    last = segments[-1] if segments else ""
    extension: str | None = None
    if "." in last and not last.startswith("."):
        candidate_ext = last.rsplit(".", 1)[-1].lower()
        if candidate_ext and len(candidate_ext) <= 12 and candidate_ext.isalnum():
            extension = candidate_ext

    in_scope = False
    same_reg = False
    if target_host:
        in_scope = is_subdomain_of(host, target_host)
        same_reg = bool(
            registrable_domain(host)
            and registrable_domain(host) == registrable_domain(target_host)
        )
        in_scope = in_scope or same_reg

    return CanonicalUrl(
        original=raw.strip(),
        normalized=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query_keys=query_keys,
        fragment=parts.fragment or "",
        extension=extension,
        depth=len(segments),
        classification=classify_url(host, path, extension, scheme),
        in_scope=in_scope,
        same_registrable=same_reg,
    )


def canonical_value(asset_type: str, value: str) -> str:
    """Canonical dedup key for a non-URL asset value."""
    text = (value or "").strip()
    if not text:
        return ""
    if asset_type in ("domain", "subdomain", "nameserver", "mail_server"):
        return (normalize_hostname(text) or text.lower().strip(".")).lower()
    if asset_type == "email":
        local, _, domain = text.partition("@")
        return f"{local.lower()}@{domain.lower().strip('.')}" if domain else text.lower()
    if asset_type == "asn":
        digits = re.sub(r"[^0-9]", "", text)
        return f"AS{digits}" if digits else text.upper()
    if asset_type == "technology":
        return re.sub(r"[\s_-]+", " ", text).strip().lower()
    if asset_type == "certificate":
        return text.lower().replace(":", "")
    return text.lower()
