"""Target parsing, validation and normalization.

Insyte accepts exactly three kinds of target: a domain name, an IPv4
address, or an IPv6 address. This module is the single place that decides
which one it is, and it is deliberately strict - the brief's rule is
"do not incorrectly treat arbitrary strings as domains".

The same code runs for API input validation and inside the workers, so a
target that reached the database is always already normalized. Frontend
validation exists for the user's benefit only and is never trusted.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

import idna

from app.core.public_suffix import public_suffix, registrable_domain


class TargetType(str, Enum):
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class TargetError(ValueError):
    """Raised when an input cannot be interpreted as a valid target."""


#: Maximum length of a DNS name in presentation format.
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63

#: A single label of an already-punycoded domain name.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

#: The TLD may not be all-numeric - that is what distinguishes a domain
#: from a dotted-quad, and it is what stops "1.2.3.4.5" being a domain.
_NUMERIC_RE = re.compile(r"^[0-9]+$")

_ALLOWED_SCHEMES = frozenset({"http", "https"})

#: "javascript:", "file:", "gopher:" … - a scheme with no "//" authority.
_SCHEME_PREFIX_RE = re.compile(r"^[a-z][a-z0-9+.\-]*:", re.I)


def _is_host_port(value: str) -> bool:
    """True when `value` is `host:digits` with nothing else - a port, not
    a URI scheme's payload."""
    host, sep, rest = value.partition(":")
    return bool(sep) and rest.isdigit() and 1 <= len(rest) <= 5 and bool(host)


def _is_bare_ipv6(value: str) -> bool:
    """True when `value` is an unbracketed IPv6 literal with no URL parts."""
    if value.count(":") < 2 or "/" in value or "@" in value:
        return False
    candidate = value.split("%", 1)[0]
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class Target:
    """A validated, normalized scan target."""

    #: Canonical value: lowercase punycode domain, or compressed IP literal.
    value: str
    target_type: TargetType
    #: Exactly what the user typed, for display and provenance.
    original: str
    #: Unicode presentation form of a domain (== value for ASCII domains).
    unicode_value: str | None = None
    #: eTLD+1, e.g. "example.co.uk" for "api.dev.example.co.uk".
    registrable: str | None = None
    #: The public suffix itself, e.g. "co.uk".
    suffix: str | None = None
    #: Labels to the left of the registrable domain, e.g. "api.dev".
    subdomain: str | None = None

    @property
    def is_ip(self) -> bool:
        return self.target_type in (TargetType.IPV4, TargetType.IPV6)

    @property
    def is_domain(self) -> bool:
        return self.target_type is TargetType.DOMAIN

    @property
    def tld(self) -> str | None:
        if not self.suffix:
            return None
        return self.suffix.rsplit(".", 1)[-1]

    @property
    def is_apex(self) -> bool:
        """True when the target is the registrable domain itself."""
        return self.is_domain and self.value == self.registrable

    @property
    def http_origin(self) -> str:
        """Origin to use for Web Surface Collection."""
        host = f"[{self.value}]" if self.target_type is TargetType.IPV6 else self.value
        return f"https://{host}"

    @property
    def slug(self) -> str:
        """Filesystem- and URL-safe identifier derived from the target.

        Used for report filenames. Deliberately built by *filtering* the
        canonical value rather than escaping the user's string, so no
        traversal sequence can survive into a path.
        """
        cleaned = re.sub(r"[^a-z0-9]+", "-", self.value.lower()).strip("-")
        return cleaned[:80] or "target"

    def as_dict(self) -> dict[str, str | None]:
        return {
            "value": self.value,
            "type": self.target_type.value,
            "original": self.original,
            "unicode": self.unicode_value,
            "registrable_domain": self.registrable,
            "public_suffix": self.suffix,
            "tld": self.tld,
            "subdomain": self.subdomain,
        }


def _strip_wrapper(raw: str) -> str:
    """Remove a URL wrapper, leaving a bare host.

    Accepts what a user is likely to paste: a full URL, a scheme-relative
    URL, a host:port pair, a trailing slash, surrounding whitespace or
    angle brackets.
    """
    value = raw.strip().strip("<>").strip()
    if not value:
        raise TargetError("Target is empty.")

    # Reject control characters outright - these are the building blocks of
    # header-injection and log-forging payloads.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise TargetError("Target contains control characters.")

    if "://" in value:
        scheme = value.split("://", 1)[0].lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise TargetError(
                f"Unsupported scheme '{scheme}'. Only http and https are accepted."
            )
        parts = urlsplit(value)
    elif value.startswith("//"):
        parts = urlsplit("https:" + value)
    elif _is_bare_ipv6(value):
        # A bare IPv6 literal must be handled before urlsplit sees it:
        # urlsplit reads "2001:4860:4860::8888" as host "2001" with a
        # nonsense port, so the brief's own IPv6 example would be rejected.
        return value.lower()
    elif _SCHEME_PREFIX_RE.match(value) and not _is_host_port(value):
        # RFC 3986 technically allows dots in a scheme name, which makes a
        # bare "host:port" (e.g. "sub.example.com:8443") match this same
        # prefix shape as "javascript:alert(1)" or "data:...". The two are
        # told apart by what follows the colon: a scheme's payload is never
        # purely numeric, a port always is.
        scheme = value.split(":", 1)[0].lower()
        raise TargetError(
            f"Unsupported scheme '{scheme}'. Only http and https are accepted."
        )
    else:
        # Bare host, possibly with a path or port. urlsplit needs a scheme
        # to populate .hostname, so give it one.
        parts = urlsplit("https://" + value)

    if parts.username or parts.password:
        raise TargetError("Target must not contain credentials.")

    host = parts.hostname  # already lowercased, IPv6 brackets removed
    if not host:
        raise TargetError("Could not extract a host from the target.")
    try:
        # Accessing .port validates it; we then discard it - Insyte scans a
        # host, not a port, and honouring a port here would invite the
        # "passive port scan" the product boundary forbids.
        _ = parts.port
    except ValueError as exc:
        raise TargetError("Target contains an invalid port.") from exc
    return host


def _parse_ip(host: str) -> Target | None:
    """Return a Target if `host` is an IP literal, else None.

    Only canonical presentation forms are accepted. Decimal ("2130706433"),
    octal ("0177.0.0.1") and hexadecimal ("0x7f.1") notations are rejected
    rather than normalized: they are overwhelmingly SSRF-evasion artefacts,
    not something a user types on purpose.
    """
    candidate = host.strip("[]")

    # An IPv6 zone id (fe80::1%eth0) is meaningless to a remote scanner.
    if "%" in candidate:
        raise TargetError("IPv6 zone identifiers are not supported.")

    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        # Not an IP. But if every label is numeric it is not a domain
        # either - catch the obfuscated-IP forms here.
        labels = candidate.split(".")
        if labels and all(_NUMERIC_RE.match(label) for label in labels):
            raise TargetError(
                "Target looks like a malformed or non-standard IP address. "
                "Use dotted-quad IPv4 (8.8.8.8) or standard IPv6 notation."
            ) from None
        if candidate.lower().startswith("0x") or ":" in candidate:
            raise TargetError(
                "Target looks like a malformed IP address literal."
            ) from None
        return None

    if isinstance(parsed, ipaddress.IPv4Address):
        # ipaddress accepts "8.8.8.8" but rejects leading zeros in 3.9.5+;
        # re-serialising guarantees the canonical form either way.
        return Target(
            value=str(parsed),
            target_type=TargetType.IPV4,
            original=host,
        )

    # IPv4-mapped and IPv4-compatible IPv6 are a classic filter-bypass
    # shape (::ffff:127.0.0.1). Normalize to the embedded IPv4 so the SSRF
    # guard and every downstream module see one representation.
    mapped = getattr(parsed, "ipv4_mapped", None) or (
        parsed.sixtofour if hasattr(parsed, "sixtofour") else None
    )
    if mapped is not None:
        return Target(
            value=str(mapped),
            target_type=TargetType.IPV4,
            original=host,
        )

    return Target(
        value=str(parsed.compressed),
        target_type=TargetType.IPV6,
        original=host,
    )


def _parse_domain(host: str, original: str) -> Target:
    """Validate and normalize a domain name, including IDN handling."""
    name = host.rstrip(".")  # a fully-qualified trailing dot is equivalent
    if not name:
        raise TargetError(f"'{original.strip()[:60]}' is not a valid target.")

    if "." not in name:
        raise TargetError(
            "Target must be a fully-qualified domain name (e.g. example.com), "
            "an IPv4 address, or an IPv6 address."
        )

    if "_" in name:
        # Underscores are legal in some DNS records but not in hostnames,
        # and an underscore label is never a scannable web target.
        raise TargetError("Domain labels must not contain underscores.")

    # IDN → punycode. uts46 applies the standard mapping (case folding,
    # NFC, disallowed-character rejection) so homoglyph and mixed-script
    # tricks fail here rather than three modules later.
    try:
        ascii_name = idna.encode(name, uts46=True, std3_rules=True).decode("ascii")
    except idna.IDNAError as exc:
        raise TargetError(f"Invalid international domain name: {exc}") from exc

    ascii_name = ascii_name.lower()

    if len(ascii_name) > MAX_DOMAIN_LENGTH:
        raise TargetError(
            f"Domain exceeds the maximum length of {MAX_DOMAIN_LENGTH} characters."
        )

    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise TargetError("Domain must contain at least two labels.")

    for label in labels:
        if not label:
            raise TargetError("Domain contains an empty label.")
        if len(label) > MAX_LABEL_LENGTH:
            raise TargetError(
                f"Domain label '{label[:20]}…' exceeds "
                f"{MAX_LABEL_LENGTH} characters."
            )
        if not _LABEL_RE.match(label):
            raise TargetError(
                f"Domain label '{label}' contains characters that are not "
                "valid in a hostname."
            )

    tld = labels[-1]
    if _NUMERIC_RE.match(tld):
        raise TargetError(
            "The last label of a domain cannot be all digits. "
            "If you meant an IP address, use standard notation."
        )
    if len(tld) < 2:
        raise TargetError("Top-level domain must be at least two characters.")

    try:
        unicode_name = idna.decode(ascii_name)
    except idna.IDNAError:
        unicode_name = ascii_name

    suffix = public_suffix(ascii_name)
    registrable = registrable_domain(ascii_name)
    subdomain: str | None = None
    if registrable and ascii_name != registrable:
        subdomain = ascii_name[: -(len(registrable) + 1)] or None

    return Target(
        value=ascii_name,
        target_type=TargetType.DOMAIN,
        original=original.strip(),
        unicode_value=unicode_name,
        registrable=registrable,
        suffix=suffix,
        subdomain=subdomain,
    )


def parse_target(raw: str) -> Target:
    """Parse user input into a validated `Target`.

    Raises:
        TargetError: with a message safe to show the user.
    """
    if not isinstance(raw, str):
        raise TargetError("Target must be a string.")
    if len(raw) > 2048:
        raise TargetError("Target is too long.")

    host = _strip_wrapper(raw)

    ip_target = _parse_ip(host)
    if ip_target is not None:
        return Target(
            value=ip_target.value,
            target_type=ip_target.target_type,
            original=raw.strip(),
        )

    return _parse_domain(host, raw)


def normalize_hostname(raw: str) -> str | None:
    """Best-effort hostname normalization for discovered (not user) values.

    Discovered hostnames come from certificates, DNS answers, JavaScript
    and archives, so they are frequently malformed. This returns None
    instead of raising - a bad value is dropped, never propagated.
    """
    if not raw or not isinstance(raw, str):
        return None
    candidate = raw.strip().strip(".").lower()
    if not candidate or len(candidate) > MAX_DOMAIN_LENGTH:
        return None
    # Wildcard SANs are meaningful; keep the wildcard but validate the rest.
    wildcard = candidate.startswith("*.")
    if wildcard:
        candidate = candidate[2:]
    try:
        target = _parse_domain(candidate, candidate)
    except TargetError:
        return None
    return f"*.{target.value}" if wildcard else target.value


def is_subdomain_of(candidate: str, parent: str) -> bool:
    """True when `candidate` is `parent` or sits beneath it.

    Compares whole labels, so "notexample.com" is not a subdomain of
    "example.com" - the substring check that mistake produces is a common
    source of scope creep in recon tooling.
    """
    candidate = (candidate or "").strip(".").lower().lstrip("*.")
    parent = (parent or "").strip(".").lower().lstrip("*.")
    if not candidate or not parent:
        return False
    if candidate == parent:
        return True
    return candidate.endswith("." + parent)
