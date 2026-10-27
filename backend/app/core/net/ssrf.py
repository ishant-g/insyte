"""SSRF policy: what Insyte is allowed to connect to, and why.

Insyte's job is to fetch URLs that a scan target controls. That makes
server-side request forgery the platform's single largest risk: a hostile
target only has to put ``<script src="http://169.254.169.254/...">`` in its
homepage, or 302 the collector to ``http://127.0.0.1:6379/``, and an
unguarded crawler will happily reach into the infrastructure running it.

The policy implemented here is deny-by-default and applies at three points:

1. **Before DNS** - scheme, credentials, port and hostname shape.
2. **After DNS** - every address the name resolves to is checked, and the
   request is then *pinned* to one validated address. This is what closes
   the DNS-rebinding window: the name is resolved once, validated, and the
   socket connects to that exact address rather than re-resolving.
3. **On every redirect** - the hop's URL goes through 1 and 2 again from
   scratch. A public URL that redirects into RFC1918 is stopped at the hop.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.config import settings

ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Ports Insyte will connect to. Restricting this is defence in depth: the
#: private-range block already covers most internal services, but a
#: public-facing host that also exposes 6379 or 11211 should not be
#: reachable through the collector either.
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443, 8000, 3000, 5000})

#: IPv4 ranges Insyte must never connect to, with the reason it is refused.
BLOCKED_V4: tuple[tuple[ipaddress.IPv4Network, str], ...] = tuple(
    (ipaddress.ip_network(cidr), reason)  # type: ignore[misc]
    for cidr, reason in (
        ("0.0.0.0/8", "this-network / unspecified"),
        ("10.0.0.0/8", "RFC1918 private"),
        ("100.64.0.0/10", "RFC6598 carrier-grade NAT"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link-local / cloud instance metadata"),
        ("172.16.0.0/12", "RFC1918 private"),
        ("192.0.0.0/24", "IETF protocol assignments"),
        ("192.0.2.0/24", "TEST-NET-1 documentation"),
        ("192.88.99.0/24", "6to4 relay anycast"),
        ("192.168.0.0/16", "RFC1918 private"),
        ("198.18.0.0/15", "benchmarking"),
        ("198.51.100.0/24", "TEST-NET-2 documentation"),
        ("203.0.113.0/24", "TEST-NET-3 documentation"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved"),
        ("255.255.255.255/32", "broadcast"),
    )
)

#: IPv6 ranges Insyte must never connect to.
BLOCKED_V6: tuple[tuple[ipaddress.IPv6Network, str], ...] = tuple(
    (ipaddress.ip_network(cidr), reason)  # type: ignore[misc]
    for cidr, reason in (
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("::ffff:0:0/96", "IPv4-mapped"),
        ("::/96", "IPv4-compatible (deprecated)"),
        ("64:ff9b::/96", "NAT64 well-known prefix"),
        ("100::/64", "discard-only"),
        ("2001:db8::/32", "documentation"),
        ("2001::/32", "Teredo tunnelling"),
        ("2002::/16", "6to4"),
        ("fc00::/7", "unique local address"),
        ("fe80::/10", "link-local"),
        ("ff00::/8", "multicast"),
    )
)

#: Hostnames that must never resolve, regardless of what DNS says.
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        # Insyte's own compose service names - a target must never be able
        # to make the worker talk to the platform's own database or broker.
        "postgres",
        "redis",
        "api",
        "worker",
        "insyte-api",
        "insyte-worker",
        "insyte-postgres",
        "insyte-redis",
    }
)

#: Suffixes that only ever name something inside a private network.
BLOCKED_SUFFIXES: tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
    ".private",
    ".test",
    ".invalid",
    ".example",
    ".onion",
    ".svc",
    ".cluster.local",
    ".ec2.internal",
    ".compute.internal",
)


class SSRFBlocked(Exception):
    """Raised when the egress policy refuses a destination.

    The message is written to be safe to show a user: it names the policy
    that fired, never internal topology.
    """

    def __init__(self, reason: str, *, destination: str = "") -> None:
        self.reason = reason
        self.destination = destination
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class SafeUrl:
    """A URL that has passed pre-DNS validation."""

    url: str
    scheme: str
    hostname: str
    port: int
    path: str
    #: True when the hostname was already an IP literal (no DNS needed).
    is_ip_literal: bool


@dataclass(frozen=True, slots=True)
class PinnedDestination:
    """A validated destination, pinned to one specific address."""

    safe_url: SafeUrl
    #: The address the socket will actually connect to.
    address: str
    family: int
    #: Every address the name resolved to, all of which passed the policy.
    all_addresses: tuple[str, ...]

    @property
    def connect_url(self) -> str:
        """URL with the hostname replaced by the pinned literal address.

        The original hostname still travels in the `Host` header and as the
        TLS SNI value, so virtual hosting and certificate verification both
        keep working - see `SafeHttpClient`.
        """
        host = (
            f"[{self.address}]"
            if self.family == socket.AF_INET6
            else self.address
        )
        default_port = 443 if self.safe_url.scheme == "https" else 80
        netloc = host if self.safe_url.port == default_port else f"{host}:{self.safe_url.port}"
        return f"{self.safe_url.scheme}://{netloc}{self.safe_url.path}"

    @property
    def host_header(self) -> str:
        default_port = 443 if self.safe_url.scheme == "https" else 80
        if self.safe_url.port == default_port:
            return self.safe_url.hostname
        return f"{self.safe_url.hostname}:{self.safe_url.port}"


def ip_block_reason(address: str | ipaddress._BaseAddress) -> str | None:
    """Return why an address is refused, or None if it is allowed."""
    try:
        ip = (
            address
            if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            else ipaddress.ip_address(str(address))
        )
    except ValueError:
        return "not a valid IP address"

    if settings.ALLOW_PRIVATE_TARGETS:
        # Only ever true in the test suite, which points the collector at a
        # loopback fixture server to prove the *rest* of the pipeline works.
        return None

    if isinstance(ip, ipaddress.IPv6Address):
        # Unwrap the tunnelling and mapping forms before range-checking, so
        # ::ffff:127.0.0.1 and 2002:7f00:1:: cannot smuggle a private v4
        # address past a v6-only check.
        for embedded in (ip.ipv4_mapped, ip.sixtofour, _teredo_client(ip)):
            if embedded is not None:
                inner = ip_block_reason(embedded)
                if inner is not None:
                    return f"{inner} (embedded IPv4 in IPv6)"
        for network, reason in BLOCKED_V6:
            if ip in network:
                return reason
    else:
        for network, reason in BLOCKED_V4:
            if ip in network:
                return reason

    # Catch anything the explicit tables miss.
    if ip.is_private:
        return "private address space"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved address space"
    if ip.is_unspecified:
        return "unspecified address"
    return None


def _teredo_client(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    teredo = ip.teredo
    return teredo[1] if teredo else None


def hostname_block_reason(hostname: str) -> str | None:
    """Return why a hostname is refused before DNS, or None."""
    host = (hostname or "").strip().rstrip(".").lower()
    if not host:
        return "empty hostname"
    if host in BLOCKED_HOSTNAMES:
        return f"'{host}' names a local or infrastructure host"
    if host in settings.blocked_hosts:
        return f"'{host}' is on the configured block list"
    for suffix in BLOCKED_SUFFIXES:
        if host.endswith(suffix):
            return f"'{suffix}' names a private or reserved namespace"
    if "\x00" in hostname or any(ord(c) < 0x20 for c in hostname):
        return "hostname contains control characters"
    return None


def validate_url(raw_url: str) -> SafeUrl:
    """Pre-DNS validation of a URL. Raises SSRFBlocked on refusal."""
    if not raw_url or not isinstance(raw_url, str):
        raise SSRFBlocked("empty URL")
    if len(raw_url) > 4096:
        raise SSRFBlocked("URL exceeds the maximum length", destination=raw_url[:80])

    # Strip whitespace that would otherwise let "http://\n127.0.0.1" through
    # a naive prefix check.
    candidate = raw_url.strip()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise SSRFBlocked("URL contains control characters")

    parts = urlsplit(candidate)
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFBlocked(
            f"scheme '{scheme or 'none'}' is not permitted; only http and https are",
            destination=candidate[:120],
        )
    if parts.username or parts.password:
        raise SSRFBlocked("URL embeds credentials", destination=candidate[:120])

    hostname = parts.hostname
    if not hostname:
        raise SSRFBlocked("URL has no host", destination=candidate[:120])

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise SSRFBlocked("URL has an invalid port", destination=candidate[:120]) from exc
    if port not in ALLOWED_PORTS:
        raise SSRFBlocked(
            f"port {port} is not in the permitted set "
            f"({', '.join(str(p) for p in sorted(ALLOWED_PORTS))})",
            destination=candidate[:120],
        )

    reason = hostname_block_reason(hostname)
    if reason is not None:
        raise SSRFBlocked(reason, destination=hostname)

    is_literal = False
    try:
        literal = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        # Not an IP literal. Reject the obfuscated numeric forms that only
        # ever appear in bypass attempts.
        bare = hostname.strip("[]")
        if bare.replace(".", "").isdigit() and "." in bare:
            raise SSRFBlocked(
                "non-standard numeric host notation", destination=hostname
            ) from None
        if bare.isdigit() or bare.lower().startswith("0x"):
            raise SSRFBlocked(
                "non-standard numeric host notation", destination=hostname
            ) from None
    else:
        is_literal = True
        block = ip_block_reason(literal)
        if block is not None:
            raise SSRFBlocked(
                f"destination address is refused: {block}", destination=hostname
            )

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    return SafeUrl(
        url=candidate,
        scheme=scheme,
        hostname=hostname.strip("[]").lower(),
        port=port,
        path=path,
        is_ip_literal=is_literal,
    )


def _resolve_host(hostname: str, port: int) -> list:
    """Run `socket.getaddrinfo` with a hard deadline.

    A broken or hostile resolver can otherwise block the calling thread
    indefinitely (libc retries with long backoffs), which used to wedge
    whole scans at 0%: every fetch goes through this guard, so one stuck
    lookup stalled every module behind it. The resolver runs on a daemon
    thread, so a wedged lookup can never hold the worker process open.
    """
    box: dict[str, object] = {}

    def _work() -> None:
        try:
            box["answers"] = socket.getaddrinfo(
                hostname, port, proto=socket.IPPROTO_TCP
            )
        except Exception as exc:  # noqa: BLE001 - re-raised on the caller
            box["error"] = exc

    worker = threading.Thread(
        target=_work, name=f"insyte-dns-{hostname[:32]}", daemon=True
    )
    worker.start()
    worker.join(timeout=settings.DNS_RESOLVE_TIMEOUT)
    if worker.is_alive():
        raise SSRFBlocked(
            f"hostname '{hostname}' DNS resolution timed out "
            f"after {settings.DNS_RESOLVE_TIMEOUT:.0f}s",
            destination=hostname,
        )
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    answers = box.get("answers")
    if not answers:
        raise SSRFBlocked(
            f"hostname '{hostname}' has no addresses",
            destination=hostname,
        )
    return answers  # type: ignore[return-value]


def resolve_and_validate(safe_url: SafeUrl) -> PinnedDestination:
    """Resolve the hostname, validate every answer, and pin one address.

    Every address in the answer set must pass the policy - not just the one
    we pick. A name that resolves to both a public and a private address is
    refused outright, because which one a later re-resolution returns is not
    under our control.
    """
    if safe_url.is_ip_literal:
        try:
            literal = ipaddress.ip_address(safe_url.hostname)
        except ValueError as exc:  # pragma: no cover - validate_url checked
            raise SSRFBlocked("invalid address literal") from exc
        family = (
            socket.AF_INET6
            if isinstance(literal, ipaddress.IPv6Address)
            else socket.AF_INET
        )
        return PinnedDestination(
            safe_url=safe_url,
            address=str(literal),
            family=family,
            all_addresses=(str(literal),),
        )

    try:
        answers = _resolve_host(safe_url.hostname, safe_url.port)
    except socket.gaierror as exc:
        raise SSRFBlocked(
            f"hostname '{safe_url.hostname}' could not be resolved",
            destination=safe_url.hostname,
        ) from exc
    except UnicodeError as exc:
        raise SSRFBlocked(
            "hostname is not encodable", destination=safe_url.hostname
        ) from exc

    if not answers:
        raise SSRFBlocked(
            f"hostname '{safe_url.hostname}' has no addresses",
            destination=safe_url.hostname,
        )

    addresses: list[tuple[str, int]] = []
    for family, _type, _proto, _canon, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        # Drop an IPv6 scope id if the resolver attached one.
        address = address.split("%", 1)[0]
        reason = ip_block_reason(address)
        if reason is not None:
            raise SSRFBlocked(
                f"'{safe_url.hostname}' resolves to a refused address: {reason}",
                destination=safe_url.hostname,
            )
        addresses.append((address, family))

    if not addresses:
        raise SSRFBlocked(
            f"'{safe_url.hostname}' has no usable IPv4/IPv6 address",
            destination=safe_url.hostname,
        )

    # Prefer IPv4: dual-stack hosts are reachable either way, and IPv4-only
    # egress is far more common in container networks.
    addresses.sort(key=lambda item: 0 if item[1] == socket.AF_INET else 1)
    chosen_address, chosen_family = addresses[0]

    return PinnedDestination(
        safe_url=safe_url,
        address=chosen_address,
        family=chosen_family,
        all_addresses=tuple(a for a, _ in addresses),
    )


def check_destination(raw_url: str) -> PinnedDestination:
    """Full validation of a URL: pre-DNS checks, then resolve and pin."""
    return resolve_and_validate(validate_url(raw_url))


def describe_policy() -> dict[str, object]:
    """Machine-readable summary of the egress policy.

    Surfaced through the API so the UI can tell a user exactly what Insyte
    will and will not connect to, rather than asking them to trust it.
    """
    return {
        "allowed_schemes": sorted(ALLOWED_SCHEMES),
        "allowed_ports": sorted(ALLOWED_PORTS),
        "allowed_methods": ["GET", "HEAD"],
        "blocked_ipv4_ranges": [str(net) for net, _ in BLOCKED_V4],
        "blocked_ipv6_ranges": [str(net) for net, _ in BLOCKED_V6],
        "blocked_hostnames": sorted(BLOCKED_HOSTNAMES),
        "blocked_suffixes": list(BLOCKED_SUFFIXES),
        "dns_rebinding_protection": "resolve-once-then-pin-connection-address",
        "redirects_revalidated": True,
        "max_redirects": settings.HTTP_MAX_REDIRECTS,
        "max_response_bytes": settings.HTTP_MAX_RESPONSE_BYTES,
        "private_targets_allowed": settings.ALLOW_PRIVATE_TARGETS,
    }
