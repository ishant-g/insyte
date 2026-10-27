"""SSRF-guarded TLS certificate retrieval.

`SafeHttpClient` covers HTTP(S) content; this covers the certificate itself,
which httpx does not expose. The same SSRF discipline applies: the
destination is resolved and validated first, and the socket connects to
the pinned address while presenting the real hostname for SNI.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core.net.ssrf import resolve_and_validate, validate_url


class TlsError(Exception):
    """The handshake failed for a reason other than SSRF policy."""


@dataclass(slots=True)
class TlsCertificate:
    hostname: str
    port: int
    remote_address: str
    tls_version: str
    der: bytes
    chain_der: list[bytes]

    @property
    def certificate(self) -> x509.Certificate:
        return x509.load_der_x509_certificate(self.der)


def fetch_certificate(
    hostname: str, *, port: int = 443, timeout: float = 10.0
) -> TlsCertificate:
    """Perform a validated TLS handshake and return the leaf certificate.

    Raises `SSRFBlocked` if the destination is refused, `TlsError` for any
    other handshake failure (timeout, refused connection, no certificate,
    hostname mismatch).
    """
    destination = resolve_and_validate(validate_url(f"https://{hostname}:{port}/"))
    ssl_context = ssl.create_default_context()

    raw = None
    try:
        raw = socket.create_connection(
            (destination.address, port), timeout=timeout
        )
        raw.settimeout(timeout)
        with ssl_context.wrap_socket(raw, server_hostname=hostname) as tls_socket:
            der = tls_socket.getpeercert(binary_form=True)
            version = tls_socket.version() or "unknown"
            chain: list[bytes] = []
            try:
                der_chain = tls_socket.get_verified_chain()  # type: ignore[attr-defined]
                chain = [c.public_bytes(ssl.Encoding.DER) for c in der_chain[1:]]
            except (AttributeError, ssl.SSLError):
                chain = []
    except TimeoutError as exc:
        raise TlsError(f"connection to {hostname}:{port} timed out") from exc
    except ConnectionRefusedError as exc:
        raise TlsError(f"{hostname}:{port} refused the connection") from exc
    except ssl.SSLCertVerificationError as exc:
        raise TlsError(f"certificate verification failed: {exc}") from exc
    except ssl.SSLError as exc:
        raise TlsError(f"TLS handshake failed: {exc}") from exc
    except OSError as exc:
        raise TlsError(f"connection failed: {exc}") from exc
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass

    if der is None:
        raise TlsError(f"{hostname}:{port} presented no certificate")

    return TlsCertificate(
        hostname=hostname,
        port=port,
        remote_address=destination.address,
        tls_version=version,
        der=der,
        chain_der=chain,
    )


def describe_certificate(cert: x509.Certificate) -> dict[str, object]:
    """Reduce a parsed certificate to Insyte's certificate-record shape."""

    def _cn(name: x509.Name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else None

    def _org(name: x509.Name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return str(attrs[0].value) if attrs else None

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = list(ext.value.get_values_for_type(x509.DNSName))  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        pass

    not_before = _aware(cert.not_valid_before_utc)
    not_after = _aware(cert.not_valid_after_utc)
    now = datetime.now(UTC)

    public_key = cert.public_key()
    key_algorithm = public_key.__class__.__name__.lstrip("_").removesuffix("PublicKey")
    key_size = getattr(public_key, "key_size", None)

    return {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "serial_number": format(cert.serial_number, "x"),
        "subject_cn": _cn(cert.subject),
        "subject": {"cn": _cn(cert.subject), "organization": _org(cert.subject)},
        "issuer_cn": _cn(cert.issuer),
        "issuer_org": _org(cert.issuer),
        "issuer": {"cn": _cn(cert.issuer), "organization": _org(cert.issuer)},
        "sans": sorted(set(sans)),
        "has_wildcard": any(name.startswith("*.") for name in sans),
        "san_count": len(set(sans)),
        "not_before": not_before,
        "not_after": not_after,
        "is_expired": bool(not_after and not_after < now),
        "days_until_expiry": (not_after - now).days if not_after else None,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key_algorithm": key_algorithm or None,
        "public_key_size": key_size,
    }


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
