"""Cryptographic primitives for accounts and stored credentials.

Deliberately dependency-free where the standard library is sufficient:

* **Password hashing** uses `hashlib.scrypt` (memory-hard, in the stdlib),
  stored in a self-describing ``scrypt$n$r$p$salt$hash`` string so the work
  factor can be raised later without a migration.
* **Session tokens** are compact HS256 JWTs signed with the deployment
  ``SECRET_KEY`` via ``hmac`` - stateless, so horizontal scaling of the API
  needs no shared session store.
* **Stored API keys are encrypted at rest** with Fernet (AES-128-CBC +
  HMAC, from the already-present ``cryptography`` package). The Fernet key
  is derived from ``SECRET_KEY`` so rotating the secret invalidates stored
  ciphertext by design - a stored provider key is a convenience, never the
  only copy.

Nothing here logs or returns a secret value.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

# ---------------------------------------------------------------------------
# Password hashing (scrypt)
# ---------------------------------------------------------------------------

_SCRYPT_N = 2**14  # 16384 - ~16 MiB, stays under OpenSSL's 32 MiB scrypt cap
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
#: 128 * r * (n + p + 1) bytes plus headroom; passed explicitly so the
#: work factor isn't silently capped by OpenSSL's default maxmem.
_SCRYPT_MAXMEM = 128 * _SCRYPT_R * (_SCRYPT_N + _SCRYPT_P + 2)


def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash string."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )
    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(dk).decode()
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt_b64}${hash_b64}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification against a stored scrypt hash."""
    try:
        scheme, n, r, p, b64salt, b64hash = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(b64salt)
        expected = base64.b64decode(b64hash)
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# ---------------------------------------------------------------------------
# JWT (HS256), stdlib only
# ---------------------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


class TokenError(Exception):
    """Raised when a token is malformed, tampered, or expired."""


def create_access_token(subject: str, *, extra: dict[str, Any] | None = None) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
    if extra:
        payload.update(extra)
    signing_input = (
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = hmac.new(
        settings.SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return signing_input + "." + _b64url_encode(signature)


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise TokenError("malformed token") from exc

    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(
        settings.SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_sig, _b64url_decode(signature_b64)):
        raise TokenError("bad signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise TokenError("bad payload") from exc

    if int(payload.get("exp", 0)) < int(time.time()):
        raise TokenError("token expired")
    return payload


# ---------------------------------------------------------------------------
# Field encryption for stored provider credentials
# ---------------------------------------------------------------------------


def _fernet() -> Fernet:
    # A stable 32-byte key derived from SECRET_KEY. Rotating SECRET_KEY
    # intentionally invalidates previously stored ciphertext.
    digest = hashlib.sha256(("insyte-cred::" + settings.SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        # Ciphertext written under a previous SECRET_KEY, or corrupted.
        return None


def secret_hint(value: str) -> str:
    """A safe, non-reversible display hint: ``••••1234`` for a real value."""
    value = value.strip()
    if not value:
        return ""
    tail = value[-4:] if len(value) >= 8 else ""
    return f"••••{tail}" if tail else "••••"
