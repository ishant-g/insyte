"""Account and credential services.

`UserService` owns registration and authentication. `CredentialService`
owns the per-account provider keys: it encrypts on write, stores only a
masked hint for display, and assembles the decrypted override mapping the
scan orchestrator installs for a run.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.credentials import (
    PROVIDER_SPEC_BY_ID,
    PROVIDER_SPECS,
    valid_fields,
)
from app.core.crypto import (
    decrypt_secret,
    encrypt_secret,
    hash_password,
    secret_hint,
    verify_password,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.models.user import ApiCredential, User

logger = get_logger(__name__)


class UserService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def register(self, email: str, password: str, display_name: str | None) -> User:
        if not settings.ALLOW_REGISTRATION:
            raise ValidationError("Self-service registration is disabled.")
        existing = self.db.scalar(select(User).where(User.email == email))
        if existing is not None:
            raise ConflictError("An account with this email already exists.")
        user = User(
            email=email,
            password_hash=hash_password(password),
            display_name=(display_name or None),
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        logger.info("user_registered", extra={"user_id": str(user.id)})
        return user

    def authenticate(self, email: str, password: str) -> User:
        user = self.db.scalar(select(User).where(User.email == email))
        # Verify against a decoy hash even when the user is missing, so the
        # response time doesn't leak whether an email exists.
        stored = user.password_hash if user else _DECOY_HASH
        ok = verify_password(password, stored)
        if not user or not ok or not user.is_active:
            raise ValidationError("Incorrect email or password.")
        return user

    def get(self, user_id: uuid.UUID) -> User:
        user = self.db.get(User, user_id)
        if user is None or not user.is_active:
            raise NotFoundError("User not found.")
        return user


#: Computed once so `authenticate` always does the same work for a missing
#: user as for a present one (timing-safe-ish; scrypt dominates either way).
_DECOY_HASH = hash_password("insyte-decoy-password")


class CredentialService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- reads -----------------------------------------------------------

    def _user_rows(self, user_id: uuid.UUID) -> dict[str, dict[str, ApiCredential]]:
        rows = self.db.scalars(
            select(ApiCredential).where(ApiCredential.user_id == user_id)
        ).all()
        out: dict[str, dict[str, ApiCredential]] = {}
        for row in rows:
            out.setdefault(row.provider_id, {})[row.field] = row
        return out

    def list_status(self, user_id: uuid.UUID) -> list[dict]:
        """Per-provider configuration status for the settings screen."""
        user_rows = self._user_rows(user_id)
        result: list[dict] = []
        for spec in PROVIDER_SPECS:
            provider_rows = user_rows.get(spec.provider_id, {})
            fields_out = []
            all_required_ok = True
            user_has_any = False
            for f in spec.fields:
                row = provider_rows.get(f.key)
                env_val = _env_field(spec.provider_id, f.key)
                user_set = row is not None
                if user_set:
                    user_has_any = True
                configured = user_set or bool(env_val)
                if not configured:
                    all_required_ok = False
                fields_out.append(
                    {
                        "key": f.key,
                        "label": f.label,
                        "secret": f.secret,
                        "configured": configured,
                        "hint": row.hint if row else (secret_hint(env_val) if env_val else ""),
                        "from_environment": (not user_set) and bool(env_val),
                    }
                )
            result.append(
                {
                    "provider_id": spec.provider_id,
                    "name": spec.name,
                    "optional": spec.optional,
                    "signup_url": spec.signup_url,
                    "free_tier": spec.free_tier,
                    "requires_api_key": not spec.optional,
                    "configured": all_required_ok,
                    "user_configured": user_has_any,
                    "fields": fields_out,
                }
            )
        return result

    # -- writes ----------------------------------------------------------

    def set_fields(self, user_id: uuid.UUID, provider_id: str, fields: dict[str, str]) -> None:
        spec = PROVIDER_SPEC_BY_ID.get(provider_id)
        if spec is None:
            raise NotFoundError(f"Unknown provider '{provider_id}'.")
        allowed = valid_fields(provider_id)
        unknown = set(fields) - allowed
        if unknown:
            raise ValidationError(f"Unknown field(s) for {provider_id}: {', '.join(sorted(unknown))}")

        existing = {
            row.field: row
            for row in self.db.scalars(
                select(ApiCredential).where(
                    ApiCredential.user_id == user_id,
                    ApiCredential.provider_id == provider_id,
                )
            ).all()
        }
        for key, raw in fields.items():
            value = (raw or "").strip()
            row = existing.get(key)
            if not value:
                # Empty value clears the stored field.
                if row is not None:
                    self.db.delete(row)
                continue
            if row is None:
                row = ApiCredential(user_id=user_id, provider_id=provider_id, field=key)
                self.db.add(row)
            row.ciphertext = encrypt_secret(value)
            row.hint = secret_hint(value)
        self.db.commit()

    def delete_provider(self, user_id: uuid.UUID, provider_id: str) -> None:
        if provider_id not in PROVIDER_SPEC_BY_ID:
            raise NotFoundError(f"Unknown provider '{provider_id}'.")
        rows = self.db.scalars(
            select(ApiCredential).where(
                ApiCredential.user_id == user_id,
                ApiCredential.provider_id == provider_id,
            )
        ).all()
        for row in rows:
            self.db.delete(row)
        self.db.commit()

    # -- override mapping for a scan ------------------------------------

    def override_mapping(self, user_id: uuid.UUID) -> dict[str, dict[str, str]]:
        """Decrypt a user's stored keys into {provider: {field: value}}.

        Only the user's own values appear here - environment defaults are
        applied by the providers themselves as the fallback, so a user's
        key layers on top of, and overrides, the deployment default.
        """
        mapping: dict[str, dict[str, str]] = {}
        rows = self.db.scalars(
            select(ApiCredential).where(ApiCredential.user_id == user_id)
        ).all()
        for row in rows:
            value = decrypt_secret(row.ciphertext)
            if value:
                mapping.setdefault(row.provider_id, {})[row.field] = value
        return mapping


def _env_field(provider_id: str, field: str) -> str:
    """The deployment's environment value for a provider field, if any."""
    if provider_id == "censys":
        return settings.CENSYS_API_ID if field == "api_id" else settings.CENSYS_API_SECRET
    if provider_id == "google_cse":
        return settings.GOOGLE_CSE_API_KEY if field == "api_key" else settings.GOOGLE_CSE_CX
    return settings.provider_key(provider_id)
