"""Account and stored-credential models.

Insyte gains accounts so that provider API keys can be stored *per user*
rather than only per deployment. Two rules shape the schema:

* A stored credential is **encrypted at rest** - the ``ciphertext`` column
  never holds a plaintext key. Only a non-reversible ``hint`` (``••••1234``)
  is stored alongside for display, so the settings UI can show *that* a key
  is set without ever showing the key.
* Credentials are scoped to exactly one user and deleted with the user.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKey, UUIDType

if TYPE_CHECKING:
    pass


class User(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    credentials: Mapped[list[ApiCredential]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ApiCredential(Base, UUIDPrimaryKey, TimestampMixin):
    """One provider credential belonging to one user.

    A provider may need more than one field (Censys id+secret, Google CSE
    key+cx); each field is a separate row so an individual field can be
    updated or cleared, and each row carries its own ciphertext.
    """

    __tablename__ = "api_credentials"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "provider_id",
            "field",
            name="uq_api_credentials_user_id_provider_id_field",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    field: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Fernet ciphertext of the credential value. Never plaintext.
    ciphertext: Mapped[str] = mapped_column(String(1024), nullable=False)
    #: Non-reversible display hint, e.g. "••••ab12". Never the real value.
    hint: Mapped[str] = mapped_column(String(32), nullable=False, default="")

    user: Mapped[User] = relationship(back_populates="credentials")
