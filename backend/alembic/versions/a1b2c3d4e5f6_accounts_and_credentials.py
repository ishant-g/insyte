"""accounts and per-account credentials

Adds the ``users`` and ``api_credentials`` tables and the ``user_id``
owner column on ``scans`` and ``projects``. Existing rows get a NULL owner
(pre-accounts data), which the application treats as ownerless.

Revision ID: a1b2c3d4e5f6
Revises: 9a2c7e1f6b0d
Create Date: 2026-09-08 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "9a2c7e1f6b0d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=False)

    op.create_table(
        "api_credentials",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.String(length=64), nullable=False),
        sa.Column("field", sa.String(length=64), nullable=False),
        sa.Column("ciphertext", sa.String(length=1024), nullable=False),
        sa.Column("hint", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_api_credentials_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_credentials")),
        sa.UniqueConstraint(
            "user_id", "provider_id", "field",
            name="uq_api_credentials_user_id_provider_id_field",
        ),
    )
    op.create_index(op.f("ix_api_credentials_created_at"), "api_credentials", ["created_at"], unique=False)
    op.create_index(op.f("ix_api_credentials_provider_id"), "api_credentials", ["provider_id"], unique=False)
    op.create_index(op.f("ix_api_credentials_user_id"), "api_credentials", ["user_id"], unique=False)

    op.add_column("scans", sa.Column("user_id", sa.Uuid(), nullable=True))
    op.create_index(op.f("ix_scans_user_id"), "scans", ["user_id"], unique=False)
    op.create_foreign_key(
        op.f("fk_scans_user_id_users"), "scans", "users", ["user_id"], ["id"], ondelete="SET NULL"
    )

    op.add_column("projects", sa.Column("user_id", sa.Uuid(), nullable=True))
    op.create_index(op.f("ix_projects_user_id"), "projects", ["user_id"], unique=False)
    op.create_foreign_key(
        op.f("fk_projects_user_id_users"), "projects", "users", ["user_id"], ["id"], ondelete="SET NULL"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_projects_user_id_users"), "projects", type_="foreignkey")
    op.drop_index(op.f("ix_projects_user_id"), table_name="projects")
    op.drop_column("projects", "user_id")

    op.drop_constraint(op.f("fk_scans_user_id_users"), "scans", type_="foreignkey")
    op.drop_index(op.f("ix_scans_user_id"), table_name="scans")
    op.drop_column("scans", "user_id")

    op.drop_index(op.f("ix_api_credentials_user_id"), table_name="api_credentials")
    op.drop_index(op.f("ix_api_credentials_provider_id"), table_name="api_credentials")
    op.drop_index(op.f("ix_api_credentials_created_at"), table_name="api_credentials")
    op.drop_table("api_credentials")

    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_index(op.f("ix_users_created_at"), table_name="users")
    op.drop_table("users")
