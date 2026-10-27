"""Allow NULL certificate fingerprints for CT-log-derived records.

Revision ID: e5f6a7b8c9d0
Revises: fd4b3f1b3103
Create Date: 2026-09-27
"""

from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "certificates", "fingerprint_sha256", existing_type=sa.String(64), nullable=True
    )


def downgrade() -> None:
    op.alter_column(
        "certificates", "fingerprint_sha256", existing_type=sa.String(64), nullable=False
    )
