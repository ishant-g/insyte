"""scan schedules

Adds the ``scan_schedules`` table for recurring scans. Each firing creates
a normal on-demand Scan row; the schedule only owns the recurrence policy,
the next firing time, and the last diff summary.

Revision ID: c1d2e3f4a5b6
Revises: a1b2c3d4e5f6
Create Date: 2026-09-27 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c1d2e3f4a5b6"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("mode", sa.String(length=24), nullable=False, server_default="passive"),
        sa.Column("module_ids", postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), 'sqlite'), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("interval_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_finalized_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_diff_summary", postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), 'sqlite'), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_scan_schedules_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_schedules")),
    )
    op.create_index(op.f("ix_scan_schedules_created_at"), "scan_schedules", ["created_at"], unique=False)
    op.create_index(op.f("ix_scan_schedules_next_run_at"), "scan_schedules", ["next_run_at"], unique=False)
    op.create_index(op.f("ix_scan_schedules_target"), "scan_schedules", ["target"], unique=False)
    op.create_index(op.f("ix_scan_schedules_user_id"), "scan_schedules", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_schedules_user_id"), table_name="scan_schedules")
    op.drop_index(op.f("ix_scan_schedules_target"), table_name="scan_schedules")
    op.drop_index(op.f("ix_scan_schedules_next_run_at"), table_name="scan_schedules")
    op.drop_index(op.f("ix_scan_schedules_created_at"), table_name="scan_schedules")
    op.drop_table("scan_schedules")
