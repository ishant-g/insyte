"""Seed the sources catalogue.

Revision ID: 8f1a2b3c4d5e
Revises: 7846f7fd00ed
Create Date: 2026-08-28
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "8f1a2b3c4d5e"
down_revision: Union[str, None] = "7846f7fd00ed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

sources_table = sa.table(
    "sources",
    sa.column("id", sa.String),
    sa.column("name", sa.String),
    sa.column("kind", sa.String),
    sa.column("description", sa.Text),
    sa.column("homepage", sa.String),
    sa.column("requires_api_key", sa.Boolean),
    sa.column("reliability", sa.Integer),
)


def upgrade() -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from app.providers import source_catalogue
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    # Idempotent: safe to re-run if a previous attempt died partway through.
    op.get_bind().execute(
        pg_insert(sources_table).values(source_catalogue()).on_conflict_do_nothing(
            index_elements=["id"]
        )
    )


def downgrade() -> None:
    op.execute(sources_table.delete())
