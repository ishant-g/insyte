"""Seed the 10 providers added after the original sources seed.

AbuseIPDB, GreyNoise, Chaos, OpenCorporates, SEC EDGAR, Wikidata,
GrayhatWarfare, HIBP, Hunter.io, Google CSE — the original seed migration
(8f1a2b3c4d5e) only covered the providers that existed when it was written.

Revision ID: 9a2c7e1f6b0d
Revises: fd4b3f1b3103
Create Date: 2026-09-02
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "9a2c7e1f6b0d"
down_revision: Union[str, None] = "fd4b3f1b3103"
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

#: The ids already inserted by 8f1a2b3c4d5e — anything in the live
#: `source_catalogue()` output NOT in this set is new since that migration
#: was written, and is what this migration inserts.
_ALREADY_SEEDED = frozenset(
    {
        "crtsh", "certspotter", "hackertarget", "rapiddns", "otx", "wayback",
        "commoncrawl", "urlscan", "rdap", "ripestat", "virustotal", "shodan",
        "censys", "securitytrails", "github", "nvd", "epss", "kev",
        "dns", "doh", "tls", "web_surface", "derived",
    }
)


def upgrade() -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from app.providers import source_catalogue
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    new_rows = [row for row in source_catalogue() if row["id"] not in _ALREADY_SEEDED]
    if new_rows:
        # Idempotent: 8f1a2b3c4d5e seeds the full current catalogue, so ids
        # added after that migration was written may already exist.
        op.get_bind().execute(
            pg_insert(sources_table).values(new_rows).on_conflict_do_nothing(
                index_elements=["id"]
            )
        )


def downgrade() -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from app.providers import source_catalogue

    new_ids = [row["id"] for row in source_catalogue() if row["id"] not in _ALREADY_SEEDED]
    if new_ids:
        op.execute(sources_table.delete().where(sources_table.c.id.in_(new_ids)))
