#!/usr/bin/env bash
# Insyte API/worker entrypoint: wait for Postgres, migrate, then hand off.
#
# Migrations run here (not as a separate compose step) so `docker compose
# up` alone is sufficient to reach a working database — the brief asks for
# first-run setup to be simple and deterministic, and a second manual
# `alembic upgrade head` step is exactly the kind of thing a first-time
# user forgets.
set -euo pipefail

wait_for_postgres() {
  echo "insyte: waiting for postgres..."
  python - <<'PYEOF'
import sys
import time

import psycopg

from app.core.config import settings

deadline = time.monotonic() + 60
last_error = None
while time.monotonic() < deadline:
    try:
        conn = psycopg.connect(settings.DATABASE_URL.replace("+psycopg", ""), connect_timeout=3)
        conn.close()
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        last_error = exc
        time.sleep(1)
print(f"insyte: postgres did not become ready in time: {last_error}", file=sys.stderr)
sys.exit(1)
PYEOF
}

wait_for_postgres
echo "insyte: running migrations..."
alembic upgrade head
echo "insyte: migrations complete."

exec "$@"
