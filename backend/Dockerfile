# syntax=docker/dockerfile:1
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# libpq is needed for psycopg's C extension; curl is used by the
# API healthcheck in docker-compose.yml.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM base AS runtime
COPY --from=builder /install /usr/local

# Runs as an unprivileged user — the collector fetches attacker-influenced
# content, so the process it runs in should not be root.
RUN useradd --create-home --uid 1000 insyte \
    && mkdir -p /var/lib/insyte/reports \
    && chown -R insyte:insyte /var/lib/insyte

COPY --chown=insyte:insyte . .

RUN chmod +x entrypoint.sh

USER insyte
EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
