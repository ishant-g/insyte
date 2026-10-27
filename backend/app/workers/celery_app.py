"""Celery application factory.

Started with: celery -A app.workers.celery_app.celery worker -l info

Time limits are set per the brief's requirement that a scan cannot hang a
worker forever: `task_time_limit` sends SIGKILL if a task overruns,
`task_soft_time_limit` raises a catchable exception first so the
orchestrator gets a chance to mark the scan FAILED with a real reason
before the hard kill.
"""

from __future__ import annotations

from celery import Celery

from app.core.config import settings

celery = Celery(
    "insyte",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_TIME_LIMIT,
    task_soft_time_limit=settings.SCAN_SOFT_TIME_LIMIT,
    # A scan holds provider rate-limit state and a large in-memory result
    # set; recycling the worker process after each task avoids slow memory
    # growth across a long-running worker's lifetime.
    worker_max_tasks_per_child=50,
    # One scan per worker process at a time. Concurrency across scans
    # comes from running multiple worker processes (see docker-compose.yml
    # `--concurrency`), not from interleaving scans within one process.
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Celery Beat: fire due scan schedules every 5 minutes. Beat is
    # stateless (all schedule state lives in the database), so a beat
    # restart never double-fires (next_run_at advances only on dispatch).
    beat_schedule={
        "dispatch-due-schedules": {
            "task": "insyte.dispatch_due_schedules",
            "schedule": 300.0,
        },
    },
    # Redis visibility timeout must exceed the longest task runtime, or a
    # long scan gets redelivered and runs twice under multi-worker scaling.
    # Scans are hard-killed at SCAN_TIME_LIMIT, so one hour is safe; set
    # explicitly so a broker default change cannot silently cause dupes.
    broker_transport_options={"visibility_timeout": 3600},
)
