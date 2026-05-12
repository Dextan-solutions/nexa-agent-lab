from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab


def _redis_url() -> str:
    return os.getenv("REDIS_URL", "redis://redis:6379/0")


celery_app = Celery(
    "agenthive",
    broker=_redis_url(),
    backend=_redis_url(),
    include=["tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)

# FIX 1: suppress broker_connection_retry warning on Celery 5+
celery_app.conf.broker_connection_retry_on_startup = True

# FIX 2: schedule Max's fraud monitoring task (requires `beat` service)
celery_app.conf.beat_schedule = {
    "max-fraud-monitor": {
        "task": "agenthive.max_fraud_monitor",
        "schedule": 60.0,  # every 60 seconds
    },
    "vera-nightly-kyc": {
        "task": "agenthive.vera_nightly_kyc_batch",
        "schedule": crontab(hour=2, minute=0),
    },
    "finn-nightly-statements": {
        "task": "agenthive.finn_nightly_batch",
        "schedule": crontab(hour=3, minute=0),
    },
}
celery_app.conf.timezone = "UTC"

# Dedicated routing to avoid queue starvation between long-running batches.
celery_app.conf.task_routes = {
    "agenthive.vera_process_kyc_document": {"queue": "vera"},
    "agenthive.vera_nightly_kyc_batch": {"queue": "vera"},
    "agenthive.finn_generate_summary": {"queue": "finn"},
    "agenthive.finn_nightly_batch": {"queue": "finn"},
    "agenthive.max_fraud_monitor": {"queue": "max"},
    "agenthive.aria_process_support_ticket": {"queue": "aria"},
    "agenthive.leo_process_loan": {"queue": "leo"},
    "agenthive.ops_handle_request": {"queue": "ops"},
}

