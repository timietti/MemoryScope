# backend/workers/celery_app.py
from celery import Celery
from backend.config import settings

celery_app = Celery(
    "memoryscope",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "backend.workers.analysis",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,   # one task at a time per worker process
    result_expires=86400 * 7,        # keep results 7 days
    broker_connection_retry_on_startup=True,
    task_default_queue="default",
    beat_schedule={
        # Purge expired dumps daily at 02:00 UTC
        "purge-expired-dumps": {
            "task": "workers.purge_expired_dumps",
            "schedule": 86400,
        },
    },
)
