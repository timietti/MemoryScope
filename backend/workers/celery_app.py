# backend/workers/celery_app.py
import logging
import logging.handlers
from pathlib import Path
from celery import Celery
from celery.signals import after_setup_logger, after_setup_task_logger
from backend.config import settings
from backend.utils.db_settings import load_db_settings_sync

# Load DB-backed settings before the worker pool is created so that
# CELERY_CONCURRENCY (set via Admin UI) takes effect on startup.
load_db_settings_sync()


def _add_file_handler(logger, **kwargs):
    if not settings.LOG_FILE:
        return
    log_path = Path(settings.LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=settings.LOG_MAX_BYTES,
        backupCount=settings.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(handler)


after_setup_logger.connect(_add_file_handler)
after_setup_task_logger.connect(_add_file_handler)

celery_app = Celery(
    "memoryscope",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "backend.workers.analysis",
    ],
)

celery_app.conf.update(
    worker_concurrency=settings.CELERY_CONCURRENCY,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_pool_restarts=True,       # allow pool_restart control command from Admin UI
    worker_prefetch_multiplier=1,   # one task at a time per worker process
    result_expires=86400 * 7,        # keep results 7 days
    broker_connection_retry_on_startup=True,
    task_default_queue="default",
    # Redis priority queue support (0 = highest, 9 = lowest)
    broker_transport_options={
        "priority_steps": list(range(10)),
        "sep": ":",
        "queue_order_strategy": "priority",
    },
    task_queue_max_priority=9,
    task_default_priority=6,        # maps to case priority 2 (Medium)
    beat_schedule={
        # Purge expired dumps daily at 02:00 UTC
        "purge-expired-dumps": {
            "task": "workers.purge_expired_dumps",
            "schedule": 86400,
        },
        # Watch folder scan — interval is re-read from DB settings each run
        "scan-watch-dir": {
            "task": "workers.scan_watch_dir",
            "schedule": settings.WATCH_DIR_POLL_INTERVAL,
        },
    },
)
