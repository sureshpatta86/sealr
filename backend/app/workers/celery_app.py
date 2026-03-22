from celery import Celery

from app.config import settings

_broker = "memory://" if settings.DEV_MODE else settings.REDIS_URL
_backend = "cache+memory://" if settings.DEV_MODE else settings.REDIS_URL

celery_app = Celery("sealr", broker=_broker, backend=_backend)

_conf: dict = {
    "task_serializer": "json",
    "accept_content": ["json"],
    "result_serializer": "json",
    "timezone": "UTC",
    "enable_utc": True,
    "task_track_started": True,
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
    "task_default_queue": "sealr-tasks",
}

if settings.DEV_MODE:
    _conf["task_always_eager"] = True  # run tasks synchronously in-process
else:
    _conf["beat_schedule"] = {
        "check-scheduled-scans": {
            "task": "check_scheduled_scans",
            "schedule": 60.0,
        },
    }

celery_app.conf.update(**_conf)

# Auto-discover tasks
celery_app.autodiscover_tasks(["app.workers"])
