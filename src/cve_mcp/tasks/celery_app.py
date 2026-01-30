"""Celery application configuration."""

from celery import Celery
from celery.schedules import crontab

from cve_mcp.config import get_settings

settings = get_settings()

# Create Celery app
celery_app = Celery(
    "cve_mcp",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "cve_mcp.tasks.sync_nvd",
        "cve_mcp.tasks.sync_cisa_kev",
        "cve_mcp.tasks.sync_epss",
        "cve_mcp.tasks.sync_exploitdb",
        "cve_mcp.tasks.maintenance",
    ],
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=28800,  # 8 hours max for full sync
    task_soft_time_limit=27000,  # 7.5 hours soft limit
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
)

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    # Daily syncs (02:00-04:00 UTC window)
    "sync-nvd-recent": {
        "task": "cve_mcp.tasks.sync_nvd.sync_nvd_recent",
        "schedule": crontab(hour=2, minute=0),
        "options": {"expires": 7200},  # 2-hour timeout
    },
    "sync-cisa-kev": {
        "task": "cve_mcp.tasks.sync_cisa_kev.sync_cisa_kev",
        "schedule": crontab(hour=2, minute=30),
        "options": {"expires": 900},  # 15-min timeout
    },
    "sync-epss-scores": {
        "task": "cve_mcp.tasks.sync_epss.sync_epss_scores",
        "schedule": crontab(hour=3, minute=0),
        "options": {"expires": 3600},  # 1-hour timeout
    },
    # Weekly syncs
    "sync-exploitdb": {
        "task": "cve_mcp.tasks.sync_exploitdb.sync_exploitdb",
        "schedule": crontab(hour=3, minute=30, day_of_week=1),  # Monday 03:30 UTC
        "options": {"expires": 1800},
    },
    # Post-sync maintenance tasks
    "refresh-materialized-views": {
        "task": "cve_mcp.tasks.maintenance.refresh_materialized_views",
        "schedule": crontab(hour=3, minute=45),
    },
    "update-computed-flags": {
        "task": "cve_mcp.tasks.maintenance.update_computed_flags",
        "schedule": crontab(hour=3, minute=50),
    },
    # Monthly full rebuild
    "sync-nvd-full": {
        "task": "cve_mcp.tasks.sync_nvd.sync_nvd_full",
        "schedule": crontab(hour=3, minute=0, day_of_month=1),  # 1st of month
        "options": {"expires": 28800},  # 8-hour timeout
    },
}
