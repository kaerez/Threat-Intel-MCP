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
        "cve_mcp.tasks.sync_attack",
        "cve_mcp.tasks.sync_atlas",
        "cve_mcp.tasks.sync_capec",
        "cve_mcp.tasks.sync_cwe",
        "cve_mcp.tasks.sync_d3fend",
        "cve_mcp.tasks.sync_cloud_security",
        "cve_mcp.tasks.sync_owasp_llm",
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
    # MITRE framework syncs (weekly on Sunday 04:00-06:00 UTC)
    "sync-attack": {
        "task": "cve_mcp.tasks.sync_attack.sync_attack",
        "schedule": crontab(hour=4, minute=0, day_of_week=0),  # Sunday 04:00 UTC
        "options": {"expires": 3600},
    },
    "sync-atlas": {
        "task": "cve_mcp.tasks.sync_atlas.sync_atlas",
        "schedule": crontab(hour=4, minute=30, day_of_week=0),  # Sunday 04:30 UTC
        "options": {"expires": 1800},
    },
    "sync-capec": {
        "task": "cve_mcp.tasks.sync_capec.sync_capec",
        "schedule": crontab(hour=5, minute=0, day_of_week=0),  # Sunday 05:00 UTC
        "options": {"expires": 1800},
    },
    "sync-cwe": {
        "task": "cve_mcp.tasks.sync_cwe.sync_cwe",
        "schedule": crontab(hour=5, minute=30, day_of_week=0),  # Sunday 05:30 UTC
        "options": {"expires": 3600},
    },
    "sync-d3fend": {
        "task": "cve_mcp.tasks.sync_d3fend.sync_d3fend",
        "schedule": crontab(hour=6, minute=0, day_of_week=0),  # Sunday 06:00 UTC
        "options": {"expires": 1800},
    },
    # OWASP LLM Top 10 sync (weekly on Sunday 06:15 UTC)
    "sync-owasp-llm": {
        "task": "cve_mcp.tasks.sync_owasp_llm.sync_owasp_llm",
        "schedule": crontab(hour=6, minute=15, day_of_week=0),  # Sunday 06:15 UTC
        "options": {"expires": 600},  # 10-min timeout (static data, fast sync)
    },
    # Cloud security syncs (weekly on Sunday 06:30-07:15 UTC)
    "sync-aws-s3-security": {
        "task": "cve_mcp.tasks.sync_cloud_security.sync_aws_s3_task",
        "schedule": crontab(hour=6, minute=30, day_of_week=0),  # Sunday 06:30 UTC
        "options": {"expires": 1800},
    },
    "sync-azure-blob-security": {
        "task": "cve_mcp.tasks.sync_cloud_security.sync_azure_blob_task",
        "schedule": crontab(hour=6, minute=45, day_of_week=0),  # Sunday 06:45 UTC
        "options": {"expires": 1800},
    },
    "sync-gcp-storage-security": {
        "task": "cve_mcp.tasks.sync_cloud_security.sync_gcp_storage_task",
        "schedule": crontab(hour=7, minute=0, day_of_week=0),  # Sunday 07:00 UTC
        "options": {"expires": 1800},
    },
    "sync-cloud-service-equivalences": {
        "task": "cve_mcp.tasks.sync_cloud_security.sync_cloud_service_equivalences_task",
        "schedule": crontab(hour=7, minute=15, day_of_week=0),  # Sunday 07:15 UTC
        "options": {"expires": 900},
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
