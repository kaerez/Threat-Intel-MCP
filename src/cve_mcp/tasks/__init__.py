"""Celery tasks for CVE MCP server."""

from cve_mcp.tasks.celery_app import celery_app
from cve_mcp.tasks.maintenance import refresh_materialized_views, update_computed_flags
from cve_mcp.tasks.sync_atlas import sync_atlas_data
from cve_mcp.tasks.sync_attack import sync_attack_data
from cve_mcp.tasks.sync_cisa_kev import sync_cisa_kev
from cve_mcp.tasks.sync_epss import sync_epss_scores
from cve_mcp.tasks.sync_exploitdb import sync_exploitdb
from cve_mcp.tasks.sync_nvd import sync_nvd_full, sync_nvd_recent

__all__ = [
    "celery_app",
    "sync_nvd_recent",
    "sync_nvd_full",
    "sync_cisa_kev",
    "sync_epss_scores",
    "sync_exploitdb",
    "sync_attack_data",
    "sync_atlas_data",
    "refresh_materialized_views",
    "update_computed_flags",
]
