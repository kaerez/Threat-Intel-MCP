"""Maintenance tasks for CVE MCP server."""

import asyncio

import structlog
from sqlalchemy import select, text, update

from cve_mcp.models import CVE, EPSSScore, ExploitReference
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.tasks.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task
def refresh_materialized_views():
    """Refresh materialized views after sync completion."""

    async def _refresh():
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_high_priority_cves")
            )
            await session.commit()
        logger.info("Materialized views refreshed")

    asyncio.run(_refresh())


@celery_app.task
def update_computed_flags():
    """Update computed boolean flags on CVE table."""

    async def _update_flags():
        async with AsyncSessionLocal() as session:
            # Update has_exploit flag
            exploit_cve_ids = await session.execute(
                select(ExploitReference.cve_id.distinct())
            )
            exploit_ids = [row[0] for row in exploit_cve_ids.all()]

            # Reset all flags first
            await session.execute(
                update(CVE).values(
                    has_exploit=False,
                    has_epss_score=False,
                )
            )

            # Set has_exploit
            if exploit_ids:
                for i in range(0, len(exploit_ids), 10000):
                    batch_ids = exploit_ids[i : i + 10000]
                    await session.execute(
                        update(CVE).where(CVE.cve_id.in_(batch_ids)).values(has_exploit=True)
                    )

            # Update has_epss_score flag
            epss_cve_ids = await session.execute(select(EPSSScore.cve_id))
            epss_ids = [row[0] for row in epss_cve_ids.all()]

            if epss_ids:
                for i in range(0, len(epss_ids), 10000):
                    batch_ids = epss_ids[i : i + 10000]
                    await session.execute(
                        update(CVE).where(CVE.cve_id.in_(batch_ids)).values(has_epss_score=True)
                    )

            await session.commit()

        logger.info("Computed flags updated")

    asyncio.run(_update_flags())


@celery_app.task
def vacuum_analyze_database():
    """Run VACUUM ANALYZE on database tables."""

    async def _vacuum():
        async with AsyncSessionLocal() as session:
            # Note: VACUUM cannot run inside a transaction block
            # This is executed via raw connection
            await session.execute(text("ANALYZE cves"))
            await session.execute(text("ANALYZE cve_references"))
            await session.execute(text("ANALYZE cve_cpe_mappings"))
            await session.execute(text("ANALYZE cisa_kev"))
            await session.execute(text("ANALYZE epss_scores"))
            await session.execute(text("ANALYZE exploit_references"))
            await session.commit()

        logger.info("Database analyzed")

    asyncio.run(_vacuum())


@celery_app.task
def cleanup_old_audit_logs():
    """Clean up audit logs older than retention period."""

    async def _cleanup():
        from cve_mcp.config import get_settings

        settings = get_settings()
        retention_days = settings.audit_log_retention_days

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    f"DELETE FROM query_audit_log WHERE timestamp < NOW() - INTERVAL '{retention_days} days'"
                )
            )
            deleted_count = result.rowcount
            await session.commit()

        logger.info("Old audit logs cleaned up", deleted_count=deleted_count)

    asyncio.run(_cleanup())
