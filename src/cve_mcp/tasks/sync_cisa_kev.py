"""CISA KEV sync task."""

import asyncio
from datetime import datetime

import httpx
import structlog
from sqlalchemy import select, update

from cve_mcp.config import get_settings
from cve_mcp.models import CVE, CISAKEV, SyncMetadata
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.tasks.celery_app import celery_app

logger = structlog.get_logger()


async def _update_sync_metadata(source: str, **kwargs) -> None:
    """Update sync metadata."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(SyncMetadata).where(SyncMetadata.source == source))
        metadata = result.scalar_one_or_none()

        if metadata:
            for key, value in kwargs.items():
                setattr(metadata, key, value)
        else:
            metadata = SyncMetadata(source=source, **kwargs)
            session.add(metadata)

        await session.commit()


async def _sync_cisa_kev_async() -> dict:
    """Async implementation of CISA KEV sync."""
    settings = get_settings()

    await _update_sync_metadata(
        "cisa_kev",
        last_sync_status="running",
        last_sync_time=datetime.now(),
    )

    sync_start = datetime.now()

    # Download KEV catalog
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(settings.cisa_kev_url)
        response.raise_for_status()
        data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])
    logger.info("Downloaded CISA KEV catalog", count=len(vulnerabilities))

    # Process KEV entries
    async with AsyncSessionLocal() as session:
        # Reset all has_kev_entry flags
        await session.execute(update(CVE).values(has_kev_entry=False))

        # Get existing CVE IDs for validation
        cve_result = await session.execute(select(CVE.cve_id))
        existing_cve_ids = {row[0] for row in cve_result.all()}

        # Clear existing KEV data
        existing_kev = await session.execute(select(CISAKEV))
        for kev in existing_kev.scalars().all():
            await session.delete(kev)

        kev_count = 0
        skipped = 0

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")

            # Only insert if CVE exists in our database
            if cve_id not in existing_cve_ids:
                skipped += 1
                continue

            # Parse date
            date_added = None
            if vuln.get("dateAdded"):
                try:
                    date_added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").date()
                except ValueError:
                    pass

            due_date = None
            if vuln.get("dueDate"):
                try:
                    due_date = datetime.strptime(vuln["dueDate"], "%Y-%m-%d").date()
                except ValueError:
                    pass

            kev_record = CISAKEV(
                cve_id=cve_id,
                vulnerability_name=vuln.get("vulnerabilityName"),
                short_description=vuln.get("shortDescription"),
                required_action=vuln.get("requiredAction", "Apply vendor mitigations"),
                due_date=due_date,
                known_ransomware_use=vuln.get("knownRansomwareCampaignUse") == "Known",
                date_added=date_added,
                notes=vuln.get("notes"),
            )
            session.add(kev_record)
            kev_count += 1

        await session.commit()

        # Update has_kev_entry flags for KEV CVEs
        kev_cve_ids = await session.execute(select(CISAKEV.cve_id))
        kev_ids = [row[0] for row in kev_cve_ids.all()]

        if kev_ids:
            await session.execute(
                update(CVE).where(CVE.cve_id.in_(kev_ids)).values(has_kev_entry=True)
            )
            await session.commit()

    sync_duration = int((datetime.now() - sync_start).total_seconds())

    await _update_sync_metadata(
        "cisa_kev",
        last_sync_time=datetime.now(),
        last_sync_status="success",
        records_synced=kev_count,
        sync_duration_seconds=sync_duration,
        error_message=None,
    )

    logger.info(
        "CISA KEV sync complete",
        kev_count=kev_count,
        skipped=skipped,
        duration_seconds=sync_duration,
    )

    return {"synced": kev_count, "skipped": skipped}


@celery_app.task(bind=True, max_retries=3)
def sync_cisa_kev(self):
    """
    Daily CISA KEV sync: Full refresh of Known Exploited Vulnerabilities catalog.
    """
    try:
        return asyncio.run(_sync_cisa_kev_async())
    except Exception as exc:
        logger.exception("CISA KEV sync failed", error=str(exc))
        asyncio.run(
            _update_sync_metadata(
                "cisa_kev",
                last_sync_status="failed",
                error_message=str(exc),
            )
        )
        raise self.retry(exc=exc, countdown=60 * (2**self.request.retries))
