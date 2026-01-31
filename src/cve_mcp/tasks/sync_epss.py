"""EPSS scores sync task."""

import asyncio
import csv
import gzip
from datetime import datetime
from io import BytesIO

import httpx
import structlog
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert

from cve_mcp.config import get_settings
from cve_mcp.models import CVE, EPSSScore, SyncMetadata
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


async def _sync_epss_scores_async() -> dict:
    """Async implementation of EPSS scores sync."""
    settings = get_settings()

    await _update_sync_metadata(
        "epss_scores",
        last_sync_status="running",
        last_sync_time=datetime.now(),
    )

    sync_start = datetime.now()

    # Download EPSS CSV (gzipped)
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        response = await client.get(settings.epss_url)
        response.raise_for_status()

    # Decompress gzip
    with gzip.open(BytesIO(response.content), "rt") as f:
        csv_content = f.read()

    # Parse CSV
    # EPSS CSV format: cve,epss,percentile (with optional date column)
    lines = csv_content.strip().split("\n")

    # Skip comment lines (starting with #)
    data_lines = [line for line in lines if not line.startswith("#")]

    if not data_lines:
        logger.warning("EPSS CSV is empty")
        return {"synced": 0}

    # Parse header
    reader = csv.DictReader(data_lines)

    # Get existing CVE IDs for validation
    async with AsyncSessionLocal() as session:
        cve_result = await session.execute(select(CVE.cve_id))
        existing_cve_ids = {row[0] for row in cve_result.all()}

    # Process in batches
    batch_size = 10000
    batch = []
    total_records = 0
    skipped = 0

    today = datetime.now().date()

    async with AsyncSessionLocal() as session:
        for row in reader:
            cve_id = row.get("cve", "").upper()

            if not cve_id or cve_id not in existing_cve_ids:
                skipped += 1
                continue

            try:
                epss_score = float(row.get("epss", 0))
                epss_percentile = float(row.get("percentile", 0))
            except (ValueError, TypeError):
                skipped += 1
                continue

            # Parse date if available
            date_scored = today
            if "date" in row and row["date"]:
                try:
                    date_scored = datetime.strptime(row["date"], "%Y-%m-%d").date()
                except ValueError:
                    pass

            batch.append({
                "cve_id": cve_id,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "date_scored": date_scored,
                "data_last_updated": datetime.now(),
            })

            if len(batch) >= batch_size:
                # Upsert batch
                stmt = insert(EPSSScore).values(batch)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["cve_id"],
                    set_={
                        "epss_score": stmt.excluded.epss_score,
                        "epss_percentile": stmt.excluded.epss_percentile,
                        "date_scored": stmt.excluded.date_scored,
                        "data_last_updated": stmt.excluded.data_last_updated,
                    },
                )
                await session.execute(stmt)
                await session.commit()

                total_records += len(batch)
                logger.info("EPSS sync progress", processed=total_records)
                batch = []

        # Insert remaining
        if batch:
            stmt = insert(EPSSScore).values(batch)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "epss_score": stmt.excluded.epss_score,
                    "epss_percentile": stmt.excluded.epss_percentile,
                    "date_scored": stmt.excluded.date_scored,
                    "data_last_updated": stmt.excluded.data_last_updated,
                },
            )
            await session.execute(stmt)
            await session.commit()
            total_records += len(batch)

        # Update has_epss_score flags
        epss_cve_ids = await session.execute(select(EPSSScore.cve_id))
        epss_ids = [row[0] for row in epss_cve_ids.all()]

        if epss_ids:
            # Update in batches to avoid memory issues
            for i in range(0, len(epss_ids), 10000):
                batch_ids = epss_ids[i : i + 10000]
                await session.execute(
                    update(CVE).where(CVE.cve_id.in_(batch_ids)).values(has_epss_score=True)
                )
            await session.commit()

    sync_duration = int((datetime.now() - sync_start).total_seconds())

    await _update_sync_metadata(
        "epss_scores",
        last_sync_time=datetime.now(),
        last_sync_status="success",
        records_synced=total_records,
        sync_duration_seconds=sync_duration,
        error_message=None,
    )

    logger.info(
        "EPSS sync complete",
        total_records=total_records,
        skipped=skipped,
        duration_seconds=sync_duration,
    )

    return {"synced": total_records, "skipped": skipped}


@celery_app.task(bind=True, max_retries=3)
def sync_epss_scores(self):
    """
    Daily EPSS sync: Download and update EPSS scores from FIRST.org.
    """
    try:
        return asyncio.run(_sync_epss_scores_async())
    except Exception as exc:
        logger.exception("EPSS sync failed", error=str(exc))
        asyncio.run(
            _update_sync_metadata(
                "epss_scores",
                last_sync_status="failed",
                error_message=str(exc),
            )
        )
        raise self.retry(exc=exc, countdown=60 * (2**self.request.retries))
