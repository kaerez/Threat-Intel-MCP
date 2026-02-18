"""OWASP LLM Top 10 data synchronization.

Loads the OWASP Top 10 for LLM Applications v1.1 (2023) from a bundled
JSON file and upserts the 10 vulnerability definitions into the database.

This is a lightweight sync (static data, no external download) that
ensures the owasp_llm_top10 table stays populated after migrations or
database rebuilds.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

import structlog

from cve_mcp.models.base import get_task_session
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.models.owasp_llm import OwaspLlmTop10
from cve_mcp.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)
slogger = structlog.get_logger()

# Bundled data file ships with the repo
DATA_FILE = Path(__file__).resolve().parent.parent.parent.parent / "scripts" / "owasp_llm_data.json"


async def sync_owasp_llm_data() -> dict[str, int]:
    """Load OWASP LLM Top 10 definitions from JSON and upsert into database.

    Returns:
        Dictionary with import statistics (e.g. {"vulnerabilities": 10})
    """
    start_time = datetime.utcnow()

    # Load bundled JSON
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"OWASP LLM data file not found: {DATA_FILE}")

    with open(DATA_FILE) as f:
        vulnerabilities = json.load(f)

    logger.info(f"Loaded {len(vulnerabilities)} OWASP LLM Top 10 entries")

    # Upsert into database
    async with get_task_session() as session:
        for vuln in vulnerabilities:
            record = OwaspLlmTop10(
                llm_id=vuln["llm_id"],
                name=vuln["name"],
                description=vuln["description"],
                common_examples=vuln.get("common_examples"),
                prevention_strategies=vuln.get("prevention_strategies"),
                example_attack_scenarios=vuln.get("example_attack_scenarios"),
                related_techniques=vuln.get("related_techniques"),
                url=vuln.get("url"),
                version=vuln.get("version", "1.1"),
                data_last_updated=datetime.utcnow(),
            )
            await session.merge(record)

        await session.commit()
        logger.info(f"Upserted {len(vulnerabilities)} OWASP LLM Top 10 entries")

    # Update sync metadata
    async with get_task_session() as session:
        sync_metadata = SyncMetadata(
            source="owasp_llm_top10",
            last_sync_time=datetime.utcnow(),
            last_sync_status="success",
            records_synced=len(vulnerabilities),
            sync_duration_seconds=int((datetime.utcnow() - start_time).total_seconds()),
        )
        await session.merge(sync_metadata)
        await session.commit()

    stats = {"vulnerabilities": len(vulnerabilities)}
    logger.info(f"OWASP LLM Top 10 sync complete: {stats}")
    return stats


@celery_app.task(bind=True, max_retries=2)
def sync_owasp_llm(self):
    """Celery task: Sync OWASP LLM Top 10 data."""
    try:
        return asyncio.run(sync_owasp_llm_data())
    except Exception as exc:
        slogger.exception("OWASP LLM Top 10 sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))
