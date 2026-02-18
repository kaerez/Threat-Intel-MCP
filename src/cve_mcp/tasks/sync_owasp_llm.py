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

from cve_mcp.models.base import get_task_session
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.models.owasp_llm import OwaspLlmTop10
from cve_mcp.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Resolve data file: try repo-relative first (local dev), then CWD-relative (Docker /app)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DATA_CANDIDATES = [
    _REPO_ROOT / "scripts" / "owasp_llm_data.json",  # local dev
    Path("scripts") / "owasp_llm_data.json",          # Docker WORKDIR /app
]


def _find_data_file() -> Path:
    """Locate the OWASP LLM data file across environments."""
    for candidate in _DATA_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"OWASP LLM data file not found. Searched: {[str(c) for c in _DATA_CANDIDATES]}"
    )


async def sync_owasp_llm_data() -> dict[str, int]:
    """Load OWASP LLM Top 10 definitions from JSON and upsert into database.

    Returns:
        Dictionary with import statistics (e.g. {"vulnerabilities": 10})
    """
    start_time = datetime.utcnow()

    data_file = _find_data_file()
    with open(data_file) as f:
        vulnerabilities = json.load(f)

    logger.info(f"Loaded {len(vulnerabilities)} OWASP LLM Top 10 entries from {data_file}")

    # Upsert into database + update sync metadata in one session
    async with get_task_session() as session:
        for vuln in vulnerabilities:
            async with session.begin_nested():
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

        logger.info(f"Upserted {len(vulnerabilities)} OWASP LLM Top 10 entries")

        # Update sync metadata in the same session
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
        logger.exception("OWASP LLM Top 10 sync failed", exc_info=exc)
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))
