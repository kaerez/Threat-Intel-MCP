"""NVD CVE sync tasks."""

import asyncio
from datetime import datetime, timedelta

import httpx
import structlog
from sqlalchemy import delete, select, update

from cve_mcp.config import get_settings
from cve_mcp.models import CVE, CVECPEMapping, CVEReference, SyncMetadata
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.tasks.celery_app import celery_app
from cve_mcp.utils.nvd_parser import parse_nvd_cve

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


async def _sync_nvd_recent_async() -> dict:
    """Async implementation of NVD recent sync."""
    settings = get_settings()

    # Get last sync time
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(SyncMetadata).where(SyncMetadata.source == "nvd_recent")
        )
        metadata = result.scalar_one_or_none()

    # Calculate time window (last 30 days or since last successful sync)
    if metadata and metadata.last_sync_status == "success":
        start_date = max(metadata.last_sync_time, datetime.now() - timedelta(days=30))
    else:
        start_date = datetime.now() - timedelta(days=30)

    end_date = datetime.now()

    await _update_sync_metadata(
        "nvd_recent",
        last_sync_status="running",
        last_sync_time=datetime.now(),
    )

    stats = {"inserted": 0, "updated": 0, "errors": 0}
    sync_start = datetime.now()

    async with httpx.AsyncClient(timeout=60.0) as client:
        start_index = 0
        results_per_page = 2000

        while True:
            try:
                params = {
                    "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                }

                headers = {}
                if settings.nvd_api_key:
                    headers["apiKey"] = settings.nvd_api_key

                response = await client.get(
                    settings.nvd_api_base_url,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 429:
                    # Rate limited - wait and retry
                    logger.warning("NVD rate limited, waiting 30s")
                    await asyncio.sleep(30)
                    continue

                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                # Process CVEs in batches
                async with AsyncSessionLocal() as session:
                    for vuln_item in vulnerabilities:
                        try:
                            cve_data = parse_nvd_cve(vuln_item)
                            cve_id = cve_data["cve_id"]

                            # Check if exists
                            existing = await session.execute(
                                select(CVE).where(CVE.cve_id == cve_id)
                            )
                            existing_cve = existing.scalar_one_or_none()

                            if existing_cve:
                                # Update existing
                                for key, value in cve_data.items():
                                    if key not in ["references", "cpe_mappings"]:
                                        setattr(existing_cve, key, value)
                                stats["updated"] += 1
                            else:
                                # Create new
                                cve_record = CVE(
                                    **{k: v for k, v in cve_data.items() if k not in ["references", "cpe_mappings"]}
                                )
                                session.add(cve_record)
                                stats["inserted"] += 1

                            # Update references
                            await session.execute(
                                delete(CVEReference).where(CVEReference.cve_id == cve_id)
                            )
                            if cve_data.get("references"):
                                for ref in cve_data["references"]:
                                    ref_record = CVEReference(cve_id=cve_id, **ref)
                                    session.add(ref_record)

                            # Update CPE mappings
                            await session.execute(
                                delete(CVECPEMapping).where(CVECPEMapping.cve_id == cve_id)
                            )
                            if cve_data.get("cpe_mappings"):
                                for cpe in cve_data["cpe_mappings"]:
                                    cpe_record = CVECPEMapping(cve_id=cve_id, **cpe)
                                    session.add(cpe_record)

                        except Exception as e:
                            logger.error(
                                "Error processing CVE",
                                cve_id=vuln_item.get("cve", {}).get("id"),
                                error=str(e),
                            )
                            stats["errors"] += 1

                    await session.commit()

                logger.info(
                    "NVD sync progress",
                    processed=start_index + len(vulnerabilities),
                    inserted=stats["inserted"],
                    updated=stats["updated"],
                )

                if len(vulnerabilities) < results_per_page:
                    break

                start_index += results_per_page

                # Rate limiting (with API key: 50 req/30s, without: 5 req/30s)
                if settings.nvd_api_key:
                    await asyncio.sleep(0.6)
                else:
                    await asyncio.sleep(6)

            except httpx.HTTPStatusError as e:
                logger.error("NVD API error", status=e.response.status_code)
                raise

    # Update sync metadata
    sync_duration = int((datetime.now() - sync_start).total_seconds())
    await _update_sync_metadata(
        "nvd_recent",
        last_sync_time=end_date,
        last_sync_status="success",
        records_synced=stats["inserted"] + stats["updated"],
        records_inserted=stats["inserted"],
        records_updated=stats["updated"],
        sync_duration_seconds=sync_duration,
        error_message=None,
    )

    logger.info("NVD recent sync complete", stats=stats, duration_seconds=sync_duration)
    return stats


@celery_app.task(bind=True, max_retries=3)
def sync_nvd_recent(self):
    """
    Daily delta sync: Fetch CVEs modified in last 30 days from NVD API 2.0.
    """
    try:
        return asyncio.run(_sync_nvd_recent_async())
    except Exception as exc:
        logger.exception("NVD recent sync failed", error=str(exc))
        # Update metadata with error
        asyncio.run(
            _update_sync_metadata(
                "nvd_recent",
                last_sync_status="failed",
                error_message=str(exc),
            )
        )
        raise self.retry(exc=exc, countdown=60 * (2**self.request.retries))


async def _sync_nvd_full_async() -> dict:
    """Async implementation of full NVD sync."""
    settings = get_settings()

    await _update_sync_metadata(
        "nvd_full",
        last_sync_status="running",
        last_sync_time=datetime.now(),
    )

    stats = {"inserted": 0, "updated": 0, "errors": 0}
    sync_start = datetime.now()

    async with httpx.AsyncClient(timeout=120.0) as client:
        start_index = 0
        results_per_page = 2000

        while True:
            try:
                params = {
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                }

                headers = {}
                if settings.nvd_api_key:
                    headers["apiKey"] = settings.nvd_api_key

                response = await client.get(
                    settings.nvd_api_base_url,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 429:
                    logger.warning("NVD rate limited, waiting 30s")
                    await asyncio.sleep(30)
                    continue

                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulnerabilities:
                    break

                # Process CVEs in batches
                async with AsyncSessionLocal() as session:
                    for vuln_item in vulnerabilities:
                        try:
                            cve_data = parse_nvd_cve(vuln_item)
                            cve_id = cve_data["cve_id"]

                            existing = await session.execute(
                                select(CVE).where(CVE.cve_id == cve_id)
                            )
                            existing_cve = existing.scalar_one_or_none()

                            if existing_cve:
                                for key, value in cve_data.items():
                                    if key not in ["references", "cpe_mappings"]:
                                        setattr(existing_cve, key, value)
                                stats["updated"] += 1
                            else:
                                cve_record = CVE(
                                    **{k: v for k, v in cve_data.items() if k not in ["references", "cpe_mappings"]}
                                )
                                session.add(cve_record)
                                stats["inserted"] += 1

                            # Update references
                            await session.execute(
                                delete(CVEReference).where(CVEReference.cve_id == cve_id)
                            )
                            if cve_data.get("references"):
                                for ref in cve_data["references"]:
                                    ref_record = CVEReference(cve_id=cve_id, **ref)
                                    session.add(ref_record)

                            # Update CPE mappings
                            await session.execute(
                                delete(CVECPEMapping).where(CVECPEMapping.cve_id == cve_id)
                            )
                            if cve_data.get("cpe_mappings"):
                                for cpe in cve_data["cpe_mappings"]:
                                    cpe_record = CVECPEMapping(cve_id=cve_id, **cpe)
                                    session.add(cpe_record)

                        except Exception as e:
                            logger.error(
                                "Error processing CVE",
                                cve_id=vuln_item.get("cve", {}).get("id"),
                                error=str(e),
                            )
                            stats["errors"] += 1

                    await session.commit()

                logger.info(
                    "NVD full sync progress",
                    processed=start_index + len(vulnerabilities),
                    total=total_results,
                    percent=round((start_index + len(vulnerabilities)) / total_results * 100, 1),
                )

                if len(vulnerabilities) < results_per_page:
                    break

                start_index += results_per_page

                # Rate limiting
                if settings.nvd_api_key:
                    await asyncio.sleep(0.6)
                else:
                    await asyncio.sleep(6)

            except httpx.HTTPStatusError as e:
                logger.error("NVD API error", status=e.response.status_code)
                raise

    sync_duration = int((datetime.now() - sync_start).total_seconds())
    await _update_sync_metadata(
        "nvd_full",
        last_sync_time=datetime.now(),
        last_sync_status="success",
        records_synced=stats["inserted"] + stats["updated"],
        records_inserted=stats["inserted"],
        records_updated=stats["updated"],
        sync_duration_seconds=sync_duration,
        error_message=None,
    )

    logger.info("NVD full sync complete", stats=stats, duration_seconds=sync_duration)
    return stats


@celery_app.task(bind=True, max_retries=3)
def sync_nvd_full(self):
    """
    Monthly full sync: Complete rebuild of CVE database from NVD.
    """
    try:
        return asyncio.run(_sync_nvd_full_async())
    except Exception as exc:
        logger.exception("NVD full sync failed", error=str(exc))
        asyncio.run(
            _update_sync_metadata(
                "nvd_full",
                last_sync_status="failed",
                error_message=str(exc),
            )
        )
        raise self.retry(exc=exc, countdown=300 * (2**self.request.retries))
