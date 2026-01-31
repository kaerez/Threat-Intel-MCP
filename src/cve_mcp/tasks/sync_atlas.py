"""MITRE ATLAS data synchronization with semantic embeddings.

Downloads ATLAS STIX bundle, parses, generates embeddings, and populates database.
ATLAS is the Adversarial Threat Landscape for AI Systems framework.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

from cve_mcp.config import get_settings
from cve_mcp.ingest.atlas_parser import (
    parse_case_study,
    parse_tactic,
    parse_technique,
)
from cve_mcp.models.atlas import (
    ATLASCaseStudy,
    ATLASTactic,
    ATLASTechnique,
)
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.services.embeddings import generate_embeddings_batch

logger = logging.getLogger(__name__)
settings = get_settings()

# MITRE ATLAS data repository URL (changed to YAML format)
ATLAS_BUNDLE_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"


async def download_atlas_bundle(cache_dir: Path) -> Path:
    """Download ATLAS bundle from GitHub.

    Args:
        cache_dir: Directory to cache downloaded bundle

    Returns:
        Path to downloaded bundle file (converted to JSON)
    """
    # Create cache directory if needed
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Download YAML but store as JSON for consistency with rest of codebase
    filename = "ATLAS.json"
    bundle_path = cache_dir / filename

    # Check if already cached
    if bundle_path.exists():
        logger.info(f"Using cached bundle: {bundle_path}")
        return bundle_path

    logger.info(f"Downloading ATLAS bundle from {ATLAS_BUNDLE_URL}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(ATLAS_BUNDLE_URL)
        response.raise_for_status()

        # Parse YAML and convert to JSON-like structure
        bundle = yaml.safe_load(response.text)
        with open(bundle_path, "w") as f:
            # Custom encoder to handle date objects from YAML
            json.dump(bundle, f, indent=2, default=str)

        logger.info(f"Downloaded bundle to {bundle_path}")

    return bundle_path


async def import_atlas_bundle(
    bundle_path: Path,
    generate_embeddings: bool = True,
) -> dict[str, int]:
    """Import ATLAS STIX bundle into database with optional embeddings.

    Args:
        bundle_path: Path to ATLAS JSON bundle
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Dictionary with import statistics
    """
    logger.info(f"Importing ATLAS data from {bundle_path}")

    # Load bundle
    with open(bundle_path) as f:
        bundle = json.load(f)

    # ATLAS YAML format: matrices[0] contains tactics and techniques
    # case-studies is at top level
    techniques_data: list[dict[str, Any]] = []
    tactics_data: list[dict[str, Any]] = []
    case_studies_data: list[dict[str, Any]] = []

    # Extract from new YAML format (matrices structure)
    matrices = bundle.get("matrices", [])
    if matrices:
        matrix = matrices[0]  # Use first matrix

        # Parse techniques from matrix
        for tech in matrix.get("techniques", []):
            parsed = parse_technique(tech)
            if parsed:
                techniques_data.append(parsed)

        # Parse tactics from matrix
        for tactic in matrix.get("tactics", []):
            parsed = parse_tactic(tactic)
            if parsed:
                tactics_data.append(parsed)

    # Parse case studies from top level
    for cs in bundle.get("case-studies", []):
        parsed = parse_case_study(cs)
        if parsed:
            case_studies_data.append(parsed)

    logger.info(
        f"Parsed {len(techniques_data)} techniques, {len(tactics_data)} tactics, "
        f"{len(case_studies_data)} case studies"
    )

    # Generate embeddings if requested
    embedding_model = "text-embedding-3-small"
    embedding_timestamp = datetime.utcnow()

    if generate_embeddings and (techniques_data or case_studies_data):
        logger.info("Generating semantic embeddings...")

        # Generate technique embeddings
        if techniques_data:
            technique_texts = [f"{t['name']}: {t['description'][:8000]}" for t in techniques_data]
            technique_embeddings = await generate_embeddings_batch(technique_texts)

            for technique, embedding in zip(techniques_data, technique_embeddings):
                technique["embedding"] = embedding
                technique["embedding_model"] = embedding_model
                technique["embedding_generated_at"] = embedding_timestamp

            logger.info(f"Generated {len(technique_embeddings)} technique embeddings")

        # Generate case study embeddings
        if case_studies_data:
            case_study_texts = []
            for cs in case_studies_data:
                # Combine name and summary for rich embedding
                text = f"{cs['name']}: {cs['summary'][:8000]}"
                case_study_texts.append(text)

            case_study_embeddings = await generate_embeddings_batch(case_study_texts)

            for case_study, embedding in zip(case_studies_data, case_study_embeddings):
                case_study["embedding"] = embedding
                case_study["embedding_model"] = embedding_model
                case_study["embedding_generated_at"] = embedding_timestamp

            logger.info(f"Generated {len(case_study_embeddings)} case study embeddings")

    # Import into database
    async with AsyncSessionLocal() as session:
        # Import techniques
        for tech_data in techniques_data:
            technique = ATLASTechnique(**tech_data)
            await session.merge(technique)

        # Import tactics
        for tactic_data in tactics_data:
            tactic = ATLASTactic(**tactic_data)
            await session.merge(tactic)

        # Import case studies
        for case_study_data in case_studies_data:
            case_study = ATLASCaseStudy(**case_study_data)
            await session.merge(case_study)

        await session.commit()
        logger.info("Committed ATLAS objects to database")

    return {
        "techniques": len(techniques_data),
        "tactics": len(tactics_data),
        "case_studies": len(case_studies_data),
    }


async def sync_atlas_data(
    cache_dir: Path | None = None,
    generate_embeddings: bool = True,
    force_download: bool = False,
) -> dict[str, int]:
    """Sync ATLAS data with semantic embeddings.

    Downloads STIX bundle from MITRE ATLAS repository,
    parses, generates embeddings, and imports into database.

    Args:
        cache_dir: Directory to cache STIX bundle (default: /tmp/atlas-bundles)
        generate_embeddings: Whether to generate semantic embeddings
        force_download: Force re-download even if cached

    Returns:
        Statistics for imported objects
    """
    if cache_dir is None:
        cache_dir = Path("/tmp/atlas-bundles")

    logger.info("Starting ATLAS data sync")
    logger.info(f"Embeddings: {'enabled' if generate_embeddings else 'disabled'}")

    start_time = datetime.utcnow()
    error_message = None
    stats: dict[str, int] = {}

    try:
        # Remove cached bundle if force download
        if force_download:
            cached_path = cache_dir / "ATLAS.json"
            if cached_path.exists():
                cached_path.unlink()
                logger.info("Removed cached bundle for fresh download")

        # Download bundle
        bundle_path = await download_atlas_bundle(cache_dir)

        # Import bundle
        stats = await import_atlas_bundle(bundle_path, generate_embeddings)

        # Update sync metadata
        async with AsyncSessionLocal() as session:
            sync_metadata = SyncMetadata(
                source="atlas",
                last_sync_time=datetime.utcnow(),
                last_sync_status="success",
                records_synced=sum(stats.values()),
                sync_duration_seconds=int((datetime.utcnow() - start_time).total_seconds()),
            )
            await session.merge(sync_metadata)
            await session.commit()

        logger.info(f"ATLAS sync complete: {stats}")

    except Exception as e:
        error_message = str(e)
        logger.error(f"ATLAS sync failed: {error_message}", exc_info=True)

        # Update sync metadata with failure
        try:
            async with AsyncSessionLocal() as session:
                sync_metadata = SyncMetadata(
                    source="atlas",
                    last_sync_time=datetime.utcnow(),
                    last_sync_status="failed",
                    records_synced=0,
                    error_message=error_message,
                    sync_duration_seconds=int((datetime.utcnow() - start_time).total_seconds()),
                )
                await session.merge(sync_metadata)
                await session.commit()
        except Exception as metadata_error:
            logger.error(f"Failed to update sync metadata: {metadata_error}")

        raise

    return stats
