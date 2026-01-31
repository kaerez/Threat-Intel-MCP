"""MITRE CAPEC data synchronization with semantic embeddings.

Downloads CAPEC STIX bundle, parses, generates embeddings, and populates database.
CAPEC is the Common Attack Pattern Enumeration and Classification framework.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from cve_mcp.config import get_settings
from cve_mcp.ingest.capec_parser import (
    parse_attack_pattern,
    parse_category,
    parse_mitigation,
)
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.models.capec import (
    CAPECCategory,
    CAPECMitigation,
    CAPECPattern,
)
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.services.embeddings import generate_embeddings_batch

logger = logging.getLogger(__name__)
settings = get_settings()

# MITRE CAPEC STIX bundle URL
CAPEC_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"


async def download_capec_bundle(cache_dir: Path) -> Path:
    """Download CAPEC STIX bundle from GitHub.

    Args:
        cache_dir: Directory to cache downloaded bundle

    Returns:
        Path to downloaded bundle file
    """
    # Create cache directory if needed
    cache_dir.mkdir(parents=True, exist_ok=True)

    filename = "stix-capec.json"
    bundle_path = cache_dir / filename

    # Check if already cached
    if bundle_path.exists():
        logger.info(f"Using cached bundle: {bundle_path}")
        return bundle_path

    logger.info(f"Downloading CAPEC STIX bundle from {CAPEC_BUNDLE_URL}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(CAPEC_BUNDLE_URL)
        response.raise_for_status()

        # Parse and save bundle
        bundle = response.json()
        with open(bundle_path, "w") as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"Downloaded bundle to {bundle_path}")

    return bundle_path


def _extract_capec_id(pattern_id: str) -> int | None:
    """Extract numeric CAPEC ID from pattern_id string.

    Args:
        pattern_id: Pattern ID like "CAPEC-1" or "1"

    Returns:
        Integer CAPEC ID or None if invalid
    """
    if not pattern_id:
        return None

    # Remove "CAPEC-" prefix if present
    if pattern_id.startswith("CAPEC-"):
        pattern_id = pattern_id[6:]

    try:
        return int(pattern_id)
    except ValueError:
        return None


async def import_capec_bundle(
    bundle_path: Path,
    generate_embeddings: bool = True,
) -> dict[str, int]:
    """Import CAPEC STIX bundle into database with optional embeddings.

    Args:
        bundle_path: Path to CAPEC JSON bundle
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Dictionary with import statistics
    """
    logger.info(f"Importing CAPEC data from {bundle_path}")

    # Load bundle
    with open(bundle_path) as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Separate objects by type
    patterns_data: list[dict[str, Any]] = []
    categories_data: list[dict[str, Any]] = []
    mitigations_data: list[dict[str, Any]] = []

    # Parse all objects
    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "attack-pattern":
            parsed = parse_attack_pattern(obj)
            if parsed:
                patterns_data.append(parsed)

        elif obj_type == "x-capec-category":
            parsed = parse_category(obj)
            if parsed:
                # Add capec_id from category_id (required by model)
                capec_id = _extract_capec_id(parsed["category_id"])
                if capec_id:
                    parsed["capec_id"] = capec_id
                    categories_data.append(parsed)

        elif obj_type == "course-of-action":
            parsed = parse_mitigation(obj)
            if parsed:
                mitigations_data.append(parsed)

    logger.info(
        f"Parsed {len(patterns_data)} patterns, {len(categories_data)} categories, "
        f"{len(mitigations_data)} mitigations"
    )

    # Generate embeddings if requested
    embedding_model = "text-embedding-3-small"
    embedding_timestamp = datetime.utcnow()

    if generate_embeddings and (patterns_data or mitigations_data):
        logger.info("Generating semantic embeddings...")

        # Generate pattern embeddings
        if patterns_data:
            pattern_texts = [
                f"{p['name']}: {p['description'][:8000]}" for p in patterns_data
            ]
            pattern_embeddings = await generate_embeddings_batch(pattern_texts)

            for pattern, embedding in zip(patterns_data, pattern_embeddings):
                pattern["embedding"] = embedding
                pattern["embedding_model"] = embedding_model
                pattern["embedding_generated_at"] = embedding_timestamp

            logger.info(f"Generated {len(pattern_embeddings)} pattern embeddings")

        # Generate mitigation embeddings
        if mitigations_data:
            mitigation_texts = [
                f"{m['name']}: {m['description'][:8000]}" for m in mitigations_data
            ]
            mitigation_embeddings = await generate_embeddings_batch(mitigation_texts)

            for mitigation, embedding in zip(mitigations_data, mitigation_embeddings):
                mitigation["embedding"] = embedding
                mitigation["embedding_model"] = embedding_model
                mitigation["embedding_generated_at"] = embedding_timestamp

            logger.info(
                f"Generated {len(mitigation_embeddings)} mitigation embeddings"
            )

    # Import into database
    async with AsyncSessionLocal() as session:
        # Import patterns
        for pattern_data in patterns_data:
            # Map parser fields to model fields
            model_data = _map_pattern_to_model(pattern_data)
            pattern = CAPECPattern(**model_data)
            await session.merge(pattern)

        # Import categories
        for category_data in categories_data:
            category = CAPECCategory(**category_data)
            await session.merge(category)

        # Import mitigations
        for mitigation_data in mitigations_data:
            mitigation = CAPECMitigation(**mitigation_data)
            await session.merge(mitigation)

        await session.commit()
        logger.info("Committed CAPEC objects to database")

    return {
        "patterns": len(patterns_data),
        "categories": len(categories_data),
        "mitigations": len(mitigations_data),
    }


def _map_pattern_to_model(pattern_data: dict[str, Any]) -> dict[str, Any]:
    """Map parser output to CAPECPattern model fields.

    The parser returns field names that may differ from the model.
    This function handles the mapping.

    Args:
        pattern_data: Parsed pattern data from capec_parser

    Returns:
        Dictionary ready for CAPECPattern model
    """
    # Direct mappings (parser field -> model field)
    model_data = {
        "pattern_id": pattern_data["pattern_id"],
        "capec_id": pattern_data["capec_id"],
        "stix_id": pattern_data["stix_id"],
        "name": pattern_data["name"],
        "description": pattern_data["description"],
        "abstraction": pattern_data.get("abstraction"),
        "status": pattern_data.get("status"),
        "parent_of": pattern_data.get("parent_of"),
        "child_of": pattern_data.get("child_of"),
        "can_precede": pattern_data.get("can_precede"),
        "can_follow": pattern_data.get("can_follow"),
        "peer_of": pattern_data.get("peer_of"),
        "prerequisites": pattern_data.get("prerequisites"),
        "skills_required": pattern_data.get("skills_required"),
        "execution_flow": pattern_data.get("execution_flow"),
        "consequences": pattern_data.get("consequences"),
        "version": pattern_data.get("version"),
        "created": pattern_data["created"],
        "modified": pattern_data["modified"],
        "deprecated": pattern_data.get("deprecated", False),
        "stix_extensions": pattern_data.get("stix_extensions"),
    }

    # Map likelihood_of_attack -> attack_likelihood
    if "likelihood_of_attack" in pattern_data:
        model_data["attack_likelihood"] = pattern_data["likelihood_of_attack"]

    # Map typical_severity (parser) -> typical_severity (model)
    if "typical_severity" in pattern_data:
        model_data["typical_severity"] = pattern_data["typical_severity"]

    # Map example_instances -> examples
    if "example_instances" in pattern_data:
        model_data["examples"] = pattern_data["example_instances"]

    # Map mitigation_refs -> mitigations
    if "mitigation_refs" in pattern_data:
        model_data["mitigations"] = pattern_data["mitigation_refs"]

    # Add embedding fields if present
    if "embedding" in pattern_data:
        model_data["embedding"] = pattern_data["embedding"]
        model_data["embedding_model"] = pattern_data.get("embedding_model")
        model_data["embedding_generated_at"] = pattern_data.get(
            "embedding_generated_at"
        )

    return model_data


async def sync_capec_data(
    cache_dir: Path | None = None,
    generate_embeddings: bool = True,
    force_download: bool = False,
) -> dict[str, int]:
    """Sync CAPEC data with semantic embeddings.

    Downloads STIX bundle from MITRE CAPEC repository,
    parses, generates embeddings, and imports into database.

    Args:
        cache_dir: Directory to cache STIX bundle (default: /tmp/capec-bundles)
        generate_embeddings: Whether to generate semantic embeddings
        force_download: Force re-download even if cached

    Returns:
        Statistics for imported objects
    """
    if cache_dir is None:
        cache_dir = Path("/tmp/capec-bundles")

    logger.info("Starting CAPEC data sync")
    logger.info(f"Embeddings: {'enabled' if generate_embeddings else 'disabled'}")

    start_time = datetime.utcnow()
    error_message = None
    stats: dict[str, int] = {}

    try:
        # Remove cached bundle if force download
        if force_download:
            cached_path = cache_dir / "stix-capec.json"
            if cached_path.exists():
                cached_path.unlink()
                logger.info("Removed cached bundle for fresh download")

        # Download bundle
        bundle_path = await download_capec_bundle(cache_dir)

        # Import bundle
        stats = await import_capec_bundle(bundle_path, generate_embeddings)

        # Update sync metadata
        async with AsyncSessionLocal() as session:
            sync_metadata = SyncMetadata(
                source="capec",
                last_sync_time=datetime.utcnow(),
                last_sync_status="success",
                records_synced=sum(stats.values()),
                sync_duration_seconds=int(
                    (datetime.utcnow() - start_time).total_seconds()
                ),
            )
            await session.merge(sync_metadata)
            await session.commit()

        logger.info(f"CAPEC sync complete: {stats}")

    except Exception as e:
        error_message = str(e)
        logger.error(f"CAPEC sync failed: {error_message}", exc_info=True)

        # Update sync metadata with failure
        try:
            async with AsyncSessionLocal() as session:
                sync_metadata = SyncMetadata(
                    source="capec",
                    last_sync_time=datetime.utcnow(),
                    last_sync_status="failed",
                    records_synced=0,
                    error_message=error_message,
                    sync_duration_seconds=int(
                        (datetime.utcnow() - start_time).total_seconds()
                    ),
                )
                await session.merge(sync_metadata)
                await session.commit()
        except Exception as metadata_error:
            logger.error(f"Failed to update sync metadata: {metadata_error}")

        raise

    return stats
