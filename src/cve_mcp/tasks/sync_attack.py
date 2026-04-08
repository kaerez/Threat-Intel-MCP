"""ATT&CK data synchronization with semantic embeddings.

Downloads MITRE ATT&CK STIX bundles, parses, generates embeddings, and populates database.
"""

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import structlog
from sqlalchemy import select

from cve_mcp.config import get_settings
from cve_mcp.ingest.attack_parser import (
    parse_group,
    parse_mitigation,
    parse_software,
    parse_tactic,
    parse_technique,
)
from cve_mcp.models.attack import (
    AttackGroup,
    AttackMitigation,
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
)
from cve_mcp.models.base import get_task_session
from cve_mcp.services.embeddings import generate_embeddings_batch
from cve_mcp.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)
slogger = structlog.get_logger()
settings = get_settings()

# MITRE ATT&CK CTI repository URLs
STIX_BUNDLE_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}


async def download_stix_bundle(url: str, cache_dir: Path) -> Path:
    """Download STIX bundle from MITRE GitHub.

    Args:
        url: URL to STIX JSON bundle
        cache_dir: Directory to cache downloaded bundles

    Returns:
        Path to downloaded bundle file
    """
    # Create cache directory if needed
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Extract filename from URL
    filename = url.split("/")[-1]
    bundle_path = cache_dir / filename

    # Check if already cached
    if bundle_path.exists():
        logger.info(f"Using cached bundle: {bundle_path}")
        return bundle_path

    logger.info(f"Downloading STIX bundle from {url}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()

        # Parse and save bundle
        bundle = response.json()
        with open(bundle_path, "w") as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"Downloaded bundle to {bundle_path}")

    return bundle_path


async def import_stix_bundle(
    bundle_path: Path,
    framework: str,
    generate_embeddings: bool = True,
) -> dict[str, int]:
    """Import STIX bundle into database with optional embeddings.

    Args:
        bundle_path: Path to STIX JSON bundle
        framework: Framework name (enterprise, mobile, ics)
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Dictionary with import statistics
    """
    logger.info(f"Importing {framework} ATT&CK data from {bundle_path}")

    # Load bundle
    with open(bundle_path) as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Separate objects by type
    techniques_data = []
    groups_data = []
    tactics_data = []
    software_data = []
    mitigations_data = []
    relationships = []

    # Track STIX ID to external ID mapping for relationships
    stix_id_map: dict[str, tuple[str, str]] = {}

    # Parse all objects
    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "attack-pattern":
            parsed = parse_technique(obj)
            if parsed:
                techniques_data.append(parsed)
                stix_id_map[obj["id"]] = ("technique", parsed["technique_id"])

        elif obj_type == "intrusion-set":
            parsed = parse_group(obj)
            if parsed:
                groups_data.append(parsed)
                stix_id_map[obj["id"]] = ("group", parsed["group_id"])

        elif obj_type == "x-mitre-tactic":
            parsed = parse_tactic(obj)
            if parsed:
                tactics_data.append(parsed)
                stix_id_map[obj["id"]] = ("tactic", parsed["tactic_id"])

        elif obj_type in ("malware", "tool"):
            parsed = parse_software(obj)
            if parsed:
                software_data.append(parsed)
                stix_id_map[obj["id"]] = ("software", parsed["software_id"])

        elif obj_type == "course-of-action":
            parsed = parse_mitigation(obj)
            if parsed:
                mitigations_data.append(parsed)
                stix_id_map[obj["id"]] = ("mitigation", parsed["mitigation_id"])

        elif obj_type == "relationship":
            relationships.append(obj)

    logger.info(
        f"Parsed {len(techniques_data)} techniques, {len(groups_data)} groups, "
        f"{len(tactics_data)} tactics, {len(software_data)} software, "
        f"{len(mitigations_data)} mitigations"
    )

    # Generate embeddings if requested
    embedding_model = "text-embedding-3-small"
    embedding_timestamp = datetime.utcnow()

    if generate_embeddings and (techniques_data or groups_data):
        logger.info("Generating semantic embeddings...")

        # Generate technique embeddings
        if techniques_data:
            technique_texts = [
                f"{t['name']}: {t['description'][:8000]}" for t in techniques_data
            ]
            technique_embeddings = await generate_embeddings_batch(technique_texts)

            for technique, embedding in zip(techniques_data, technique_embeddings):
                technique["embedding"] = embedding
                technique["embedding_model"] = embedding_model
                technique["embedding_generated_at"] = embedding_timestamp

            logger.info(f"Generated {len(technique_embeddings)} technique embeddings")

        # Generate group embeddings
        if groups_data:
            group_texts = []
            for g in groups_data:
                aliases = ", ".join(g.get("aliases", []) or [])
                text = f"{g['name']} (aka {aliases}): {g['description'][:8000]}"
                group_texts.append(text)

            group_embeddings = await generate_embeddings_batch(group_texts)

            for group, embedding in zip(groups_data, group_embeddings):
                group["embedding"] = embedding
                group["embedding_model"] = embedding_model
                group["embedding_generated_at"] = embedding_timestamp

            logger.info(f"Generated {len(group_embeddings)} group embeddings")

    # Import into database
    async with get_task_session() as session:
        # Import techniques - parents first, then sub-techniques (FK constraint)
        parent_techniques = [t for t in techniques_data if not t.get("is_subtechnique")]
        sub_techniques = [t for t in techniques_data if t.get("is_subtechnique")]

        for tech_data in parent_techniques:
            technique = AttackTechnique(**tech_data)
            await session.merge(technique)

        # Flush to ensure parents exist before sub-techniques
        await session.flush()

        for tech_data in sub_techniques:
            technique = AttackTechnique(**tech_data)
            await session.merge(technique)

        # Import groups
        for group_data in groups_data:
            group = AttackGroup(**group_data)
            await session.merge(group)

        # Import tactics
        for tactic_data in tactics_data:
            tactic = AttackTactic(**tactic_data)
            await session.merge(tactic)

        # Import software
        for software_item in software_data:
            software = AttackSoftware(**software_item)
            await session.merge(software)

        # Import mitigations
        for mitigation_data in mitigations_data:
            mitigation = AttackMitigation(**mitigation_data)
            await session.merge(mitigation)

        await session.commit()
        logger.info("Committed objects to database")

    # Process relationships (after objects are imported)
    if relationships:
        await process_relationships(relationships, stix_id_map)

    return {
        "techniques": len(techniques_data),
        "groups": len(groups_data),
        "tactics": len(tactics_data),
        "software": len(software_data),
        "mitigations": len(mitigations_data),
    }


async def process_relationships(
    relationships: list[dict[str, Any]],
    stix_id_map: dict[str, tuple[str, str]],
) -> None:
    """Process STIX relationships to populate association arrays.

    Updates:
    - group.techniques_used (group -> technique)
    - group.software_used (group -> software)
    - software.techniques_used (software -> technique)
    - mitigation.mitigates_techniques (mitigation -> technique)

    Args:
        relationships: List of STIX relationship objects
        stix_id_map: Mapping of STIX ID to (type, external_id)
    """
    logger.info(f"Processing {len(relationships)} relationships")

    # Organize relationships by type
    group_techniques: dict[str, list[str]] = defaultdict(list)
    group_software: dict[str, list[str]] = defaultdict(list)
    software_techniques: dict[str, list[str]] = defaultdict(list)
    mitigation_techniques: dict[str, list[str]] = defaultdict(list)

    for rel in relationships:
        rel_type = rel.get("relationship_type")
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")

        # Skip if source or target not in our map
        if source_ref not in stix_id_map or target_ref not in stix_id_map:
            continue

        source_type, source_id = stix_id_map[source_ref]
        target_type, target_id = stix_id_map[target_ref]

        # Group uses technique
        if rel_type == "uses" and source_type == "group" and target_type == "technique":
            group_techniques[source_id].append(target_id)

        # Group uses software
        elif rel_type == "uses" and source_type == "group" and target_type == "software":
            group_software[source_id].append(target_id)

        # Software uses technique
        elif rel_type == "uses" and source_type == "software" and target_type == "technique":
            software_techniques[source_id].append(target_id)

        # Mitigation mitigates technique
        elif rel_type == "mitigates" and source_type == "mitigation" and target_type == "technique":
            mitigation_techniques[source_id].append(target_id)

    # Update database with relationships
    async with get_task_session() as session:
        # Update group.techniques_used
        for group_id, technique_ids in group_techniques.items():
            result = await session.execute(
                select(AttackGroup).filter(AttackGroup.group_id == group_id)
            )
            group = result.scalar_one_or_none()
            if group:
                group.techniques_used = technique_ids

        # Update group.software_used
        for group_id, software_ids in group_software.items():
            result = await session.execute(
                select(AttackGroup).filter(AttackGroup.group_id == group_id)
            )
            group = result.scalar_one_or_none()
            if group:
                group.software_used = software_ids

        # Update software.techniques_used
        for software_id, technique_ids in software_techniques.items():
            result = await session.execute(
                select(AttackSoftware).filter(AttackSoftware.software_id == software_id)
            )
            software = result.scalar_one_or_none()
            if software:
                software.techniques_used = technique_ids

        # Update mitigation.mitigates_techniques
        for mitigation_id, technique_ids in mitigation_techniques.items():
            result = await session.execute(
                select(AttackMitigation).filter(AttackMitigation.mitigation_id == mitigation_id)
            )
            mitigation = result.scalar_one_or_none()
            if mitigation:
                mitigation.mitigates_techniques = technique_ids

        await session.commit()
        logger.info("Updated relationship associations")


async def sync_attack_data(
    cache_dir: Path | None = None,
    generate_embeddings: bool = True,
) -> dict[str, int]:
    """Sync all ATT&CK frameworks with semantic embeddings.

    Downloads STIX bundles for enterprise, mobile, and ICS frameworks,
    parses, generates embeddings, and imports into database.

    Args:
        cache_dir: Directory to cache STIX bundles (default: /tmp/attack-bundles)
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Aggregated statistics for all frameworks
    """
    if cache_dir is None:
        cache_dir = Path("/tmp/attack-bundles")

    logger.info("Starting ATT&CK data sync")
    logger.info(f"Embeddings: {'enabled' if generate_embeddings else 'disabled'}")

    total_stats = defaultdict(int)

    for framework, url in STIX_BUNDLE_URLS.items():
        logger.info(f"Syncing {framework} framework...")

        # Download bundle
        bundle_path = await download_stix_bundle(url, cache_dir)

        # Import bundle
        stats = await import_stix_bundle(bundle_path, framework, generate_embeddings)

        # Aggregate stats
        for key, value in stats.items():
            total_stats[key] += value

        logger.info(f"Completed {framework}: {stats}")

    logger.info(f"ATT&CK sync complete: {dict(total_stats)}")

    return dict(total_stats)


@celery_app.task(bind=True, max_retries=2)
def sync_attack(self):
    """Celery task: Sync MITRE ATT&CK data (enterprise, mobile, ICS)."""
    try:
        return asyncio.run(sync_attack_data(generate_embeddings=False))
    except Exception as exc:
        slogger.exception("ATT&CK sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2**self.request.retries))
