"""Sync task for D3FEND defensive countermeasures data.

Downloads D3FEND data from MISP Galaxy, parses it, validates ATT&CK FKs,
and stores in database with optional embeddings.

Also downloads the D3FEND ontology to extract D3FEND→ATT&CK technique
mappings through shared digital artifacts (the MISP Galaxy data does NOT
contain these mappings).
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.ingest.d3fend_parser import (
    extract_ontology_attack_mappings,
    parse_technique,
)
from cve_mcp.models.attack import AttackTechnique
from cve_mcp.models.base import get_task_session
from cve_mcp.models.d3fend import (
    D3FENDRelationshipType,
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDTechniqueAttackMapping,
)
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.services.embeddings import generate_embedding
from cve_mcp.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)
slogger = structlog.get_logger()

D3FEND_DATA_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-d3fend.json"
D3FEND_ONTOLOGY_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"

# Tactic display order (based on D3FEND kill chain)
TACTIC_ORDER = {
    "D3-MODEL": 0,
    "D3-HARDEN": 1,
    "D3-DETECT": 2,
    "D3-ISOLATE": 3,
    "D3-DECEIVE": 4,
    "D3-EVICT": 5,
    "D3-RESTORE": 6,
}

# Tactic descriptions from D3FEND ontology
TACTIC_DESCRIPTIONS = {
    "D3-MODEL": "Techniques for establishing a baseline model of the system to protect.",
    "D3-HARDEN": "Techniques for making systems more resistant to attack.",
    "D3-DETECT": "Techniques for identifying malicious activity.",
    "D3-ISOLATE": "Techniques for separating systems or components.",
    "D3-DECEIVE": "Techniques for misleading adversaries.",
    "D3-EVICT": "Techniques for removing adversary presence.",
    "D3-RESTORE": "Techniques for recovering from incidents.",
}


async def download_d3fend_data(url: str = D3FEND_DATA_URL) -> dict[str, Any]:
    """Download D3FEND data from MISP Galaxy.

    Args:
        url: URL to D3FEND MISP Galaxy JSON file

    Returns:
        Parsed JSON data with D3FEND techniques

    Raises:
        httpx.HTTPStatusError: If download fails
    """
    logger.info(f"Downloading D3FEND data from {url}")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

    logger.info(f"Downloaded D3FEND data: {data.get('name', 'unknown')}")
    return data


async def download_d3fend_ontology(url: str = D3FEND_ONTOLOGY_URL) -> dict[str, Any]:
    """Download D3FEND ontology JSON for ATT&CK mapping extraction.

    The ontology contains the full D3FEND knowledge graph including
    relationships between D3FEND techniques, digital artifacts, and
    ATT&CK offensive techniques.

    Args:
        url: URL to D3FEND ontology JSON file

    Returns:
        Parsed JSON-LD ontology data

    Raises:
        httpx.HTTPStatusError: If download fails
    """
    logger.info(f"Downloading D3FEND ontology from {url}")

    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

    graph_count = len(data.get("@graph", []))
    logger.info(f"Downloaded D3FEND ontology: {graph_count} graph entries")
    return data


def extract_tactics(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract unique tactics from parsed techniques.

    Args:
        techniques: List of parsed technique dictionaries with tactic_id

    Returns:
        List of tactic dictionaries with tactic_id, name, description, display_order
    """
    seen: set[str] = set()
    tactics: list[dict[str, Any]] = []

    for tech in techniques:
        tactic_id = tech.get("tactic_id")

        # Skip if no tactic_id or already seen
        if not tactic_id or tactic_id in seen:
            continue

        seen.add(tactic_id)

        # Format name from tactic_id (D3-HARDEN -> Harden)
        name = tactic_id.replace("D3-", "").title()

        tactics.append({
            "tactic_id": tactic_id,
            "name": name,
            "description": TACTIC_DESCRIPTIONS.get(tactic_id, ""),
            "display_order": TACTIC_ORDER.get(tactic_id, 99),
        })

    return tactics


def _map_relationship_type(relationship_str: str | None) -> D3FENDRelationshipType | None:
    """Map relationship string to enum value.

    Handles both MISP Galaxy relationship types and D3FEND ontology property names.

    Args:
        relationship_str: Relationship type string from parser

    Returns:
        D3FENDRelationshipType enum value or None if unknown
    """
    if not relationship_str:
        return None

    normalized = relationship_str.lower().replace("_", "-")

    # Try direct enum lookup first
    try:
        return D3FENDRelationshipType(normalized)
    except ValueError:
        pass

    # Fallback mapping for alternative names
    fallback = {
        "mitigates": D3FENDRelationshipType.COUNTERS,
        "mitigated-by": D3FENDRelationshipType.COUNTERS,
        "detects": D3FENDRelationshipType.MONITORS,
        "erases": D3FENDRelationshipType.DELETES,
        "configures": D3FENDRelationshipType.HARDENS,
        "manages": D3FENDRelationshipType.RESTRICTS,
        "queries": D3FENDRelationshipType.ANALYZES,
        "may-query": D3FENDRelationshipType.ANALYZES,
        "may-access": D3FENDRelationshipType.USES,
        "may-contain": D3FENDRelationshipType.ISOLATES,
        "creates": D3FENDRelationshipType.PRODUCES,
        "use-limits": D3FENDRelationshipType.RESTRICTS,
    }

    return fallback.get(normalized)


async def sync_d3fend_data(
    session: AsyncSession,
    generate_embeddings: bool = True,
    verbose: bool = False,
) -> dict[str, int]:
    """Sync D3FEND data to database.

    Flow:
    1. Download MISP Galaxy JSON + D3FEND ontology
    2. Parse all techniques from MISP Galaxy
    3. Extract ATT&CK mappings from ontology (MISP Galaxy has none)
    4. Extract and sync tactics
    5. Get valid ATT&CK technique IDs for FK validation
    6. Sync techniques with embeddings
    7. Sync ATT&CK mappings (skip invalid FKs)

    Args:
        session: AsyncSession for database operations
        generate_embeddings: Whether to generate semantic embeddings
        verbose: Enable verbose logging

    Returns:
        Dictionary with counts: tactics, techniques, attack_mappings, skipped_mappings,
        failed_embeddings
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    start_time = datetime.utcnow()
    stats: dict[str, int] = {}

    try:
        # Step 1: Download D3FEND data from both sources
        logger.info("Starting D3FEND data sync")
        data = await download_d3fend_data()

        # Download ontology for ATT&CK mappings
        try:
            ontology_data = await download_d3fend_ontology()
        except Exception as e:
            logger.warning(f"Failed to download D3FEND ontology, continuing without ATT&CK mappings: {e}")
            ontology_data = None

        # Step 2: Parse all techniques from MISP Galaxy
        values = data.get("values", [])
        logger.info(f"Parsing {len(values)} D3FEND entries")

        parsed_techniques: list[dict[str, Any]] = []
        for entry in values:
            parsed = parse_technique(entry)
            if parsed and parsed.get("technique_id"):
                parsed_techniques.append(parsed)
            else:
                # Log skipped techniques at DEBUG level
                entry_value = entry.get("value", "unknown")
                if not parsed:
                    logger.debug(f"Skipping entry '{entry_value}': parse failed")
                else:
                    logger.debug(
                        f"Skipping entry '{entry_value}': missing technique_id"
                    )

        logger.info(f"Parsed {len(parsed_techniques)} techniques")

        # Step 3: Extract ATT&CK mappings from ontology
        ontology_mappings: list[dict[str, str]] = []
        if ontology_data:
            ontology_mappings = extract_ontology_attack_mappings(ontology_data)
            logger.info(f"Extracted {len(ontology_mappings)} ATT&CK mappings from ontology")

        # Step 4: Extract and sync tactics
        tactics_data = extract_tactics(parsed_techniques)
        logger.info(f"Extracted {len(tactics_data)} unique tactics")

        # Sync tactics using upsert
        now = datetime.utcnow()
        for tactic_data in tactics_data:
            stmt = insert(D3FENDTactic).values(
                tactic_id=tactic_data["tactic_id"],
                name=tactic_data["name"],
                description=tactic_data["description"],
                display_order=tactic_data["display_order"],
                data_last_updated=now,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["tactic_id"],
                set_={
                    "name": stmt.excluded.name,
                    "description": stmt.excluded.description,
                    "display_order": stmt.excluded.display_order,
                    "data_last_updated": stmt.excluded.data_last_updated,
                },
            )
            await session.execute(stmt)

        logger.info(f"Synced {len(tactics_data)} tactics")

        # Step 5: Get valid ATT&CK technique IDs for FK validation
        result = await session.execute(
            select(AttackTechnique.technique_id)
        )
        valid_attack_ids = set(result.scalars().all())
        logger.info(f"Found {len(valid_attack_ids)} valid ATT&CK technique IDs")

        # Also get valid D3FEND technique IDs (from parsed data)
        valid_d3fend_ids = {t["technique_id"] for t in parsed_techniques}

        # Step 6: Sync techniques with optional embeddings
        embedding_model = "text-embedding-3-small"
        techniques_count = 0
        failed_embeddings = 0

        for tech_data in parsed_techniques:
            technique_id = tech_data["technique_id"]
            name = tech_data.get("name", "")
            description = tech_data.get("description", "")

            # Generate embedding if requested
            embedding = None
            embedding_generated_at = None
            if generate_embeddings and name and description:
                try:
                    embedding_text = f"{name}: {description}"[:8000]
                    embedding = await generate_embedding(embedding_text)
                    embedding_generated_at = now
                    if verbose:
                        logger.debug(f"Generated embedding for {technique_id}")
                except Exception as e:
                    logger.warning(f"Failed to generate embedding for {technique_id}: {e}")
                    failed_embeddings += 1

            # Prepare technique data
            stmt = insert(D3FENDTechnique).values(
                technique_id=technique_id,
                name=name,
                description=description or "",
                tactic_id=tech_data.get("tactic_id"),
                synonyms=tech_data.get("synonyms"),
                references=tech_data.get("references"),
                kb_article_url=tech_data.get("kb_article_url"),
                embedding=embedding,
                embedding_model=embedding_model if embedding else None,
                embedding_generated_at=embedding_generated_at,
                data_last_updated=now,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["technique_id"],
                set_={
                    "name": stmt.excluded.name,
                    "description": stmt.excluded.description,
                    "tactic_id": stmt.excluded.tactic_id,
                    "synonyms": stmt.excluded.synonyms,
                    "references": stmt.excluded.references,
                    "kb_article_url": stmt.excluded.kb_article_url,
                    "embedding": stmt.excluded.embedding,
                    "embedding_model": stmt.excluded.embedding_model,
                    "embedding_generated_at": stmt.excluded.embedding_generated_at,
                    "data_last_updated": stmt.excluded.data_last_updated,
                },
            )
            await session.execute(stmt)
            techniques_count += 1

        logger.info(f"Synced {techniques_count} techniques")

        # Step 7: Sync ATT&CK mappings from MISP Galaxy + ontology
        attack_mappings_count = 0
        skipped_mappings_count = 0

        # Collect all mappings: MISP Galaxy (usually empty) + ontology
        all_mappings: list[dict[str, str]] = []

        # MISP Galaxy mappings (per-technique)
        for tech_data in parsed_techniques:
            technique_id = tech_data["technique_id"]
            for mapping in tech_data.get("attack_mappings", []):
                all_mappings.append({
                    "d3fend_technique_id": technique_id,
                    "attack_technique_id": mapping.get("attack_technique_id", ""),
                    "relationship_type": mapping.get("relationship_type", ""),
                })

        # Ontology mappings
        all_mappings.extend(ontology_mappings)

        logger.info(f"Processing {len(all_mappings)} total ATT&CK mappings")

        for mapping in all_mappings:
            d3fend_technique_id = mapping["d3fend_technique_id"]
            attack_technique_id = mapping["attack_technique_id"]
            relationship_type_str = mapping.get("relationship_type", "")

            # Validate D3FEND FK
            if d3fend_technique_id not in valid_d3fend_ids:
                if verbose:
                    logger.debug(
                        f"Skipping mapping {d3fend_technique_id} -> {attack_technique_id} "
                        f"(D3FEND technique not in MISP Galaxy)"
                    )
                skipped_mappings_count += 1
                continue

            # Validate ATT&CK FK
            if attack_technique_id not in valid_attack_ids:
                if verbose:
                    logger.debug(
                        f"Skipping mapping {d3fend_technique_id} -> {attack_technique_id} "
                        f"(ATT&CK technique not found)"
                    )
                skipped_mappings_count += 1
                continue

            # Map relationship type
            relationship_type = _map_relationship_type(relationship_type_str)
            if not relationship_type:
                if verbose:
                    logger.debug(
                        f"Unknown relationship type '{relationship_type_str}' for "
                        f"{d3fend_technique_id} -> {attack_technique_id}, using RELATED_TO"
                    )
                relationship_type = D3FENDRelationshipType.RELATED_TO

            # Insert mapping using upsert
            # Use .value explicitly — asyncpg sends enum .name (uppercase)
            # instead of .value (lowercase) for native PostgreSQL enums
            stmt = insert(D3FENDTechniqueAttackMapping).values(
                d3fend_technique_id=d3fend_technique_id,
                attack_technique_id=attack_technique_id,
                relationship_type=relationship_type.value,
            )
            stmt = stmt.on_conflict_do_nothing(
                constraint="uq_d3fend_attack_mapping"
            )
            await session.execute(stmt)
            attack_mappings_count += 1

        logger.info(
            f"Synced {attack_mappings_count} ATT&CK mappings, "
            f"skipped {skipped_mappings_count}"
        )

        # Commit all changes
        await session.commit()

        stats = {
            "tactics": len(tactics_data),
            "techniques": techniques_count,
            "attack_mappings": attack_mappings_count,
            "skipped_mappings": skipped_mappings_count,
            "failed_embeddings": failed_embeddings,
        }

        # Update sync metadata with success
        sync_metadata = SyncMetadata(
            source="d3fend",
            last_sync_time=datetime.utcnow(),
            last_sync_status="success",
            records_synced=stats["tactics"] + stats["techniques"] + stats["attack_mappings"],
            sync_duration_seconds=int(
                (datetime.utcnow() - start_time).total_seconds()
            ),
        )
        await session.merge(sync_metadata)
        await session.commit()

        logger.info(f"D3FEND sync complete: {stats}")

    except Exception as e:
        error_message = str(e)
        logger.error(f"D3FEND sync failed: {error_message}", exc_info=True)

        # Update sync metadata with failure
        try:
            sync_metadata = SyncMetadata(
                source="d3fend",
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


@celery_app.task(bind=True, max_retries=2)
def sync_d3fend(self):
    """Celery task: Sync MITRE D3FEND defensive countermeasures."""

    async def _run():
        async with get_task_session() as session:
            return await sync_d3fend_data(session, generate_embeddings=False)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        slogger.exception("D3FEND sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2**self.request.retries))
