"""Sync task for D3FEND defensive countermeasures data.

Downloads D3FEND data from MISP Galaxy, parses it, validates ATT&CK FKs,
and stores in database with optional embeddings.
"""

import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.ingest.d3fend_parser import parse_technique
from cve_mcp.models.attack import AttackTechnique
from cve_mcp.models.d3fend import (
    D3FENDRelationshipType,
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDTechniqueAttackMapping,
)
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.services.embeddings import generate_embedding

logger = logging.getLogger(__name__)

D3FEND_DATA_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-d3fend.json"

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

    Args:
        relationship_str: Relationship type string from parser

    Returns:
        D3FENDRelationshipType enum value or None if unknown
    """
    if not relationship_str:
        return None

    # Normalize and map
    mapping = {
        "counters": D3FENDRelationshipType.COUNTERS,
        "enables": D3FENDRelationshipType.ENABLES,
        "related-to": D3FENDRelationshipType.RELATED_TO,
        "produces": D3FENDRelationshipType.PRODUCES,
        "uses": D3FENDRelationshipType.USES,
    }

    return mapping.get(relationship_str.lower())


async def sync_d3fend_data(
    session: AsyncSession,
    generate_embeddings: bool = True,
    verbose: bool = False,
) -> dict[str, int]:
    """Sync D3FEND data to database.

    Flow:
    1. Download MISP Galaxy JSON
    2. Parse all techniques
    3. Extract and sync tactics
    4. Get valid ATT&CK technique IDs for FK validation
    5. Sync techniques with embeddings
    6. Sync ATT&CK mappings (skip invalid FKs)

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

    start_time = datetime.now(UTC)
    stats: dict[str, int] = {}

    try:
        # Step 1: Download D3FEND data
        logger.info("Starting D3FEND data sync")
        data = await download_d3fend_data()

        # Step 2: Parse all techniques
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

        # Step 3: Extract and sync tactics
        tactics_data = extract_tactics(parsed_techniques)
        logger.info(f"Extracted {len(tactics_data)} unique tactics")

        # Sync tactics using upsert
        now = datetime.now(UTC)
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

        # Step 4: Get valid ATT&CK technique IDs for FK validation
        result = await session.execute(
            select(AttackTechnique.technique_id)
        )
        valid_attack_ids = set(result.scalars().all())
        logger.info(f"Found {len(valid_attack_ids)} valid ATT&CK technique IDs")

        # Step 5: Sync techniques with optional embeddings
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

        # Step 6: Sync ATT&CK mappings (skip invalid FKs)
        attack_mappings_count = 0
        skipped_mappings_count = 0

        for tech_data in parsed_techniques:
            technique_id = tech_data["technique_id"]
            attack_mappings = tech_data.get("attack_mappings", [])

            for mapping in attack_mappings:
                attack_technique_id = mapping.get("attack_technique_id")
                relationship_type_str = mapping.get("relationship_type")

                # Validate FK
                if attack_technique_id not in valid_attack_ids:
                    if verbose:
                        logger.debug(
                            f"Skipping mapping {technique_id} -> {attack_technique_id} "
                            f"(ATT&CK technique not found)"
                        )
                    skipped_mappings_count += 1
                    continue

                # Map relationship type
                relationship_type = _map_relationship_type(relationship_type_str)
                if not relationship_type:
                    logger.warning(
                        f"Unknown relationship type '{relationship_type_str}' for "
                        f"{technique_id} -> {attack_technique_id}"
                    )
                    skipped_mappings_count += 1
                    continue

                # Insert mapping using upsert
                stmt = insert(D3FENDTechniqueAttackMapping).values(
                    d3fend_technique_id=technique_id,
                    attack_technique_id=attack_technique_id,
                    relationship_type=relationship_type,
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
            last_sync_time=datetime.now(UTC),
            last_sync_status="success",
            records_synced=stats["tactics"] + stats["techniques"],
            sync_duration_seconds=int(
                (datetime.now(UTC) - start_time).total_seconds()
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
                last_sync_time=datetime.now(UTC),
                last_sync_status="failed",
                records_synced=0,
                error_message=error_message,
                sync_duration_seconds=int(
                    (datetime.now(UTC) - start_time).total_seconds()
                ),
            )
            await session.merge(sync_metadata)
            await session.commit()
        except Exception as metadata_error:
            logger.error(f"Failed to update sync metadata: {metadata_error}")

        raise

    return stats
