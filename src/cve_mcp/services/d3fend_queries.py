"""Query services for D3FEND defensive countermeasures.

Provides 5 async query functions for MITRE D3FEND defensive technique data:
- Traditional search: keyword/filter-based queries for defensive techniques
- Semantic search: AI-powered similarity matching using pgvector
- Cross-framework: D3FEND to ATT&CK mapping for defense-to-offense correlation
- Coverage analysis: ATT&CK coverage assessment for D3FEND techniques
"""

from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from cve_mcp.models.attack import AttackTechnique
from cve_mcp.models.d3fend import (
    D3FENDRelationshipType,
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDTechniqueAttackMapping,
)
from cve_mcp.services.embeddings import generate_embedding


def _technique_to_dict(technique: D3FENDTechnique, include_full: bool = False) -> dict[str, Any]:
    """Convert D3FENDTechnique to summary or full dict.

    Args:
        technique: D3FENDTechnique model instance
        include_full: If True, include all fields; if False, return summary only

    Returns:
        Dictionary representation of the technique
    """
    if include_full:
        return {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "description": technique.description,
            "tactic_id": technique.tactic_id,
            "tactic_name": technique.tactic.name if technique.tactic else None,
            "parent_id": technique.parent_id,
            "synonyms": technique.synonyms,
            "references": technique.references,
            "kb_article_url": technique.kb_article_url,
            "d3fend_version": technique.d3fend_version,
            "deprecated": technique.deprecated,
            "created": technique.created.isoformat() if technique.created else None,
            "modified": technique.modified.isoformat() if technique.modified else None,
            "badge_url": technique.badge_url,
            "embedding_generated": technique.embedding is not None,
        }

    # Summary format
    description = technique.description or ""
    if len(description) > 200:
        description = description[:200] + "..."

    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "description": description,
        "tactic_id": technique.tactic_id,
        "deprecated": technique.deprecated,
        "badge_url": technique.badge_url,
    }


async def search_defenses(
    session: AsyncSession,
    query: str | None = None,
    tactic: list[str] | None = None,
    include_children: bool = False,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search defensive techniques by keyword.

    Args:
        session: Database session
        query: Full-text search query (searches name, description, synonyms)
        tactic: Filter by tactic names (e.g., ["Harden", "Detect"])
        include_children: If True, also include child techniques of matches
        limit: Maximum results to return

    Returns:
        Tuple of (defensive technique list, total count)
    """
    # Build base query
    stmt = select(D3FENDTechnique).options(selectinload(D3FENDTechnique.children))

    # Apply filters
    filters = []

    # Exclude deprecated by default
    filters.append(D3FENDTechnique.deprecated.is_(False))

    # Keyword search on name, description, and synonyms
    if query:
        search_filter = or_(
            D3FENDTechnique.name.ilike(f"%{query}%"),
            D3FENDTechnique.description.ilike(f"%{query}%"),
            func.coalesce(
                func.array_to_string(D3FENDTechnique.synonyms, ' ', ''), ''
            ).ilike(f"%{query}%"),
        )
        filters.append(search_filter)

    # Tactic filter (join with tactics table)
    if tactic:
        # Join with tactics to filter by name
        stmt = stmt.join(D3FENDTactic, D3FENDTechnique.tactic_id == D3FENDTactic.tactic_id)
        filters.append(D3FENDTactic.name.in_(tactic))

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count before applying limit
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    techniques = result.scalars().all()

    # Format results
    results = [_technique_to_dict(t) for t in techniques]

    # If include_children, add child techniques
    if include_children and techniques:
        existing_ids = {t.technique_id for t in techniques}
        child_ids = set()

        for tech in techniques:
            for child in tech.children:
                if child.technique_id not in existing_ids:
                    child_ids.add(child.technique_id)

        if child_ids:
            child_stmt = (
                select(D3FENDTechnique)
                .where(D3FENDTechnique.technique_id.in_(child_ids))
                .where(D3FENDTechnique.deprecated.is_(False))
            )
            child_result = await session.execute(child_stmt)
            children = child_result.scalars().all()

            for child in children:
                child_dict = _technique_to_dict(child)
                child_dict["is_child_match"] = True
                results.append(child_dict)

    return results, total_count


async def find_similar_defenses(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    tactic: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Semantic search for defensive techniques using vector embeddings.

    Args:
        session: Database session
        description: Natural language description to find similar defenses
        min_similarity: Minimum similarity threshold (0-1)
        tactic: Filter by tactic names
        limit: Maximum results to return

    Returns:
        List of techniques with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [
        D3FENDTechnique.embedding.is_not(None),
        D3FENDTechnique.deprecated.is_(False),
    ]

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - D3FENDTechnique.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    # Tactic filter
    if tactic:
        stmt = select(
            D3FENDTechnique,
            similarity.label("similarity_score"),
        ).join(D3FENDTactic, D3FENDTechnique.tactic_id == D3FENDTactic.tactic_id)
        filters.append(D3FENDTactic.name.in_(tactic))
    else:
        stmt = select(
            D3FENDTechnique,
            similarity.label("similarity_score"),
        )

    stmt = (
        stmt.where(and_(*filters))
        .order_by(D3FENDTechnique.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for technique, sim_score in rows:
        technique_dict = _technique_to_dict(technique)
        technique_dict["similarity_score"] = float(sim_score)
        results.append(technique_dict)

    return results


async def get_defense_details(
    session: AsyncSession,
    technique_id: str,
) -> dict[str, Any] | None:
    """Get full technique details including ATT&CK mappings.

    Args:
        session: Database session
        technique_id: D3FEND technique ID (e.g., "D3-AL")

    Returns:
        Complete technique details with ATT&CK mappings, or None if not found
    """
    # Normalize ID format
    technique_id = technique_id.upper()
    if not technique_id.startswith("D3-"):
        technique_id = f"D3-{technique_id}"

    # Fetch technique with eager loading of relationships
    stmt = (
        select(D3FENDTechnique)
        .options(
            selectinload(D3FENDTechnique.tactic),
            selectinload(D3FENDTechnique.attack_mappings),
        )
        .where(D3FENDTechnique.technique_id == technique_id)
    )

    result = await session.execute(stmt)
    technique = result.scalar_one_or_none()

    if not technique:
        return None

    # Build full response
    technique_dict = _technique_to_dict(technique, include_full=True)

    # Add ATT&CK mappings with details
    attack_mappings = []
    for mapping in technique.attack_mappings:
        attack_mappings.append(
            {
                "attack_technique_id": mapping.attack_technique_id,
                "relationship_type": mapping.relationship_type.value,
            }
        )

    technique_dict["attack_mappings"] = attack_mappings
    technique_dict["attack_mappings_count"] = len(attack_mappings)

    return technique_dict


async def get_defenses_for_attack(
    session: AsyncSession,
    attack_technique_id: str,
    include_subtechniques: bool = True,
    relationship_type: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Find D3FEND countermeasures for an ATT&CK technique.

    This is the KEY FEATURE that answers: "How do I defend against this attack?"

    Args:
        session: Database session
        attack_technique_id: ATT&CK technique ID (e.g., "T1059" or "T1059.001")
        include_subtechniques: If True, also find defenses for subtechniques
            (e.g., T1059.001, T1059.002, etc. when given T1059)
        relationship_type: Filter by relationship type(s) (e.g., ["counters"])

    Returns:
        List of defensive techniques with their relationships to the attack
    """
    # Normalize ATT&CK technique ID
    attack_technique_id = attack_technique_id.upper()
    if not attack_technique_id.startswith("T"):
        attack_technique_id = f"T{attack_technique_id}"

    # Build list of attack technique IDs to search
    attack_ids = [attack_technique_id]

    if include_subtechniques and "." not in attack_technique_id:
        # If main technique (not subtechnique), also search for subtechniques
        # Query for subtechniques like T1059.001, T1059.002, etc.
        subtechnique_stmt = select(AttackTechnique.technique_id).where(
            AttackTechnique.parent_technique_id == attack_technique_id
        )
        subtechnique_result = await session.execute(subtechnique_stmt)
        subtechnique_ids = [row[0] for row in subtechnique_result.all()]
        attack_ids.extend(subtechnique_ids)

    # Build query for mappings
    stmt = (
        select(D3FENDTechniqueAttackMapping)
        .options(selectinload(D3FENDTechniqueAttackMapping.d3fend_technique))
        .where(D3FENDTechniqueAttackMapping.attack_technique_id.in_(attack_ids))
    )

    # Filter by relationship type
    if relationship_type:
        # Convert string values to enum
        rel_types = []
        for rt in relationship_type:
            try:
                rel_types.append(D3FENDRelationshipType(rt.lower()))
            except ValueError:
                pass  # Skip invalid relationship types

        if rel_types:
            stmt = stmt.where(D3FENDTechniqueAttackMapping.relationship_type.in_(rel_types))

    result = await session.execute(stmt)
    mappings = result.scalars().all()

    # Build results grouped by defense technique
    seen_defenses = {}
    for mapping in mappings:
        technique = mapping.d3fend_technique
        if technique.deprecated:
            continue

        tech_id = technique.technique_id
        if tech_id not in seen_defenses:
            seen_defenses[tech_id] = {
                **_technique_to_dict(technique),
                "defends_against": [],
            }

        seen_defenses[tech_id]["defends_against"].append(
            {
                "attack_technique_id": mapping.attack_technique_id,
                "relationship_type": mapping.relationship_type.value,
            }
        )

    return list(seen_defenses.values())


async def get_attack_coverage(
    session: AsyncSession,
    technique_ids: list[str],
    show_gaps: bool = True,
) -> dict[str, Any]:
    """Analyze ATT&CK coverage for given D3FEND techniques.

    This helps assess defensive coverage and identify gaps.

    Args:
        session: Database session
        technique_ids: List of D3FEND technique IDs to analyze
        show_gaps: If True, include list of uncovered ATT&CK techniques

    Returns:
        Coverage analysis including:
        - covered_techniques: list of ATT&CK IDs covered
        - coverage_details: dict mapping ATT&CK ID to D3FEND defenders
        - total_covered: count of covered techniques
        - gaps: uncovered ATT&CK techniques (if show_gaps)
        - total_gaps: count of uncovered techniques
        - coverage_percentage: percentage of known ATT&CK techniques covered
    """
    if not technique_ids:
        return {
            "covered_techniques": [],
            "coverage_details": {},
            "total_covered": 0,
            "gaps": [],
            "total_gaps": 0,
            "coverage_percentage": 0.0,
        }

    # Normalize technique IDs
    normalized_ids = []
    for tid in technique_ids:
        tid = tid.upper()
        if not tid.startswith("D3-"):
            tid = f"D3-{tid}"
        normalized_ids.append(tid)

    # Fetch techniques with their attack mappings
    stmt = (
        select(D3FENDTechnique)
        .options(selectinload(D3FENDTechnique.attack_mappings))
        .where(D3FENDTechnique.technique_id.in_(normalized_ids))
    )

    result = await session.execute(stmt)
    techniques = result.scalars().all()

    # Build coverage map
    coverage_details: dict[str, list[dict[str, str]]] = {}

    for technique in techniques:
        for mapping in technique.attack_mappings:
            attack_id = mapping.attack_technique_id

            if attack_id not in coverage_details:
                coverage_details[attack_id] = []

            coverage_details[attack_id].append(
                {
                    "d3fend_technique_id": technique.technique_id,
                    "d3fend_technique_name": technique.name,
                    "relationship_type": mapping.relationship_type.value,
                }
            )

    covered_techniques = list(coverage_details.keys())
    total_covered = len(covered_techniques)

    # Calculate gaps if requested
    gaps = []
    total_gaps = 0

    if show_gaps:
        # Get all known ATT&CK techniques
        attack_stmt = select(AttackTechnique.technique_id).where(
            and_(
                AttackTechnique.deprecated.is_(False),
                AttackTechnique.revoked.is_(False),
            )
        )
        attack_result = await session.execute(attack_stmt)
        all_attack_ids = {row[0] for row in attack_result.all()}

        # Find gaps
        gaps = sorted(all_attack_ids - set(covered_techniques))
        total_gaps = len(gaps)

    # Calculate coverage percentage
    total_attack_techniques = total_covered + total_gaps if show_gaps else total_covered
    coverage_percentage = (
        (total_covered / total_attack_techniques * 100) if total_attack_techniques > 0 else 0.0
    )

    return {
        "covered_techniques": sorted(covered_techniques),
        "coverage_details": coverage_details,
        "total_covered": total_covered,
        "gaps": gaps,
        "total_gaps": total_gaps,
        "coverage_percentage": round(coverage_percentage, 2),
    }
