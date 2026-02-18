"""CWE query service with traditional and semantic search.

Provides 6 async query functions for MITRE CWE weakness data:
- Traditional search: keyword/filter-based queries with hierarchical support
- Semantic search: AI-powered similarity matching using pgvector
- Hierarchy navigation: parent/child relationship traversal
- Cross-framework: CAPEC to CWE mapping
"""

from typing import Any

from sqlalchemy import and_, case, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.cwe import CWEExternalMapping, CWEWeakness
from cve_mcp.services.embeddings import generate_embedding
from cve_mcp.utils import escape_like


def _weakness_to_dict(weakness: CWEWeakness, include_full: bool = False) -> dict[str, Any]:
    """Convert CWEWeakness to summary dict with badge_url.

    Args:
        weakness: CWEWeakness model instance
        include_full: If True, include all fields; if False, return summary only

    Returns:
        Dictionary representation of the weakness
    """
    if include_full:
        return {
            "cwe_id": weakness.cwe_id,
            "weakness_id": weakness.weakness_id,
            "name": weakness.name,
            "description": weakness.description,
            "extended_description": weakness.extended_description,
            "abstraction": weakness.abstraction,
            "status": weakness.status,
            "common_consequences": weakness.common_consequences,
            "potential_mitigations": weakness.potential_mitigations,
            "detection_methods": weakness.detection_methods,
            "likelihood_of_exploit": weakness.likelihood_of_exploit,
            "parent_of": weakness.parent_of,
            "child_of": weakness.child_of,
            "peer_of": weakness.peer_of,
            "can_precede": weakness.can_precede,
            "can_follow": weakness.can_follow,
            "related_attack_patterns": weakness.related_attack_patterns,
            "created": weakness.created.isoformat() if weakness.created else None,
            "modified": weakness.modified.isoformat() if weakness.modified else None,
            "cwe_version": weakness.cwe_version,
            "deprecated": weakness.deprecated,
            "badge_url": weakness.badge_url,
            "embedding_generated": weakness.embedding is not None,
        }

    description = weakness.description or ""
    return {
        "cwe_id": weakness.cwe_id,
        "weakness_id": weakness.weakness_id,
        "name": weakness.name,
        "description": (
            description[:200] + "..."
            if len(description) > 200
            else description
        ),
        "abstraction": weakness.abstraction,
        "status": weakness.status,
        "likelihood_of_exploit": weakness.likelihood_of_exploit,
        "deprecated": weakness.deprecated,
        "badge_url": weakness.badge_url,
    }


async def search_weaknesses(
    session: AsyncSession,
    query: str | None = None,
    abstraction: list[str] | None = None,
    include_children: bool = False,
    active_only: bool = True,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search CWE weaknesses using traditional full-text and filter-based search.

    Args:
        session: Database session
        query: Full-text search query (searches name and description)
        abstraction: Filter by abstraction levels (Pillar, Class, Base, Variant, Compound)
        include_children: If True, also include child weaknesses of matches
        active_only: Exclude deprecated weaknesses
        limit: Maximum results to return

    Returns:
        Tuple of (weaknesses list, total count)
    """
    # Build query
    stmt = select(CWEWeakness)

    # Apply filters
    filters = []

    if active_only:
        filters.append(CWEWeakness.deprecated.is_(False))

    if abstraction:
        filters.append(CWEWeakness.abstraction.in_(abstraction))

    _query_terms = []
    if query:
        # Split multi-word queries into individual terms and match ANY term.
        _query_terms = [t.strip() for t in query.split() if t.strip()]
        if _query_terms:
            term_filters = []
            for term in _query_terms:
                term_filters.append(CWEWeakness.name.ilike(f"%{escape_like(term)}%"))
                term_filters.append(CWEWeakness.description.ilike(f"%{escape_like(term)}%"))
            filters.append(or_(*term_filters))

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Order by relevance: count how many query terms match each row
    if _query_terms:
        relevance = sum(
            case(
                (or_(
                    CWEWeakness.name.ilike(f"%{escape_like(term)}%"),
                    CWEWeakness.description.ilike(f"%{escape_like(term)}%"),
                ), literal(1)),
                else_=literal(0),
            )
            for term in _query_terms
        )
        stmt = stmt.order_by(relevance.desc())

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    weaknesses = result.scalars().all()

    # Format results
    results = [_weakness_to_dict(w) for w in weaknesses]

    # If include_children, recursively fetch children
    if include_children and results:
        child_ids = set()
        for w in weaknesses:
            if w.parent_of:
                child_ids.update(w.parent_of)

        if child_ids:
            # Fetch children not already in results
            existing_ids = {w.cwe_id for w in weaknesses}
            new_child_ids = child_ids - existing_ids

            if new_child_ids:
                child_stmt = select(CWEWeakness).where(CWEWeakness.cwe_id.in_(new_child_ids))
                if active_only:
                    child_stmt = child_stmt.where(CWEWeakness.deprecated.is_(False))

                child_result = await session.execute(child_stmt)
                children = child_result.scalars().all()
                for child in children:
                    child_dict = _weakness_to_dict(child)
                    child_dict["is_child_match"] = True
                    results.append(child_dict)

    return results, total_count


async def find_similar_weaknesses(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    abstraction: list[str] | None = None,
    active_only: bool = True,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar CWE weaknesses using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of weakness or vulnerability
        min_similarity: Minimum similarity threshold (0-1)
        abstraction: Filter by abstraction levels
        active_only: Exclude deprecated weaknesses
        limit: Maximum results to return

    Returns:
        List of weaknesses with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [CWEWeakness.embedding.is_not(None)]

    if active_only:
        filters.append(CWEWeakness.deprecated.is_(False))

    if abstraction:
        filters.append(CWEWeakness.abstraction.in_(abstraction))

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - CWEWeakness.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            CWEWeakness,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(CWEWeakness.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for weakness, sim_score in rows:
        weakness_dict = _weakness_to_dict(weakness)
        weakness_dict["similarity_score"] = float(sim_score)
        results.append(weakness_dict)

    return results


async def get_weakness_details(
    session: AsyncSession,
    weakness_id: str,
) -> dict[str, Any] | None:
    """Get full weakness details including mitigations, consequences, external mappings.

    Args:
        session: Database session
        weakness_id: Weakness ID (e.g., "CWE-79" or "79")

    Returns:
        Complete weakness details or None if not found
    """
    # Normalize ID
    if not weakness_id.upper().startswith("CWE-"):
        weakness_id = f"CWE-{weakness_id}"
    else:
        weakness_id = weakness_id.upper()

    stmt = select(CWEWeakness).where(CWEWeakness.cwe_id == weakness_id)
    result = await session.execute(stmt)
    weakness = result.scalar_one_or_none()

    if not weakness:
        return None

    # Get external mappings
    mapping_stmt = select(CWEExternalMapping).where(
        CWEExternalMapping.weakness_id == weakness_id
    )
    mapping_result = await session.execute(mapping_stmt)
    mappings = mapping_result.scalars().all()

    weakness_dict = _weakness_to_dict(weakness, include_full=True)
    weakness_dict["external_mappings"] = [
        {
            "source": m.external_source,
            "external_id": m.external_id,
            "mapping_type": m.mapping_type,
            "rationale": m.rationale,
        }
        for m in mappings
    ]

    return weakness_dict


async def search_by_external_mapping(
    session: AsyncSession,
    source: str,
    external_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search weaknesses by OWASP/SANS mapping.

    Args:
        session: Database session
        source: External source name (e.g., "OWASP Top Ten 2021", "SANS Top 25")
        external_id: External ID filter (e.g., "A03:2021")
        limit: Maximum results to return

    Returns:
        List of weaknesses matching the external mapping
    """
    # Build subquery to get weakness IDs from mappings
    mapping_filters = [CWEExternalMapping.external_source.ilike(f"%{escape_like(source)}%")]

    if external_id:
        mapping_filters.append(CWEExternalMapping.external_id.ilike(f"%{escape_like(external_id)}%"))

    mapping_stmt = (
        select(CWEExternalMapping.weakness_id, CWEExternalMapping)
        .where(and_(*mapping_filters))
        .limit(limit)
    )

    mapping_result = await session.execute(mapping_stmt)
    mappings = mapping_result.all()

    if not mappings:
        return []

    # Get unique weakness IDs
    weakness_ids = list({m[0] for m in mappings})

    # Fetch weaknesses
    weakness_stmt = select(CWEWeakness).where(CWEWeakness.cwe_id.in_(weakness_ids))
    weakness_result = await session.execute(weakness_stmt)
    weaknesses = {w.cwe_id: w for w in weakness_result.scalars().all()}

    # Format results with mapping info
    results = []
    for weakness_id, mapping in mappings:
        if weakness_id in weaknesses:
            weakness_dict = _weakness_to_dict(weaknesses[weakness_id])
            weakness_dict["external_mapping"] = {
                "source": mapping.external_source,
                "external_id": mapping.external_id,
                "mapping_type": mapping.mapping_type,
            }
            results.append(weakness_dict)

    return results


async def get_weakness_hierarchy(
    session: AsyncSession,
    weakness_id: str,
    direction: str = "both",
    depth: int = 3,
) -> dict[str, Any]:
    """Navigate parent/child hierarchy of a weakness.

    Args:
        session: Database session
        weakness_id: Weakness ID (e.g., "CWE-79" or "79")
        direction: Direction to traverse ("parents", "children", "both")
        depth: Maximum depth to traverse

    Returns:
        Hierarchy tree with weakness at root
    """
    # Normalize ID
    if not weakness_id.upper().startswith("CWE-"):
        weakness_id = f"CWE-{weakness_id}"
    else:
        weakness_id = weakness_id.upper()

    # Get root weakness
    stmt = select(CWEWeakness).where(CWEWeakness.cwe_id == weakness_id)
    result = await session.execute(stmt)
    weakness = result.scalar_one_or_none()

    if not weakness:
        return {"error": f"Weakness {weakness_id} not found"}

    async def fetch_related(
        cwe_ids: list[str], current_depth: int, fetch_direction: str
    ) -> list[dict[str, Any]]:
        """Recursively fetch related weaknesses."""
        if current_depth >= depth or not cwe_ids:
            return []

        stmt = select(CWEWeakness).where(CWEWeakness.cwe_id.in_(cwe_ids))
        result = await session.execute(stmt)
        related = result.scalars().all()

        items = []
        for w in related:
            item = _weakness_to_dict(w)

            # Recursively fetch next level
            if fetch_direction in ("children", "both") and w.parent_of:
                item["children"] = await fetch_related(
                    w.parent_of, current_depth + 1, "children"
                )

            if fetch_direction in ("parents", "both") and w.child_of:
                item["parents"] = await fetch_related(w.child_of, current_depth + 1, "parents")

            items.append(item)

        return items

    # Build result
    result_dict = _weakness_to_dict(weakness)

    if direction in ("children", "both") and weakness.parent_of:
        result_dict["children"] = await fetch_related(weakness.parent_of, 0, "children")

    if direction in ("parents", "both") and weakness.child_of:
        result_dict["parents"] = await fetch_related(weakness.child_of, 0, "parents")

    if weakness.peer_of:
        # Include peers at same level (not recursive)
        peer_stmt = select(CWEWeakness).where(CWEWeakness.cwe_id.in_(weakness.peer_of))
        peer_result = await session.execute(peer_stmt)
        result_dict["peers"] = [_weakness_to_dict(p) for p in peer_result.scalars().all()]

    return result_dict


async def find_weaknesses_for_capec(
    session: AsyncSession,
    pattern_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Cross-framework: find CWEs exploited by CAPEC pattern.

    Args:
        session: Database session
        pattern_id: CAPEC pattern ID (e.g., "CAPEC-66")
        limit: Maximum results to return

    Returns:
        List of weaknesses related to the CAPEC pattern
    """
    # Normalize CAPEC ID
    if not pattern_id.upper().startswith("CAPEC-"):
        pattern_id = f"CAPEC-{pattern_id}"
    else:
        pattern_id = pattern_id.upper()

    # Search for weaknesses that have this CAPEC in related_attack_patterns
    stmt = (
        select(CWEWeakness)
        .where(CWEWeakness.related_attack_patterns.contains([pattern_id]))
        .limit(limit)
    )

    result = await session.execute(stmt)
    weaknesses = result.scalars().all()

    # Format results
    results = []
    for weakness in weaknesses:
        weakness_dict = _weakness_to_dict(weakness)
        weakness_dict["related_via_capec"] = pattern_id
        results.append(weakness_dict)

    return results
