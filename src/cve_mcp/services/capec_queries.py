"""CAPEC query service with traditional and semantic search.

Provides 5 async query functions for MITRE CAPEC attack pattern data:
- Traditional search: keyword/filter-based queries for patterns and mitigations
- Semantic search: AI-powered similarity matching using pgvector
"""

from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.capec import CAPECMitigation, CAPECPattern
from cve_mcp.services.embeddings import generate_embedding
from cve_mcp.utils import escape_like


async def search_patterns(
    session: AsyncSession,
    query: str | None = None,
    abstraction: list[str] | None = None,
    likelihood: str | None = None,
    severity: str | None = None,
    related_cwe: list[str] | None = None,
    active_only: bool = True,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search CAPEC patterns using traditional full-text and filter-based search.

    Args:
        session: Database session
        query: Full-text search query (searches name and description)
        abstraction: Filter by abstraction levels (e.g., ["Meta", "Standard", "Detailed"])
        likelihood: Filter by attack likelihood (e.g., "High", "Medium", "Low")
        severity: Filter by typical severity (e.g., "High", "Medium", "Low")
        related_cwe: Filter by related CWE IDs (e.g., ["CWE-79", "CWE-89"])
        active_only: Exclude deprecated patterns
        limit: Maximum results to return

    Returns:
        Tuple of (patterns list, total count)
    """
    # Build query
    stmt = select(CAPECPattern)

    # Apply filters
    filters = []

    if active_only:
        filters.append(CAPECPattern.deprecated.is_(False))

    if abstraction:
        filters.append(CAPECPattern.abstraction.in_(abstraction))

    if likelihood:
        filters.append(CAPECPattern.attack_likelihood == likelihood)

    if severity:
        filters.append(CAPECPattern.typical_severity == severity)

    if related_cwe:
        # Array overlap operator for CWE relationships
        filters.append(CAPECPattern.related_weaknesses.overlap(related_cwe))

    if query:
        # Use tsvector full-text search with ILIKE name fallback for relevance.
        ts_query = func.plainto_tsquery("english", query)
        search_filter = or_(
            CAPECPattern.description_vector.op("@@")(ts_query),
            CAPECPattern.name.ilike(f"%{escape_like(query)}%"),
        )
        terms = [t.strip() for t in query.split() if t.strip()]
        if terms:
            for term in terms:
                search_filter = or_(search_filter, CAPECPattern.name.ilike(f"%{escape_like(term)}%"))
        filters.append(search_filter)

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Order by relevance when query is provided
    if query:
        ts_query = func.plainto_tsquery("english", query)
        stmt = stmt.order_by(
            func.ts_rank(CAPECPattern.description_vector, ts_query).desc()
        )

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    patterns = result.scalars().all()

    # Format results
    results = []
    for pattern in patterns:
        description = pattern.description or ""
        results.append(
            {
                "pattern_id": pattern.pattern_id,
                "capec_id": pattern.capec_id,
                "name": pattern.name,
                "description": (
                    description[:200] + "..."
                    if len(description) > 200
                    else description
                ),
                "abstraction": pattern.abstraction,
                "attack_likelihood": pattern.attack_likelihood,
                "typical_severity": pattern.typical_severity,
                "related_weaknesses": pattern.related_weaknesses,
                "deprecated": pattern.deprecated,
                "badge_url": pattern.badge_url,
            }
        )

    return results, total_count


async def get_pattern_details(
    session: AsyncSession,
    pattern_id: str,
) -> dict[str, Any] | None:
    """Get complete details for a specific CAPEC pattern.

    Args:
        session: Database session
        pattern_id: Pattern ID (e.g., "CAPEC-66")

    Returns:
        Complete pattern details or None if not found
    """
    stmt = select(CAPECPattern).where(CAPECPattern.pattern_id == pattern_id)
    result = await session.execute(stmt)
    pattern = result.scalar_one_or_none()

    if not pattern:
        return None

    return {
        "pattern_id": pattern.pattern_id,
        "capec_id": pattern.capec_id,
        "stix_id": pattern.stix_id,
        "name": pattern.name,
        "description": pattern.description,  # Full description
        "abstraction": pattern.abstraction,
        "status": pattern.status,
        "attack_likelihood": pattern.attack_likelihood,
        "typical_severity": pattern.typical_severity,
        "prerequisites": pattern.prerequisites,
        "skills_required": pattern.skills_required,
        "resources_required": pattern.resources_required,
        "execution_flow": pattern.execution_flow,
        "consequences": pattern.consequences,
        "mitigations": pattern.mitigations,
        "examples": pattern.examples,
        "references": pattern.references,
        "parent_of": pattern.parent_of,
        "child_of": pattern.child_of,
        "can_precede": pattern.can_precede,
        "can_follow": pattern.can_follow,
        "peer_of": pattern.peer_of,
        "related_attack_patterns": pattern.related_attack_patterns,
        "related_weaknesses": pattern.related_weaknesses,
        "version": pattern.version,
        "created": pattern.created.isoformat() if pattern.created else None,
        "modified": pattern.modified.isoformat() if pattern.modified else None,
        "deprecated": pattern.deprecated,
        "badge_url": pattern.badge_url,
        "embedding_generated": pattern.embedding is not None,
    }


async def find_similar_patterns(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    abstraction: list[str] | None = None,
    likelihood: str | None = None,
    severity: str | None = None,
    active_only: bool = True,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar CAPEC patterns using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of attack scenario
        min_similarity: Minimum similarity threshold (0-1)
        abstraction: Filter by abstraction levels
        likelihood: Filter by attack likelihood
        severity: Filter by typical severity
        active_only: Exclude deprecated patterns
        limit: Maximum results to return

    Returns:
        List of patterns with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [CAPECPattern.embedding.is_not(None)]

    if active_only:
        filters.append(CAPECPattern.deprecated.is_(False))

    if abstraction:
        filters.append(CAPECPattern.abstraction.in_(abstraction))

    if likelihood:
        filters.append(CAPECPattern.attack_likelihood == likelihood)

    if severity:
        filters.append(CAPECPattern.typical_severity == severity)

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - CAPECPattern.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            CAPECPattern,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(CAPECPattern.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for pattern, sim_score in rows:
        description = pattern.description or ""
        results.append(
            {
                "pattern_id": pattern.pattern_id,
                "capec_id": pattern.capec_id,
                "name": pattern.name,
                "description": (
                    description[:200] + "..."
                    if len(description) > 200
                    else description
                ),
                "abstraction": pattern.abstraction,
                "attack_likelihood": pattern.attack_likelihood,
                "typical_severity": pattern.typical_severity,
                "similarity_score": float(sim_score),
                "badge_url": pattern.badge_url,
            }
        )

    return results


async def search_mitigations(
    session: AsyncSession,
    query: str | None = None,
    effectiveness: str | None = None,
    patterns: list[str] | None = None,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search CAPEC mitigations using traditional search.

    Args:
        session: Database session
        query: Full-text search query (searches name and description)
        effectiveness: Filter by effectiveness level (e.g., "High", "Medium", "Low")
        patterns: Filter by patterns mitigated (e.g., ["CAPEC-66"])
        limit: Maximum results to return

    Returns:
        Tuple of (mitigations list, total count)
    """
    # Build query
    stmt = select(CAPECMitigation)

    # Apply filters
    filters = []

    if effectiveness:
        filters.append(CAPECMitigation.effectiveness == effectiveness)

    if patterns:
        # Array overlap operator
        filters.append(CAPECMitigation.mitigates_patterns.overlap(patterns))

    if query:
        # Split multi-word queries into individual terms and match ANY term.
        terms = [t.strip() for t in query.split() if t.strip()]
        if terms:
            term_filters = []
            for term in terms:
                term_filters.append(CAPECMitigation.name.ilike(f"%{escape_like(term)}%"))
                term_filters.append(CAPECMitigation.description.ilike(f"%{escape_like(term)}%"))
            filters.append(or_(*term_filters))

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    mitigations = result.scalars().all()

    # Format results
    results = []
    for mit in mitigations:
        description = mit.description or ""
        results.append(
            {
                "mitigation_id": mit.mitigation_id,
                "name": mit.name,
                "description": (
                    description[:200] + "..." if len(description) > 200 else description
                ),
                "effectiveness": mit.effectiveness,
                "mitigates_patterns": mit.mitigates_patterns,
                "implementation_phases": mit.implementation_phases,
            }
        )

    return results, total_count


async def find_similar_mitigations(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    effectiveness: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar CAPEC mitigations using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of mitigation need or security control
        min_similarity: Minimum similarity threshold (0-1)
        effectiveness: Filter by effectiveness level
        limit: Maximum results to return

    Returns:
        List of mitigations with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [CAPECMitigation.embedding.is_not(None)]

    if effectiveness:
        filters.append(CAPECMitigation.effectiveness == effectiveness)

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - CAPECMitigation.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            CAPECMitigation,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(CAPECMitigation.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for mit, sim_score in rows:
        description = mit.description or ""
        results.append(
            {
                "mitigation_id": mit.mitigation_id,
                "name": mit.name,
                "description": (
                    description[:200] + "..." if len(description) > 200 else description
                ),
                "effectiveness": mit.effectiveness,
                "mitigates_patterns": mit.mitigates_patterns,
                "implementation_phases": mit.implementation_phases,
                "similarity_score": float(sim_score),
            }
        )

    return results
