"""ATT&CK query service with traditional and semantic search.

Provides 8 async query functions for MITRE ATT&CK data:
- Traditional search: keyword/filter-based queries
- Semantic search: AI-powered similarity matching using pgvector
"""

from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.attack import AttackGroup, AttackTechnique
from cve_mcp.services.embeddings import generate_embedding


async def search_techniques(
    session: AsyncSession,
    query: str | None = None,
    tactics: list[str] | None = None,
    platforms: list[str] | None = None,
    include_subtechniques: bool = True,
    active_only: bool = True,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search techniques using traditional full-text and filter-based search.

    Args:
        session: Database session
        query: Full-text search query (searches name and description)
        tactics: Filter by tactics (e.g., ["initial-access", "execution"])
        platforms: Filter by platforms (e.g., ["windows", "linux"])
        include_subtechniques: Include subtechniques in results
        active_only: Exclude deprecated/revoked techniques
        limit: Maximum results to return

    Returns:
        Tuple of (techniques list, total count)
    """
    # Build query
    stmt = select(AttackTechnique)

    # Apply filters
    filters = []

    if active_only:
        filters.append(AttackTechnique.deprecated.is_(False))
        filters.append(AttackTechnique.revoked.is_(False))

    if not include_subtechniques:
        filters.append(AttackTechnique.is_subtechnique.is_(False))

    if tactics:
        # Array overlap operator
        filters.append(AttackTechnique.tactics.overlap(tactics))

    if platforms:
        # Array overlap operator
        filters.append(AttackTechnique.platforms.overlap(platforms))

    if query:
        # Full-text search on name and description using ILIKE
        search_filter = or_(
            AttackTechnique.name.ilike(f"%{query}%"),
            AttackTechnique.description.ilike(f"%{query}%"),
        )
        filters.append(search_filter)

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    techniques = result.scalars().all()

    # Format results
    results = []
    for tech in techniques:
        results.append({
            "technique_id": tech.technique_id,
            "name": tech.name,
            "description": tech.description[:200] + "..." if len(tech.description) > 200 else tech.description,
            "tactics": tech.tactics,
            "platforms": tech.platforms,
            "is_subtechnique": tech.is_subtechnique,
            "deprecated": tech.deprecated,
            "revoked": tech.revoked,
            "badge_url": tech.badge_url,
        })

    return results, total_count


async def get_technique_details(
    session: AsyncSession,
    technique_id: str,
) -> dict[str, Any] | None:
    """Get complete details for a specific technique.

    Args:
        session: Database session
        technique_id: Technique ID (e.g., "T1566" or "T1566.001")

    Returns:
        Complete technique details or None if not found
    """
    stmt = select(AttackTechnique).where(AttackTechnique.technique_id == technique_id)
    result = await session.execute(stmt)
    tech = result.scalar_one_or_none()

    if not tech:
        return None

    return {
        "technique_id": tech.technique_id,
        "stix_id": tech.stix_id,
        "name": tech.name,
        "description": tech.description,  # Full description
        "is_subtechnique": tech.is_subtechnique,
        "parent_technique_id": tech.parent_technique_id,
        "tactics": tech.tactics,
        "platforms": tech.platforms,
        "data_sources": tech.data_sources,
        "detection": tech.detection,
        "permissions_required": tech.permissions_required,
        "effective_permissions": tech.effective_permissions,
        "version": tech.version,
        "created": tech.created.isoformat() if tech.created else None,
        "modified": tech.modified.isoformat() if tech.modified else None,
        "deprecated": tech.deprecated,
        "revoked": tech.revoked,
        "badge_url": tech.badge_url,
        "embedding_generated": tech.embedding is not None,
    }


async def get_technique_badges(
    session: AsyncSession,
    technique_ids: list[str],
) -> dict[str, str]:
    """Get badge URLs for multiple techniques.

    Args:
        session: Database session
        technique_ids: List of technique IDs

    Returns:
        Dictionary mapping technique_id to badge_url
    """
    stmt = select(AttackTechnique).where(AttackTechnique.technique_id.in_(technique_ids))
    result = await session.execute(stmt)
    techniques = result.scalars().all()

    return {tech.technique_id: tech.badge_url for tech in techniques}


async def search_threat_actors(
    session: AsyncSession,
    query: str | None = None,
    techniques: list[str] | None = None,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search threat actor groups using traditional search.

    Args:
        session: Database session
        query: Full-text search query (searches name, aliases, description)
        techniques: Filter by techniques used (e.g., ["T1566.001"])
        limit: Maximum results to return

    Returns:
        Tuple of (groups list, total count)
    """
    # Build query
    stmt = select(AttackGroup)

    # Apply filters
    filters = []

    # Exclude revoked groups
    filters.append(AttackGroup.revoked.is_(False))

    if techniques:
        # Array overlap operator
        filters.append(AttackGroup.techniques_used.overlap(techniques))

    if query:
        # Full-text search on name, aliases, and description
        search_filter = or_(
            AttackGroup.name.ilike(f"%{query}%"),
            AttackGroup.description.ilike(f"%{query}%"),
        )
        filters.append(search_filter)

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total_count = total_result.scalar_one()

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    groups = result.scalars().all()

    # Format results
    results = []
    for group in groups:
        results.append({
            "group_id": group.group_id,
            "name": group.name,
            "aliases": group.aliases,
            "description": group.description[:200] + "..." if len(group.description) > 200 else group.description,
            "techniques_count": len(group.techniques_used) if group.techniques_used else 0,
            "revoked": group.revoked,
        })

    return results, total_count


async def find_similar_techniques(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    tactics: list[str] | None = None,
    platforms: list[str] | None = None,
    active_only: bool = True,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar techniques using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of attack scenario
        min_similarity: Minimum similarity threshold (0-1)
        tactics: Filter by tactics
        platforms: Filter by platforms
        active_only: Exclude deprecated/revoked techniques
        limit: Maximum results to return

    Returns:
        List of techniques with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    # Use cosine distance operator <=> and convert to similarity with 1 - distance
    filters = [AttackTechnique.embedding.is_not(None)]

    if active_only:
        filters.append(AttackTechnique.deprecated.is_(False))
        filters.append(AttackTechnique.revoked.is_(False))

    if tactics:
        filters.append(AttackTechnique.tactics.overlap(tactics))

    if platforms:
        filters.append(AttackTechnique.platforms.overlap(platforms))

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - AttackTechnique.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            AttackTechnique,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(AttackTechnique.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for tech, sim_score in rows:
        results.append({
            "technique_id": tech.technique_id,
            "name": tech.name,
            "description": tech.description[:200] + "..." if len(tech.description) > 200 else tech.description,
            "tactics": tech.tactics,
            "platforms": tech.platforms,
            "is_subtechnique": tech.is_subtechnique,
            "similarity_score": float(sim_score),
            "badge_url": tech.badge_url,
        })

    return results


async def find_similar_threat_actors(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar threat actor groups using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of threat actor or activity
        min_similarity: Minimum similarity threshold (0-1)
        limit: Maximum results to return

    Returns:
        List of groups with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [
        AttackGroup.embedding.is_not(None),
        AttackGroup.revoked.is_(False),
    ]

    # Calculate similarity
    similarity = 1 - AttackGroup.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            AttackGroup,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(AttackGroup.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for group, sim_score in rows:
        results.append({
            "group_id": group.group_id,
            "name": group.name,
            "aliases": group.aliases,
            "description": group.description[:200] + "..." if len(group.description) > 200 else group.description,
            "techniques_count": len(group.techniques_used) if group.techniques_used else 0,
            "similarity_score": float(sim_score),
        })

    return results


async def get_group_profile(
    session: AsyncSession,
    group_id: str,
) -> dict[str, Any] | None:
    """Get complete profile for a threat actor group.

    Args:
        session: Database session
        group_id: Group ID (e.g., "G0001")

    Returns:
        Complete group profile or None if not found
    """
    stmt = select(AttackGroup).where(AttackGroup.group_id == group_id)
    result = await session.execute(stmt)
    group = result.scalar_one_or_none()

    if not group:
        return None

    return {
        "group_id": group.group_id,
        "stix_id": group.stix_id,
        "name": group.name,
        "aliases": group.aliases,
        "description": group.description,  # Full description
        "associated_groups": group.associated_groups,
        "techniques_used": group.techniques_used,
        "software_used": group.software_used,
        "attribution_confidence": group.attribution_confidence,
        "version": group.version,
        "created": group.created.isoformat() if group.created else None,
        "modified": group.modified.isoformat() if group.modified else None,
        "revoked": group.revoked,
        "embedding_generated": group.embedding is not None,
    }
