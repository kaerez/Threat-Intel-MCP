"""ATLAS query service with traditional and semantic search.

Provides 5 async query functions for MITRE ATLAS AI/ML threat data:
- Traditional search: keyword/filter-based queries for techniques and case studies
- Semantic search: AI-powered similarity matching using pgvector
"""

from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.atlas import ATLASCaseStudy, ATLASTechnique
from cve_mcp.services.embeddings import generate_embedding


async def search_techniques(
    session: AsyncSession,
    query: str | None = None,
    tactics: list[str] | None = None,
    ml_lifecycle_stage: str | None = None,
    ai_system_type: list[str] | None = None,
    active_only: bool = True,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search ATLAS techniques using traditional full-text and filter-based search.

    Args:
        session: Database session
        query: Full-text search query (searches name and description)
        tactics: Filter by tactics (e.g., ["reconnaissance", "ml-attack"])
        ml_lifecycle_stage: Filter by ML lifecycle stage (e.g., "training", "deployment")
        ai_system_type: Filter by AI system type (e.g., ["computer-vision", "nlp"])
        active_only: Exclude deprecated/revoked techniques
        limit: Maximum results to return

    Returns:
        Tuple of (techniques list, total count)
    """
    # Build query
    stmt = select(ATLASTechnique)

    # Apply filters
    filters = []

    if active_only:
        filters.append(ATLASTechnique.deprecated.is_(False))
        filters.append(ATLASTechnique.revoked.is_(False))

    if tactics:
        # Array overlap operator
        filters.append(ATLASTechnique.tactics.overlap(tactics))

    if ml_lifecycle_stage:
        filters.append(ATLASTechnique.ml_lifecycle_stage == ml_lifecycle_stage)

    if ai_system_type:
        # Array overlap operator
        filters.append(ATLASTechnique.ai_system_type.overlap(ai_system_type))

    if query:
        # Full-text search on name and description using ILIKE
        search_filter = or_(
            ATLASTechnique.name.ilike(f"%{query}%"),
            ATLASTechnique.description.ilike(f"%{query}%"),
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
            "description": (
                tech.description[:200] + "..."
                if len(tech.description) > 200
                else tech.description
            ),
            "tactics": tech.tactics,
            "ml_lifecycle_stage": tech.ml_lifecycle_stage,
            "ai_system_type": tech.ai_system_type,
            "deprecated": tech.deprecated,
            "revoked": tech.revoked,
            "badge_url": tech.badge_url,
        })

    return results, total_count


async def get_technique_details(
    session: AsyncSession,
    technique_id: str,
) -> dict[str, Any] | None:
    """Get complete details for a specific ATLAS technique.

    Args:
        session: Database session
        technique_id: Technique ID (e.g., "AML.T0001")

    Returns:
        Complete technique details or None if not found
    """
    stmt = select(ATLASTechnique).where(ATLASTechnique.technique_id == technique_id)
    result = await session.execute(stmt)
    tech = result.scalar_one_or_none()

    if not tech:
        return None

    return {
        "technique_id": tech.technique_id,
        "stix_id": tech.stix_id,
        "name": tech.name,
        "description": tech.description,  # Full description
        "tactics": tech.tactics,
        "ml_lifecycle_stage": tech.ml_lifecycle_stage,
        "ai_system_type": tech.ai_system_type,
        "detection": tech.detection,
        "mitigation": tech.mitigation,
        "version": tech.version,
        "created": tech.created.isoformat() if tech.created else None,
        "modified": tech.modified.isoformat() if tech.modified else None,
        "deprecated": tech.deprecated,
        "revoked": tech.revoked,
        "badge_url": tech.badge_url,
        "embedding_generated": tech.embedding is not None,
    }


async def find_similar_techniques(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    tactics: list[str] | None = None,
    ml_lifecycle_stage: str | None = None,
    ai_system_type: list[str] | None = None,
    active_only: bool = True,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar ATLAS techniques using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of AI/ML attack scenario
        min_similarity: Minimum similarity threshold (0-1)
        tactics: Filter by tactics
        ml_lifecycle_stage: Filter by ML lifecycle stage
        ai_system_type: Filter by AI system type
        active_only: Exclude deprecated/revoked techniques
        limit: Maximum results to return

    Returns:
        List of techniques with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [ATLASTechnique.embedding.is_not(None)]

    if active_only:
        filters.append(ATLASTechnique.deprecated.is_(False))
        filters.append(ATLASTechnique.revoked.is_(False))

    if tactics:
        filters.append(ATLASTechnique.tactics.overlap(tactics))

    if ml_lifecycle_stage:
        filters.append(ATLASTechnique.ml_lifecycle_stage == ml_lifecycle_stage)

    if ai_system_type:
        filters.append(ATLASTechnique.ai_system_type.overlap(ai_system_type))

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - ATLASTechnique.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            ATLASTechnique,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(ATLASTechnique.embedding.cosine_distance(query_embedding))
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
            "description": (
                tech.description[:200] + "..."
                if len(tech.description) > 200
                else tech.description
            ),
            "tactics": tech.tactics,
            "ml_lifecycle_stage": tech.ml_lifecycle_stage,
            "ai_system_type": tech.ai_system_type,
            "similarity_score": float(sim_score),
            "badge_url": tech.badge_url,
        })

    return results


async def search_case_studies(
    session: AsyncSession,
    query: str | None = None,
    techniques: list[str] | None = None,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Search ATLAS case studies using traditional search.

    Args:
        session: Database session
        query: Full-text search query (searches name and summary)
        techniques: Filter by techniques used (e.g., ["AML.T0001"])
        limit: Maximum results to return

    Returns:
        Tuple of (case studies list, total count)
    """
    # Build query
    stmt = select(ATLASCaseStudy)

    # Apply filters
    filters = []

    if techniques:
        # Array overlap operator
        filters.append(ATLASCaseStudy.techniques_used.overlap(techniques))

    if query:
        # Full-text search on name and summary
        search_filter = or_(
            ATLASCaseStudy.name.ilike(f"%{query}%"),
            ATLASCaseStudy.summary.ilike(f"%{query}%"),
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
    case_studies = result.scalars().all()

    # Format results
    results = []
    for cs in case_studies:
        results.append({
            "case_study_id": cs.case_study_id,
            "name": cs.name,
            "summary": (
                cs.summary[:200] + "..."
                if len(cs.summary) > 200
                else cs.summary
            ),
            "techniques_used": cs.techniques_used,
            "incident_date": cs.incident_date.isoformat() if cs.incident_date else None,
            "target_system": cs.target_system,
        })

    return results, total_count


async def find_similar_case_studies(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find similar ATLAS case studies using semantic search with AI embeddings.

    Args:
        session: Database session
        description: Natural language description of AI/ML incident or scenario
        min_similarity: Minimum similarity threshold (0-1)
        limit: Maximum results to return

    Returns:
        List of case studies with similarity scores
    """
    # Generate embedding for query description
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    filters = [ATLASCaseStudy.embedding.is_not(None)]

    # Calculate similarity as 1 - cosine_distance
    similarity = 1 - ATLASCaseStudy.embedding.cosine_distance(query_embedding)

    # Add similarity threshold filter
    filters.append(similarity >= min_similarity)

    stmt = (
        select(
            ATLASCaseStudy,
            similarity.label("similarity_score"),
        )
        .where(and_(*filters))
        .order_by(ATLASCaseStudy.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    # Format results
    results = []
    for cs, sim_score in rows:
        results.append({
            "case_study_id": cs.case_study_id,
            "name": cs.name,
            "summary": (
                cs.summary[:200] + "..."
                if len(cs.summary) > 200
                else cs.summary
            ),
            "techniques_used": cs.techniques_used,
            "incident_date": cs.incident_date.isoformat() if cs.incident_date else None,
            "target_system": cs.target_system,
            "similarity_score": float(sim_score),
        })

    return results
