"""OWASP LLM Top 10 query service with split-term search."""

import json
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.owasp_llm import OwaspLlmTop10
from cve_mcp.utils import escape_like


async def search_owasp_llm_vulnerabilities(
    session: AsyncSession,
    query: str | None = None,
    llm_ids: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Search OWASP LLM Top 10 vulnerabilities using split-term search.

    Args:
        session: Database session
        query: Search terms (split into individual words for OR matching)
        llm_ids: Filter by specific LLM IDs (e.g., ["LLM01", "LLM02"])
        limit: Maximum results to return

    Returns:
        List of vulnerability dicts with all fields
    """
    stmt = select(OwaspLlmTop10)

    # Apply filters
    filters = []

    if llm_ids:
        # Normalize to uppercase
        normalized_ids = [lid.upper() for lid in llm_ids]
        filters.append(OwaspLlmTop10.llm_id.in_(normalized_ids))

    if query:
        # Split query into individual terms and OR across them (simple ILIKE matching)
        terms = [t.strip() for t in query.split() if t.strip()]
        if terms:
            term_filters = []
            for term in terms:
                term_filters.append(OwaspLlmTop10.name.ilike(f"%{escape_like(term)}%"))
                term_filters.append(OwaspLlmTop10.description.ilike(f"%{escape_like(term)}%"))
            filters.append(or_(*term_filters))

    if filters:
        stmt = stmt.where(*filters)

    # Always order by llm_id
    stmt = stmt.order_by(OwaspLlmTop10.llm_id)

    stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    vulnerabilities = result.scalars().all()

    # Convert to dict format
    results = []
    for vuln in vulnerabilities:
        # Parse related_techniques JSON if it's a string
        related_techniques = vuln.related_techniques
        if isinstance(related_techniques, str):
            try:
                related_techniques = json.loads(related_techniques)
            except (json.JSONDecodeError, TypeError):
                related_techniques = {}

        results.append(
            {
                "llm_id": vuln.llm_id,
                "name": vuln.name,
                "description": vuln.description,
                "common_examples": vuln.common_examples or [],
                "prevention_strategies": vuln.prevention_strategies or [],
                "example_attack_scenarios": vuln.example_attack_scenarios or [],
                "related_techniques": related_techniques,
                "url": vuln.url,
                "version": vuln.version,
            }
        )

    return results


async def get_owasp_llm_vulnerability(
    session: AsyncSession,
    llm_id: str,
) -> dict[str, Any] | None:
    """
    Get a specific OWASP LLM Top 10 vulnerability by ID.

    Args:
        session: Database session
        llm_id: LLM ID (e.g., "LLM01")

    Returns:
        Vulnerability dict or None if not found
    """
    stmt = select(OwaspLlmTop10).where(OwaspLlmTop10.llm_id == llm_id.upper())
    result = await session.execute(stmt)
    vuln = result.scalar_one_or_none()

    if not vuln:
        return None

    # Parse related_techniques JSON if it's a string
    related_techniques = vuln.related_techniques
    if isinstance(related_techniques, str):
        try:
            related_techniques = json.loads(related_techniques)
        except (json.JSONDecodeError, TypeError):
            related_techniques = {}

    return {
        "llm_id": vuln.llm_id,
        "name": vuln.name,
        "description": vuln.description,
        "common_examples": vuln.common_examples or [],
        "prevention_strategies": vuln.prevention_strategies or [],
        "example_attack_scenarios": vuln.example_attack_scenarios or [],
        "related_techniques": related_techniques,
        "url": vuln.url,
        "version": vuln.version,
    }
