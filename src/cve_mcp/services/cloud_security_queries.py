"""Query services for cloud security data."""

from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from cve_mcp.models.cloud_security import (
    CloudProvider,
    CloudSecurityProperty,
    CloudService,
    CloudServiceEquivalence,
    CloudSharedResponsibility,
)
from cve_mcp.services.embeddings import generate_embedding


# ============================================================================
# Service Queries
# ============================================================================


async def search_services(
    session: AsyncSession,
    query: str | None = None,
    provider: str | None = None,
    category: str | None = None,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """
    Search cloud services with filters.

    Args:
        session: Database session
        query: Text search query (searches name and description)
        provider: Filter by provider ID
        category: Filter by service category
        limit: Maximum results to return

    Returns:
        Tuple of (results list, total count)
    """
    stmt = select(CloudService)

    # Build filters
    filters = []

    if provider:
        filters.append(CloudService.provider_id == provider)

    if category:
        filters.append(CloudService.service_category == category)

    if query:
        # Use ILIKE for case-insensitive search
        search_filter = or_(
            CloudService.service_name.ilike(f"%{query}%"),
            CloudService.official_name.ilike(f"%{query}%"),
            CloudService.description.ilike(f"%{query}%"),
        )
        filters.append(search_filter)

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    count_result = await session.execute(count_stmt)
    total_count = count_result.scalar() or 0

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    services = result.scalars().all()

    # Format results (summary format)
    formatted = [_service_to_dict(svc, include_full=False) for svc in services]

    return (formatted, total_count)


async def get_service_details(
    session: AsyncSession,
    service_id: str,
) -> dict[str, Any] | None:
    """
    Get complete details for a cloud service including all properties.

    Args:
        session: Database session
        service_id: Service ID (e.g., "aws-s3")

    Returns:
        Service details dict or None if not found
    """
    stmt = (
        select(CloudService)
        .where(CloudService.service_id == service_id)
        .options(selectinload(CloudService.properties))
    )

    result = await session.execute(stmt)
    service = result.scalar_one_or_none()

    if not service:
        return None

    # Format with full details
    service_dict = _service_to_dict(service, include_full=True)

    # Add properties grouped by type
    properties_by_type: dict[str, list[dict[str, Any]]] = {}

    for prop in service.properties:
        if prop.deprecated:
            continue

        prop_type = prop.property_type
        if prop_type not in properties_by_type:
            properties_by_type[prop_type] = []

        properties_by_type[prop_type].append(_property_to_dict(prop, include_full=True))

    service_dict["properties_by_type"] = properties_by_type
    service_dict["total_properties"] = len(service.properties)

    return service_dict


async def get_service_security(
    session: AsyncSession,
    provider: str,
    service: str,
) -> dict[str, Any] | None:
    """
    Get all security properties for a specific service.

    This is the primary tool function for retrieving security info.

    Args:
        session: Database session
        provider: Provider ID ("aws", "azure", "gcp")
        service: Service short name ("s3", "blob-storage", "cloud-storage")

    Returns:
        Dict with service info and all security properties
    """
    service_id = f"{provider}-{service}"

    stmt = (
        select(CloudService)
        .where(CloudService.service_id == service_id)
        .options(selectinload(CloudService.properties))
    )

    result = await session.execute(stmt)
    service_obj = result.scalar_one_or_none()

    if not service_obj:
        return None

    # Group properties by type
    properties_by_type: dict[str, list[dict[str, Any]]] = {}

    for prop in service_obj.properties:
        if prop.deprecated:
            continue

        prop_type = prop.property_type
        if prop_type not in properties_by_type:
            properties_by_type[prop_type] = []

        properties_by_type[prop_type].append(_property_to_dict(prop, include_full=True))

    return {
        "service_id": service_obj.service_id,
        "service_name": service_obj.service_name,
        "official_name": service_obj.official_name,
        "provider_id": service_obj.provider_id,
        "category": service_obj.service_category,
        "description": service_obj.description or "",
        "documentation_url": service_obj.documentation_url,
        "security_documentation_url": service_obj.security_documentation_url,
        "properties_by_type": properties_by_type,
        "total_properties": len([p for p in service_obj.properties if not p.deprecated]),
        "last_verified": service_obj.last_verified.isoformat() if service_obj.last_verified else None,
    }


async def compare_services(
    session: AsyncSession,
    service_category: str,
    providers: list[str] | None = None,
) -> dict[str, Any] | None:
    """
    Compare equivalent services across cloud providers.

    Args:
        session: Database session
        service_category: Service category (e.g., "object_storage")
        providers: Optional list of providers to compare (defaults to all)

    Returns:
        Comparison dict with nuances and property comparisons
    """
    # Get equivalence record
    stmt = select(CloudServiceEquivalence).where(
        CloudServiceEquivalence.service_category == service_category
    )

    result = await session.execute(stmt)
    equivalence = result.scalar_one_or_none()

    if not equivalence:
        return None

    # Filter service_ids by requested providers if specified
    service_ids = equivalence.service_ids
    if providers:
        service_ids = [sid for sid in service_ids if any(sid.startswith(f"{p}-") for p in providers)]

    # Get services
    stmt = select(CloudService).where(CloudService.service_id.in_(service_ids))
    result = await session.execute(stmt)
    services = result.scalars().all()

    # Build comparison
    services_comparison = {}
    for svc in services:
        services_comparison[svc.service_id] = {
            "service_name": svc.service_name,
            "official_name": svc.official_name,
            "provider": svc.provider_id,
            "description": svc.description or "",
            "documentation_url": svc.documentation_url,
        }

    return {
        "category": service_category,
        "services": services_comparison,
        "comparable_dimensions": equivalence.comparable_dimensions or [],
        "non_comparable_dimensions": equivalence.non_comparable_dimensions or [],
        "nuances": equivalence.nuances or {},
        "comparison_notes": equivalence.comparison_notes,
        "confidence_score": equivalence.confidence_score,
        "last_verified": equivalence.last_verified.isoformat() if equivalence.last_verified else None,
    }


async def get_shared_responsibility(
    session: AsyncSession,
    provider: str,
    service: str,
    layer: str | None = None,
) -> dict[str, Any] | None:
    """
    Get shared responsibility model for a service.

    Args:
        session: Database session
        provider: Provider ID
        service: Service short name
        layer: Optional specific layer to query

    Returns:
        Dict with responsibility breakdown by layer
    """
    service_id = f"{provider}-{service}"

    # Check service exists
    stmt = select(CloudService).where(CloudService.service_id == service_id)
    result = await session.execute(stmt)
    service_obj = result.scalar_one_or_none()

    if not service_obj:
        return None

    # Query responsibilities
    stmt = select(CloudSharedResponsibility).where(
        CloudSharedResponsibility.service_id == service_id
    )

    if layer:
        stmt = stmt.where(CloudSharedResponsibility.layer == layer)

    result = await session.execute(stmt)
    responsibilities = result.scalars().all()

    # Group by layer and owner
    by_layer: dict[str, dict[str, Any]] = {}

    for resp in responsibilities:
        layer_name = resp.layer
        if layer_name not in by_layer:
            by_layer[layer_name] = {
                "layer": layer_name,
                "owner": resp.owner,
                "description": resp.description or "",
                "specifics": resp.specifics or {},
                "source_url": resp.source_url,
            }

    return {
        "service_id": service_id,
        "service_name": service_obj.service_name,
        "provider": service_obj.provider_id,
        "responsibilities_by_layer": by_layer,
        "total_layers": len(by_layer),
    }


# ============================================================================
# Semantic Search
# ============================================================================


async def find_similar_services(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Find similar cloud services using vector similarity.

    Requires OPENAI_API_KEY to be set.

    Args:
        session: Database session
        description: Description text to find similar services for
        min_similarity: Minimum cosine similarity (0.0-1.0)
        limit: Maximum results

    Returns:
        List of similar services with similarity scores
    """
    # Generate embedding for query
    embedding = await generate_embedding(description)

    if not embedding:
        return []

    # Query using pgvector cosine similarity
    stmt = (
        select(
            CloudService,
            (1 - CloudService.embedding.cosine_distance(embedding)).label("similarity"),
        )
        .where(CloudService.embedding.isnot(None))
        .where((1 - CloudService.embedding.cosine_distance(embedding)) >= min_similarity)
        .order_by((1 - CloudService.embedding.cosine_distance(embedding)).desc())
        .limit(limit)
    )

    result = await session.execute(stmt)
    rows = result.all()

    formatted = []
    for row in rows:
        service = row[0]
        similarity = row[1]

        service_dict = _service_to_dict(service, include_full=False)
        service_dict["similarity"] = round(similarity, 4)
        formatted.append(service_dict)

    return formatted


# ============================================================================
# Property Queries
# ============================================================================


async def search_properties(
    session: AsyncSession,
    query: str | None = None,
    provider: str | None = None,
    property_type: str | None = None,
    min_confidence: float = 0.0,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """
    Search security properties with filters.

    Args:
        session: Database session
        query: Text search query
        provider: Filter by provider
        property_type: Filter by property type
        min_confidence: Minimum confidence score
        limit: Maximum results

    Returns:
        Tuple of (results list, total count)
    """
    stmt = select(CloudSecurityProperty).join(CloudService)

    filters = []

    if provider:
        filters.append(CloudService.provider_id == provider)

    if property_type:
        filters.append(CloudSecurityProperty.property_type == property_type)

    if min_confidence > 0.0:
        filters.append(CloudSecurityProperty.confidence_score >= min_confidence)

    if query:
        search_filter = or_(
            CloudSecurityProperty.property_name.ilike(f"%{query}%"),
            CloudSecurityProperty.summary.ilike(f"%{query}%"),
        )
        filters.append(search_filter)

    if filters:
        stmt = stmt.where(and_(*filters))

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    count_result = await session.execute(count_stmt)
    total_count = count_result.scalar() or 0

    # Apply limit and execute
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    properties = result.scalars().all()

    formatted = [_property_to_dict(prop, include_full=False) for prop in properties]

    return (formatted, total_count)


# ============================================================================
# Helper Functions
# ============================================================================


def _service_to_dict(service: CloudService, include_full: bool = False) -> dict[str, Any]:
    """
    Convert CloudService model to dict.

    Args:
        service: CloudService instance
        include_full: If True, include all fields; if False, summary only

    Returns:
        Formatted dict
    """
    # Guard against None
    description = service.description or ""

    result = {
        "service_id": service.service_id,
        "provider_id": service.provider_id,
        "service_name": service.service_name,
        "official_name": service.official_name,
        "category": service.service_category,
        "description": description[:200] + "..." if len(description) > 200 else description,
    }

    if include_full:
        result.update(
            {
                "description_full": description,
                "equivalent_services": service.equivalent_services or {},
                "documentation_url": service.documentation_url,
                "security_documentation_url": service.security_documentation_url,
                "api_reference_url": service.api_reference_url,
                "last_verified": service.last_verified.isoformat() if service.last_verified else None,
                "created": service.created.isoformat() if service.created else None,
                "modified": service.modified.isoformat() if service.modified else None,
                "deprecated": service.deprecated,
                "has_embedding": service.embedding is not None,
            }
        )

    return result


def _property_to_dict(prop: CloudSecurityProperty, include_full: bool = False) -> dict[str, Any]:
    """
    Convert CloudSecurityProperty model to dict.

    Args:
        prop: CloudSecurityProperty instance
        include_full: If True, include all fields; if False, summary only

    Returns:
        Formatted dict
    """
    # Guard against None
    summary = prop.summary or ""

    result = {
        "property_id": prop.property_id,
        "property_type": prop.property_type,
        "property_name": prop.property_name,
        "summary": summary[:300] + "..." if len(summary) > 300 else summary,
        "confidence_score": prop.confidence_score,
    }

    if include_full:
        result.update(
            {
                "property_value": prop.property_value or {},
                "source_url": prop.source_url,
                "source_type": prop.source_type,
                "source_section": prop.source_section,
                "source_quote": prop.source_quote or "",
                "verification_method": prop.verification_method,
                "verification_metadata": prop.verification_metadata or {},
                "extracted_date": prop.extracted_date.isoformat() if prop.extracted_date else None,
                "last_verified": prop.last_verified.isoformat() if prop.last_verified else None,
                "cis_controls": prop.cis_controls or [],
                "nist_controls": prop.nist_controls or [],
                "compliance_frameworks": prop.compliance_frameworks or [],
                "affected_by_cves": prop.affected_by_cves or [],
                "breaking_change": prop.breaking_change,
                "change_date": prop.change_date.isoformat() if prop.change_date else None,
                "change_notes": prop.change_notes,
            }
        )

    return result


# ============================================================================
# Admin/Maintenance Queries
# ============================================================================


async def get_low_confidence_properties(
    session: AsyncSession,
    threshold: float = 0.70,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Get properties with confidence below threshold for review.

    Args:
        session: Database session
        threshold: Confidence threshold
        limit: Maximum results

    Returns:
        List of low-confidence properties
    """
    stmt = (
        select(CloudSecurityProperty)
        .where(CloudSecurityProperty.confidence_score < threshold)
        .order_by(CloudSecurityProperty.confidence_score.asc())
        .limit(limit)
    )

    result = await session.execute(stmt)
    properties = result.scalars().all()

    return [_property_to_dict(prop, include_full=True) for prop in properties]


async def get_stale_services(
    session: AsyncSession,
    days_threshold: int = 90,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Get services that haven't been verified recently.

    Args:
        session: Database session
        days_threshold: Number of days since last verification
        limit: Maximum results

    Returns:
        List of stale services
    """
    from datetime import datetime, timedelta

    cutoff_date = datetime.utcnow() - timedelta(days=days_threshold)

    stmt = (
        select(CloudService)
        .where(CloudService.last_verified < cutoff_date)
        .order_by(CloudService.last_verified.asc())
        .limit(limit)
    )

    result = await session.execute(stmt)
    services = result.scalars().all()

    formatted = []
    for svc in services:
        service_dict = _service_to_dict(svc, include_full=True)
        service_dict["days_since_verification"] = (
            datetime.utcnow() - svc.last_verified
        ).days
        formatted.append(service_dict)

    return formatted
