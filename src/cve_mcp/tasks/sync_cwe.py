"""MITRE CWE data synchronization with semantic embeddings.

Downloads CWE XML data, parses, generates embeddings, and populates database.
CWE is the Common Weakness Enumeration - a catalog of software and hardware
weakness types.
"""

import asyncio
import io
import logging
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import structlog
from lxml import etree

from cve_mcp.ingest.cwe_parser import (
    parse_category,
    parse_external_mapping,
    parse_view,
    parse_weakness,
)
from cve_mcp.models.base import get_task_session
from cve_mcp.models.cwe import (
    CWECategory,
    CWEExternalMapping,
    CWEView,
    CWEWeakness,
    CWEWeaknessCategory,
)
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.services.embeddings import generate_embeddings_batch
from cve_mcp.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)
slogger = structlog.get_logger()

# MITRE CWE XML data URL
CWE_DATA_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_CACHE_DIR = Path.home() / ".cache" / "cve-mcp" / "cwe"


async def download_cwe_data(
    cache_dir: Path,
    force_download: bool = False,
) -> bytes:
    """Download CWE ZIP and extract XML content.

    Args:
        cache_dir: Directory to cache downloaded data
        force_download: Force re-download even if cached

    Returns:
        XML content as bytes
    """
    # Create cache directory if needed
    cache_dir.mkdir(parents=True, exist_ok=True)

    xml_cache_path = cache_dir / "cwec_latest.xml"

    # Check if already cached
    if xml_cache_path.exists() and not force_download:
        logger.info(f"Using cached CWE data: {xml_cache_path}")
        return xml_cache_path.read_bytes()

    logger.info(f"Downloading CWE data from {CWE_DATA_URL}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.get(CWE_DATA_URL)
        response.raise_for_status()

        # Extract XML from ZIP
        zip_data = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_data, "r") as zf:
            # Find the XML file in the ZIP
            xml_files = [f for f in zf.namelist() if f.endswith(".xml")]
            if not xml_files:
                raise ValueError("No XML file found in CWE ZIP")

            xml_filename = xml_files[0]
            logger.info(f"Extracting {xml_filename} from ZIP")
            xml_content = zf.read(xml_filename)

        # Cache the XML
        xml_cache_path.write_bytes(xml_content)
        logger.info(f"Cached CWE XML to {xml_cache_path}")

    return xml_content


def parse_cwe_xml(xml_content: bytes) -> dict[str, Any]:
    """Parse CWE XML content into structured data.

    Args:
        xml_content: CWE XML file content

    Returns:
        Dictionary with weaknesses, categories, views, and version info
    """
    logger.info("Parsing CWE XML content")

    # Parse XML
    root = etree.fromstring(xml_content)

    # Get namespace
    nsmap = root.nsmap
    ns = nsmap.get(None, "")
    if ns:
        ns = f"{{{ns}}}"

    # Extract version info
    version = root.get("Version", "unknown")
    logger.info(f"CWE version: {version}")

    # Parse weaknesses
    weaknesses: list[dict[str, Any]] = []
    weaknesses_elem = root.find(f"{ns}Weaknesses")
    if weaknesses_elem is not None:
        for weakness_elem in weaknesses_elem.findall(f"{ns}Weakness"):
            parsed = parse_weakness(weakness_elem, ns)
            if parsed:
                parsed["cwe_version"] = version
                weaknesses.append(parsed)

    logger.info(f"Parsed {len(weaknesses)} weaknesses")

    # Parse categories
    categories: list[dict[str, Any]] = []
    categories_elem = root.find(f"{ns}Categories")
    if categories_elem is not None:
        for category_elem in categories_elem.findall(f"{ns}Category"):
            parsed = parse_category(category_elem, ns)
            if parsed:
                categories.append(parsed)

    logger.info(f"Parsed {len(categories)} categories")

    # Parse views
    views: list[dict[str, Any]] = []
    views_elem = root.find(f"{ns}Views")
    if views_elem is not None:
        for view_elem in views_elem.findall(f"{ns}View"):
            parsed = parse_view(view_elem, ns)
            if parsed:
                views.append(parsed)

    logger.info(f"Parsed {len(views)} views")

    # Extract member lists for category memberships
    for cat_data in categories:
        cat_id = cat_data["category_id"]
        # Find members element
        cat_elem = categories_elem.find(f"{ns}Category[@ID='{cat_id.replace('CWE-', '')}']")
        if cat_elem is not None:
            members_elem = cat_elem.find(f"{ns}Relationships")
            if members_elem is not None:
                member_ids = []
                for member in members_elem.findall(f"{ns}Has_Member"):
                    member_id = member.get("CWE_ID")
                    if member_id:
                        member_ids.append(f"CWE-{member_id}")
                cat_data["members"] = member_ids

    # Extract member lists for view memberships
    for view_data in views:
        view_id_num = view_data["view_id"].replace("CWE-", "")
        view_elem = views_elem.find(f"{ns}View[@ID='{view_id_num}']")
        if view_elem is not None:
            members_elem = view_elem.find(f"{ns}Members")
            if members_elem is not None:
                member_ids = []
                for member in members_elem.findall(f"{ns}Has_Member"):
                    member_id = member.get("CWE_ID")
                    if member_id:
                        member_ids.append(f"CWE-{member_id}")
                view_data["members"] = member_ids

    return {
        "weaknesses": weaknesses,
        "categories": categories,
        "views": views,
        "version": version,
    }


async def sync_views(
    session: Any,
    views: list[dict[str, Any]],
) -> int:
    """Sync CWE views to database.

    Args:
        session: Database session
        views: List of parsed view data

    Returns:
        Number of views synced
    """
    logger.info(f"Syncing {len(views)} views")

    for view_data in views:
        # Map parser fields to model fields
        view = CWEView(
            view_id=view_data["view_id"],
            name=view_data["name"],
            view_type=view_data.get("view_type"),
            status=view_data.get("status"),
            description=view_data.get("objective"),  # Map objective -> description
        )
        await session.merge(view)

    return len(views)


async def sync_categories(
    session: Any,
    categories: list[dict[str, Any]],
    default_view_id: str = "CWE-1000",
) -> int:
    """Sync CWE categories to database.

    Args:
        session: Database session
        categories: List of parsed category data
        default_view_id: Default view ID for categories

    Returns:
        Number of categories synced
    """
    logger.info(f"Syncing {len(categories)} categories")

    for i, cat_data in enumerate(categories):
        # Map parser fields to model fields
        category = CWECategory(
            category_id=cat_data["category_id"],
            name=cat_data["name"],
            description=cat_data.get("summary"),  # Map summary -> description
            view_id=default_view_id,
        )
        await session.merge(category)

        if (i + 1) % 100 == 0:
            logger.info(f"Synced {i + 1}/{len(categories)} categories")

    return len(categories)


async def sync_category_memberships(
    session: Any,
    categories: list[dict[str, Any]],
    views: list[dict[str, Any]],
) -> int:
    """Sync weakness-category-view relationships.

    Categories and views contain member lists that define which
    weaknesses belong to which organizational groupings.

    Args:
        session: Database session
        categories: List of parsed category data with members
        views: List of parsed view data with members

    Returns:
        Number of category memberships synced
    """
    from sqlalchemy import select

    from cve_mcp.models.cwe import CWECategory, CWEView, CWEWeakness

    logger.info("Syncing category memberships")

    # Get valid IDs for FK validation
    result = await session.execute(select(CWEWeakness.cwe_id))
    valid_weakness_ids = {row[0] for row in result.all()}
    result = await session.execute(select(CWECategory.category_id))
    valid_category_ids = {row[0] for row in result.all()}
    result = await session.execute(select(CWEView.view_id))
    valid_view_ids = {row[0] for row in result.all()}
    logger.info(
        f"FK validation: {len(valid_weakness_ids)} weaknesses, "
        f"{len(valid_category_ids)} categories, {len(valid_view_ids)} views"
    )

    # Clear existing memberships
    await session.execute(CWEWeaknessCategory.__table__.delete())

    count = 0
    skipped = 0

    # Process category memberships
    for cat_data in categories:
        category_id = cat_data["category_id"]
        members = cat_data.get("members") or []
        # Default to CWE-1000 (Research Concepts) view for categories
        view_id = "CWE-1000"

        # Validate category and view exist
        if category_id not in valid_category_ids or view_id not in valid_view_ids:
            skipped += len(members)
            continue

        for member_id in members:
            # Ensure CWE- prefix
            if not member_id.startswith("CWE-"):
                member_id = f"CWE-{member_id}"

            # Skip if weakness doesn't exist (e.g., deprecated)
            if member_id not in valid_weakness_ids:
                skipped += 1
                continue

            membership = CWEWeaknessCategory(
                weakness_id=member_id,
                category_id=category_id,
                view_id=view_id,
            )
            session.add(membership)
            count += 1

    # Skip view memberships - views are not categories and can't be used as category_id FK
    # View structure is captured in cwe_views table directly
    logger.info(f"Synced {count} category memberships, skipped {skipped} invalid refs")
    return count


async def sync_weaknesses(
    session: Any,
    weaknesses: list[dict[str, Any]],
    generate_embeddings: bool = True,
) -> int:
    """Sync CWE weaknesses to database with optional embeddings.

    Args:
        session: Database session
        weaknesses: List of parsed weakness data
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Number of weaknesses synced
    """
    logger.info(f"Syncing {len(weaknesses)} weaknesses")

    # Generate embeddings if requested
    embedding_model = "text-embedding-3-small"
    embedding_timestamp = datetime.utcnow()
    embeddings: list[list[float]] = []

    if generate_embeddings and weaknesses:
        logger.info("Generating semantic embeddings for weaknesses...")

        # Create embedding texts from name and description
        embedding_texts = []
        for w in weaknesses:
            name = w.get("name", "")
            description = w.get("description", "")
            text = f"{name}: {description}"[:8000]
            embedding_texts.append(text)

        embeddings = await generate_embeddings_batch(embedding_texts)
        logger.info(f"Generated {len(embeddings)} weakness embeddings")

    # Sync weaknesses to database
    for i, weakness_data in enumerate(weaknesses):
        # Build model data
        model_data = {
            "cwe_id": weakness_data["cwe_id"],
            "weakness_id": weakness_data["weakness_id"],
            "name": weakness_data["name"],
            "description": weakness_data["description"],
            "extended_description": weakness_data.get("extended_description"),
            "abstraction": weakness_data.get("abstraction"),
            "status": weakness_data.get("status"),
            "likelihood_of_exploit": weakness_data.get("likelihood_of_exploit"),
            "common_consequences": weakness_data.get("common_consequences"),
            "potential_mitigations": weakness_data.get("potential_mitigations"),
            "detection_methods": weakness_data.get("detection_methods"),
            "parent_of": weakness_data.get("parent_of"),
            "child_of": weakness_data.get("child_of"),
            "peer_of": weakness_data.get("peer_of"),
            "can_precede": weakness_data.get("can_precede"),
            "can_follow": weakness_data.get("can_follow"),
            "cwe_version": weakness_data.get("cwe_version"),
            "deprecated": weakness_data.get("deprecated", False),
        }

        # Add embedding if generated
        if embeddings and i < len(embeddings):
            model_data["embedding"] = embeddings[i]
            model_data["embedding_model"] = embedding_model
            model_data["embedding_generated_at"] = embedding_timestamp

        weakness = CWEWeakness(**model_data)
        await session.merge(weakness)

        if (i + 1) % 100 == 0:
            logger.info(f"Synced {i + 1}/{len(weaknesses)} weaknesses")

    return len(weaknesses)


async def sync_external_mappings(
    session: Any,
    weaknesses: list[dict[str, Any]],
) -> int:
    """Sync CWE external mappings (OWASP, SANS, etc.) to database.

    Args:
        session: Database session
        weaknesses: List of parsed weakness data with taxonomy_mappings

    Returns:
        Number of external mappings synced
    """
    logger.info("Syncing external mappings")

    mapping_count = 0

    for weakness_data in weaknesses:
        cwe_id = weakness_data.get("cwe_id")
        taxonomy_mappings = weakness_data.get("taxonomy_mappings", [])

        if not cwe_id or not taxonomy_mappings:
            continue

        for mapping_data in taxonomy_mappings:
            parsed = parse_external_mapping(cwe_id, mapping_data)
            if not parsed:
                continue

            # Map to CWEExternalMapping model
            mapping = CWEExternalMapping(
                weakness_id=parsed["weakness_id"],
                external_source=parsed["taxonomy_name"],
                external_id=parsed.get("entry_id") or "",
                mapping_type=parsed.get("framework_type"),
                rationale=parsed.get("entry_name"),
            )
            await session.merge(mapping)
            mapping_count += 1

        if mapping_count > 0 and mapping_count % 100 == 0:
            logger.info(f"Synced {mapping_count} external mappings")

    logger.info(f"Synced {mapping_count} external mappings total")
    return mapping_count


async def update_capec_cwe_links(session: Any) -> int:
    """Build reverse mapping from CAPEC.related_weaknesses to CWE.related_attack_patterns.

    This function queries CAPEC patterns that have related_weaknesses and builds
    a reverse mapping to update the CWE weaknesses with their related CAPEC patterns.

    Args:
        session: Database session

    Returns:
        Number of CWE weaknesses updated with CAPEC links
    """
    logger.info("Building CAPEC -> CWE reverse mappings")

    try:
        from sqlalchemy import select

        from cve_mcp.models.capec import CAPECPattern
    except ImportError:
        logger.warning("CAPEC models not available, skipping CAPEC-CWE link update")
        return 0

    # Query all CAPEC patterns with related_weaknesses
    result = await session.execute(
        select(CAPECPattern.pattern_id, CAPECPattern.related_weaknesses).where(
            CAPECPattern.related_weaknesses.isnot(None)
        )
    )
    capec_patterns = result.fetchall()

    if not capec_patterns:
        logger.info("No CAPEC patterns with related weaknesses found")
        return 0

    # Build reverse mapping: CWE ID -> [CAPEC IDs]
    cwe_to_capec: dict[str, list[str]] = defaultdict(list)

    for pattern_id, related_weaknesses in capec_patterns:
        if related_weaknesses:
            for cwe_id in related_weaknesses:
                cwe_to_capec[cwe_id].append(pattern_id)

    logger.info(f"Found {len(cwe_to_capec)} CWE weaknesses with CAPEC links")

    # Update CWE weaknesses with related_attack_patterns
    updated_count = 0

    for cwe_id, capec_ids in cwe_to_capec.items():
        result = await session.execute(
            select(CWEWeakness).where(CWEWeakness.cwe_id == cwe_id)
        )
        weakness = result.scalar_one_or_none()

        if weakness:
            weakness.related_attack_patterns = capec_ids
            await session.merge(weakness)
            updated_count += 1

            if updated_count % 100 == 0:
                logger.info(f"Updated {updated_count} CWE weaknesses with CAPEC links")

    logger.info(f"Updated {updated_count} CWE weaknesses with CAPEC links total")
    return updated_count


async def sync_cwe_full(
    cache_dir: Path | None = None,
    force_download: bool = False,
    generate_embeddings: bool = True,
) -> dict[str, int]:
    """Full CWE data sync with semantic embeddings.

    Downloads CWE XML from MITRE, parses all data types,
    generates embeddings, and imports into database.

    Args:
        cache_dir: Directory to cache CWE XML (default: ~/.cache/cve-mcp/cwe)
        force_download: Force re-download even if cached
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Statistics for imported objects
    """
    if cache_dir is None:
        cache_dir = CWE_CACHE_DIR

    logger.info("Starting CWE data sync")
    logger.info(f"Embeddings: {'enabled' if generate_embeddings else 'disabled'}")

    start_time = datetime.utcnow()
    error_message = None
    stats: dict[str, int] = {}

    try:
        # Download CWE data
        xml_content = await download_cwe_data(cache_dir, force_download)

        # Parse XML
        parsed_data = parse_cwe_xml(xml_content)

        # Import into database
        async with get_task_session() as session:
            # Sync views first (they are referenced by categories)
            views_count = await sync_views(session, parsed_data["views"])

            # Sync categories (they reference views)
            categories_count = await sync_categories(session, parsed_data["categories"])

            # Sync weaknesses with embeddings (before memberships to ensure FKs exist)
            weaknesses_count = await sync_weaknesses(
                session,
                parsed_data["weaknesses"],
                generate_embeddings,
            )

            # Sync category memberships (after weaknesses exist for FK constraints)
            memberships_count = await sync_category_memberships(
                session, parsed_data["categories"], parsed_data["views"]
            )

            # Sync external mappings from weakness taxonomy data
            mappings_count = await sync_external_mappings(
                session,
                parsed_data["weaknesses"],
            )

            # Build CAPEC-CWE reverse links
            capec_links_count = await update_capec_cwe_links(session)

            await session.commit()
            logger.info("Committed CWE data to database")

            stats = {
                "views": views_count,
                "categories": categories_count,
                "weaknesses": weaknesses_count,
                "category_memberships": memberships_count,
                "external_mappings": mappings_count,
                "capec_links": capec_links_count,
            }

        # Update sync metadata
        async with get_task_session() as session:
            sync_metadata = SyncMetadata(
                source="cwe",
                last_sync_time=datetime.utcnow(),
                last_sync_status="success",
                records_synced=sum(stats.values()),
                sync_duration_seconds=int(
                    (datetime.utcnow() - start_time).total_seconds()
                ),
            )
            await session.merge(sync_metadata)
            await session.commit()

        logger.info(f"CWE sync complete: {stats}")

    except Exception as e:
        error_message = str(e)
        logger.error(f"CWE sync failed: {error_message}", exc_info=True)

        # Update sync metadata with failure
        try:
            async with get_task_session() as session:
                sync_metadata = SyncMetadata(
                    source="cwe",
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
def sync_cwe(self):
    """Celery task: Sync MITRE CWE software weakness data."""
    try:
        return asyncio.run(sync_cwe_full(generate_embeddings=False))
    except Exception as exc:
        slogger.exception("CWE sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2**self.request.retries))
