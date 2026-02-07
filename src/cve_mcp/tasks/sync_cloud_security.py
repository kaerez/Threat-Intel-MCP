"""Sync tasks for cloud security properties with quality gates."""

import asyncio
from datetime import datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.ingest.cloud_security_parser import (
    parse_aws_config_rule,
    parse_aws_security_hub_control,
    parse_azure_arm_property,
    parse_azure_policy_definition,
    parse_cloud_service,
    parse_gcp_org_policy_constraint,
)
from cve_mcp.models.base import get_task_session
from cve_mcp.models.cloud_security import (
    CloudProvider,
    CloudSecurityProperty,
    CloudSecurityPropertyChange,
    CloudService,
    CloudServiceEquivalence,
)
from cve_mcp.models.metadata import SyncMetadata
from cve_mcp.tasks.celery_app import celery_app

logger = structlog.get_logger(__name__)
slogger = structlog.stdlib.get_logger(__name__)


# ============================================================================
# Quality Gates
# ============================================================================


def passes_quality_gates(property_data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Apply quality gates to a parsed property.

    Args:
        property_data: Parsed property dict from parser

    Returns:
        Tuple of (passes: bool, failures: list[str])
    """
    failures = []

    # Gate 1: Has source quote
    if not property_data.get("source_quote"):
        failures.append("Missing source_quote")

    # Gate 2: Has source URL
    source_url = property_data.get("source_url")
    if not source_url:
        failures.append("Missing source_url")

    # Gate 3: Confidence threshold
    confidence = property_data.get("confidence_score", 0.0)
    if confidence < 0.70:
        failures.append(f"Confidence too low: {confidence:.2f} < 0.70")

    # Gate 4: Has property value
    if not property_data.get("property_value"):
        failures.append("Missing property_value")

    # Gate 5: Has property name
    if not property_data.get("property_name"):
        failures.append("Missing property_name")

    return (len(failures) == 0, failures)


async def verify_source_accessible(url: str, timeout: float = 10.0) -> bool:
    """
    Verify that a source URL is accessible.

    Args:
        url: URL to check
        timeout: Request timeout in seconds

    Returns:
        True if URL returns 200, False otherwise
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.head(url)
            return response.status_code == 200
    except Exception:
        # Don't fail on connectivity issues, just log
        return False


# ============================================================================
# AWS Sync Functions
# ============================================================================


async def sync_aws_s3_security(
    session: AsyncSession,
    generate_embeddings: bool = False,
    verbose: bool = False,
) -> dict[str, int]:
    """
    Sync AWS S3 security properties from authoritative sources.

    This would typically fetch from:
    - AWS Security Hub ListSecurityControlDefinitions API
    - AWS Config DescribeConfigRules API
    - AWS Config conformance pack templates

    For now, this is a placeholder that initializes the service.

    Args:
        session: Database session
        generate_embeddings: Whether to generate vector embeddings
        verbose: Enable verbose logging

    Returns:
        Dict with sync statistics
    """
    start_time = datetime.utcnow()
    stats: dict[str, int] = {
        "services_synced": 0,
        "properties_synced": 0,
        "properties_updated": 0,
        "properties_failed_quality": 0,
        "changes_detected": 0,
    }

    try:
        logger.info("sync_aws_s3_security.started")

        # Step 1: Ensure provider exists
        await _ensure_provider_exists(session, "aws")

        # Step 2: Ensure S3 service exists
        s3_service = parse_cloud_service(
            provider="aws",
            service_name="S3",
            official_name="Amazon Simple Storage Service",
            service_category="object_storage",
            description="Object storage service with high scalability, data availability, security, and performance",
            documentation_url="https://docs.aws.amazon.com/s3/",
        )

        await _upsert_service(session, s3_service)
        stats["services_synced"] += 1

        # Step 3: Fetch Security Hub controls for S3
        # NOTE: In production, this would call AWS API:
        # controls = await fetch_aws_security_hub_controls("s3")
        # For now, we'll use sample data structure

        sample_controls = await _get_aws_s3_sample_controls()

        for control_data in sample_controls:
            parsed = parse_aws_security_hub_control(control_data)
            if not parsed:
                continue

            # Apply quality gates
            passes, failures = passes_quality_gates(parsed)
            if not passes:
                logger.warning(
                    "property_failed_quality_gates",
                    service="aws-s3",
                    property=parsed.get("property_name"),
                    failures=failures,
                )
                stats["properties_failed_quality"] += 1
                continue

            # Add service_id
            parsed["service_id"] = "aws-s3"

            # Check for changes and upsert
            change_detected = await _upsert_property_with_change_detection(
                session, parsed, verbose=verbose
            )

            if change_detected:
                stats["changes_detected"] += 1
                stats["properties_updated"] += 1
            else:
                stats["properties_synced"] += 1

        await session.commit()

        # Step 4: Update sync metadata
        await _update_sync_metadata(
            session,
            source="cloud_security_aws_s3",
            status="success",
            records=stats["properties_synced"] + stats["properties_updated"],
            duration=(datetime.utcnow() - start_time).total_seconds(),
        )

        logger.info("sync_aws_s3_security.completed", stats=stats)
        return stats

    except Exception as e:
        logger.error("sync_aws_s3_security.failed", error=str(e), exc_info=True)
        await session.rollback()

        await _update_sync_metadata(
            session,
            source="cloud_security_aws_s3",
            status="failed",
            error_message=str(e),
        )

        raise


async def _get_aws_s3_sample_controls() -> list[dict[str, Any]]:
    """
    Get sample AWS Security Hub controls for S3.

    In production, this would fetch from AWS API.
    """
    return [
        {
            "SecurityControlId": "S3.1",
            "Title": "S3 Block Public Access setting should be enabled",
            "Description": "This control checks whether S3 Block Public Access settings are enabled at the account level. The control fails if Block Public Access settings are not enabled.",
            "SeverityRating": "MEDIUM",
            "ControlStatus": "ENABLED",
            "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
            "SecurityControlStandardsDefinitions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "ControlId": "S3.1",
                },
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0",
                    "ControlId": "2.1.4",
                },
            ],
        },
        {
            "SecurityControlId": "S3.5",
            "Title": "S3 buckets should require requests to use SSL",
            "Description": "This control checks whether S3 buckets have policies that require requests to use SSL (HTTPS). The control fails if the bucket policy does not require SSL.",
            "SeverityRating": "MEDIUM",
            "ControlStatus": "ENABLED",
            "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.5/remediation",
            "SecurityControlStandardsDefinitions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "ControlId": "S3.5",
                },
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/nist-800-53/v/5.0.0",
                    "ControlId": "SC-8",
                },
            ],
        },
        {
            "SecurityControlId": "S3.17",
            "Title": "S3 buckets should be encrypted at rest with AWS KMS keys",
            "Description": "This control checks whether S3 buckets are encrypted at rest with AWS KMS keys. The control fails if the bucket is not encrypted with KMS.",
            "SeverityRating": "MEDIUM",
            "ControlStatus": "ENABLED",
            "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.17/remediation",
            "SecurityControlStandardsDefinitions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "ControlId": "S3.17",
                },
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/nist-800-53/v/5.0.0",
                    "ControlId": "SC-13",
                },
            ],
        },
    ]


# ============================================================================
# Azure Sync Functions
# ============================================================================


async def sync_azure_blob_security(
    session: AsyncSession,
    generate_embeddings: bool = False,
    verbose: bool = False,
) -> dict[str, int]:
    """
    Sync Azure Blob Storage security properties.

    This would fetch from:
    - Azure ARM API schema
    - Azure Policy built-in definitions
    - Azure Security Baseline

    Args:
        session: Database session
        generate_embeddings: Whether to generate vector embeddings
        verbose: Enable verbose logging

    Returns:
        Dict with sync statistics
    """
    start_time = datetime.utcnow()
    stats: dict[str, int] = {
        "services_synced": 0,
        "properties_synced": 0,
        "properties_updated": 0,
        "properties_failed_quality": 0,
        "changes_detected": 0,
    }

    try:
        logger.info("sync_azure_blob_security.started")

        # Ensure provider exists
        await _ensure_provider_exists(session, "azure")

        # Ensure Blob Storage service exists
        blob_service = parse_cloud_service(
            provider="azure",
            service_name="Blob Storage",
            official_name="Azure Blob Storage",
            service_category="object_storage",
            description="Massively scalable object storage for unstructured data",
            documentation_url="https://learn.microsoft.com/en-us/azure/storage/blobs/",
        )

        await _upsert_service(session, blob_service)
        stats["services_synced"] += 1

        # Fetch Azure Policy definitions
        # In production: fetch from GitHub or Azure API
        sample_policies = await _get_azure_blob_sample_policies()

        for policy_data in sample_policies:
            parsed = parse_azure_policy_definition(policy_data)
            if not parsed:
                continue

            passes, failures = passes_quality_gates(parsed)
            if not passes:
                logger.warning(
                    "property_failed_quality_gates",
                    service="azure-blob-storage",
                    property=parsed.get("property_name"),
                    failures=failures,
                )
                stats["properties_failed_quality"] += 1
                continue

            parsed["service_id"] = "azure-blob-storage"

            change_detected = await _upsert_property_with_change_detection(
                session, parsed, verbose=verbose
            )

            if change_detected:
                stats["changes_detected"] += 1
                stats["properties_updated"] += 1
            else:
                stats["properties_synced"] += 1

        await session.commit()

        await _update_sync_metadata(
            session,
            source="cloud_security_azure_blob",
            status="success",
            records=stats["properties_synced"] + stats["properties_updated"],
            duration=(datetime.utcnow() - start_time).total_seconds(),
        )

        logger.info("sync_azure_blob_security.completed", stats=stats)
        return stats

    except Exception as e:
        logger.error("sync_azure_blob_security.failed", error=str(e), exc_info=True)
        await session.rollback()

        await _update_sync_metadata(
            session,
            source="cloud_security_azure_blob",
            status="failed",
            error_message=str(e),
        )

        raise


async def _get_azure_blob_sample_policies() -> list[dict[str, Any]]:
    """Get sample Azure Policy definitions for Blob Storage."""
    return [
        {
            "id": "/providers/Microsoft.Authorization/policyDefinitions/secure-transfer",
            "properties": {
                "name": "secure-transfer-required",
                "displayName": "Secure transfer to storage accounts should be enabled",
                "description": "Audit requirement of Secure transfer in your storage account. Secure transfer is an option that forces your storage account to accept requests only from secure connections (HTTPS). Use of HTTPS ensures authentication between the server and the service and protects data in transit from network layer attacks.",
                "policyType": "BuiltIn",
                "mode": "All",
                "metadata": {
                    "category": "Storage",
                    "ASC": "true",
                },
                "policyRule": {
                    "if": {
                        "allOf": [
                            {
                                "field": "type",
                                "equals": "Microsoft.Storage/storageAccounts",
                            },
                            {
                                "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
                                "notEquals": "true",
                            },
                        ]
                    },
                    "then": {"effect": "Audit"},
                },
            },
        },
        {
            "id": "/providers/Microsoft.Authorization/policyDefinitions/infrastructure-encryption",
            "properties": {
                "name": "infrastructure-encryption-required",
                "displayName": "Storage accounts should have infrastructure encryption",
                "description": "Enable infrastructure encryption for higher level of assurance that the data is secure. When infrastructure encryption is enabled, data in a storage account is encrypted twice.",
                "policyType": "BuiltIn",
                "mode": "All",
                "metadata": {
                    "category": "Storage",
                    "CIS": "true",
                },
                "policyRule": {
                    "if": {
                        "allOf": [
                            {
                                "field": "type",
                                "equals": "Microsoft.Storage/storageAccounts",
                            },
                            {
                                "field": "Microsoft.Storage/storageAccounts/encryption.requireInfrastructureEncryption",
                                "notEquals": "true",
                            },
                        ]
                    },
                    "then": {"effect": "Audit"},
                },
            },
        },
    ]


# ============================================================================
# GCP Sync Functions
# ============================================================================


async def sync_gcp_storage_security(
    session: AsyncSession,
    generate_embeddings: bool = False,
    verbose: bool = False,
) -> dict[str, int]:
    """
    Sync GCP Cloud Storage security properties.

    This would fetch from:
    - GCP Organization Policy constraints
    - Security Command Center recommendations
    - Cloud Asset Inventory

    Args:
        session: Database session
        generate_embeddings: Whether to generate vector embeddings
        verbose: Enable verbose logging

    Returns:
        Dict with sync statistics
    """
    start_time = datetime.utcnow()
    stats: dict[str, int] = {
        "services_synced": 0,
        "properties_synced": 0,
        "properties_updated": 0,
        "properties_failed_quality": 0,
        "changes_detected": 0,
    }

    try:
        logger.info("sync_gcp_storage_security.started")

        # Ensure provider exists
        await _ensure_provider_exists(session, "gcp")

        # Ensure Cloud Storage service exists
        storage_service = parse_cloud_service(
            provider="gcp",
            service_name="Cloud Storage",
            official_name="Google Cloud Storage",
            service_category="object_storage",
            description="Unified object storage for developers and enterprises",
            documentation_url="https://cloud.google.com/storage/docs",
        )

        await _upsert_service(session, storage_service)
        stats["services_synced"] += 1

        # Fetch Org Policy constraints
        # In production: fetch from GCP API
        sample_constraints = await _get_gcp_storage_sample_constraints()

        for constraint_data in sample_constraints:
            parsed = parse_gcp_org_policy_constraint(constraint_data)
            if not parsed:
                continue

            passes, failures = passes_quality_gates(parsed)
            if not passes:
                logger.warning(
                    "property_failed_quality_gates",
                    service="gcp-cloud-storage",
                    property=parsed.get("property_name"),
                    failures=failures,
                )
                stats["properties_failed_quality"] += 1
                continue

            parsed["service_id"] = "gcp-cloud-storage"

            change_detected = await _upsert_property_with_change_detection(
                session, parsed, verbose=verbose
            )

            if change_detected:
                stats["changes_detected"] += 1
                stats["properties_updated"] += 1
            else:
                stats["properties_synced"] += 1

        await session.commit()

        await _update_sync_metadata(
            session,
            source="cloud_security_gcp_storage",
            status="success",
            records=stats["properties_synced"] + stats["properties_updated"],
            duration=(datetime.utcnow() - start_time).total_seconds(),
        )

        logger.info("sync_gcp_storage_security.completed", stats=stats)
        return stats

    except Exception as e:
        logger.error("sync_gcp_storage_security.failed", error=str(e), exc_info=True)
        await session.rollback()

        await _update_sync_metadata(
            session,
            source="cloud_security_gcp_storage",
            status="failed",
            error_message=str(e),
        )

        raise


async def _get_gcp_storage_sample_constraints() -> list[dict[str, Any]]:
    """Get sample GCP Organization Policy constraints for Cloud Storage."""
    return [
        {
            "name": "constraints/storage.publicAccessPrevention",
            "displayName": "Enforce public access prevention",
            "description": "This organization policy constraint enforces public access prevention on Cloud Storage buckets. When enforced, buckets cannot be made publicly accessible.",
            "constraintType": "BOOLEAN",
            "booleanConstraint": {},
            "enforcement": "ENFORCEMENT_ENFORCED",
        },
        {
            "name": "constraints/storage.uniformBucketLevelAccess",
            "displayName": "Enforce uniform bucket-level access",
            "description": "This constraint requires uniform bucket-level access to be enabled on Cloud Storage buckets. This disables ACLs for the bucket.",
            "constraintType": "BOOLEAN",
            "booleanConstraint": {},
            "enforcement": "ENFORCEMENT_ENFORCED",
        },
        {
            "name": "constraints/gcp.restrictNonCmekServices",
            "displayName": "Restrict which services may create resources without CMEK",
            "description": "This list constraint defines the set of Google Cloud services that can be used without customer-managed encryption keys (CMEK).",
            "constraintType": "LIST",
            "listConstraint": {
                "supportsIn": True,
                "supportsUnder": False,
            },
        },
    ]


# ============================================================================
# Service Equivalence Sync
# ============================================================================


async def sync_service_equivalences(
    session: AsyncSession,
    verbose: bool = False,
) -> dict[str, int]:
    """
    Sync cross-provider service equivalencies.

    Args:
        session: Database session
        verbose: Enable verbose logging

    Returns:
        Dict with sync statistics
    """
    stats: dict[str, int] = {"equivalences_synced": 0}

    try:
        logger.info("sync_service_equivalences.started")

        # Object Storage equivalence
        object_storage_equiv = {
            "service_category": "object_storage",
            "service_ids": ["aws-s3", "azure-blob-storage", "gcp-cloud-storage"],
            "comparable_dimensions": [
                "encryption_at_rest",
                "encryption_in_transit",
                "access_control",
                "audit_logging",
                "network_isolation",
            ],
            "non_comparable_dimensions": ["pricing", "performance_slas"],
            "nuances": {
                "aws-s3": "Supports S3 Object Lock (WORM compliance mode) and S3 Glacier for archival",
                "azure-blob-storage": "Immutable storage with time-based retention and legal hold policies",
                "gcp-cloud-storage": "Retention policies with bucket lock, but not true WORM until locked",
            },
            "comparison_notes": "All three provide comparable security features for encryption, access control, and logging. Key difference is in data immutability: AWS S3 Object Lock provides WORM compliance mode, Azure has immutable storage with legal holds, GCP has retention policies that become immutable when locked.",
            "confidence_score": 0.95,
            "created": datetime.utcnow(),
            "modified": datetime.utcnow(),
            "last_verified": datetime.utcnow(),
        }

        stmt = insert(CloudServiceEquivalence).values(**object_storage_equiv)
        stmt = stmt.on_conflict_do_update(
            index_elements=["service_category"],
            set_={k: stmt.excluded[k] for k in object_storage_equiv.keys() if k != "service_category"},
        )
        await session.execute(stmt)
        stats["equivalences_synced"] += 1

        await session.commit()

        logger.info("sync_service_equivalences.completed", stats=stats)
        return stats

    except Exception as e:
        logger.error("sync_service_equivalences.failed", error=str(e), exc_info=True)
        await session.rollback()
        raise


# ============================================================================
# Helper Functions
# ============================================================================


async def _ensure_provider_exists(session: AsyncSession, provider_id: str) -> None:
    """Ensure a cloud provider exists in the database."""
    provider_data = {
        "aws": {
            "provider_id": "aws",
            "name": "Amazon Web Services",
            "description": "AWS is a comprehensive cloud computing platform",
            "homepage_url": "https://aws.amazon.com",
            "security_doc_url": "https://docs.aws.amazon.com/security/",
            "compliance_doc_url": "https://aws.amazon.com/compliance/",
        },
        "azure": {
            "provider_id": "azure",
            "name": "Microsoft Azure",
            "description": "Azure is Microsoft's cloud computing platform",
            "homepage_url": "https://azure.microsoft.com",
            "security_doc_url": "https://learn.microsoft.com/en-us/azure/security/",
            "compliance_doc_url": "https://learn.microsoft.com/en-us/azure/compliance/",
        },
        "gcp": {
            "provider_id": "gcp",
            "name": "Google Cloud Platform",
            "description": "GCP is Google's cloud computing platform",
            "homepage_url": "https://cloud.google.com",
            "security_doc_url": "https://cloud.google.com/security",
            "compliance_doc_url": "https://cloud.google.com/security/compliance",
        },
    }

    if provider_id not in provider_data:
        raise ValueError(f"Unknown provider: {provider_id}")

    data = provider_data[provider_id]
    data["created"] = datetime.utcnow()
    data["modified"] = datetime.utcnow()

    stmt = insert(CloudProvider).values(**data)
    stmt = stmt.on_conflict_do_nothing(index_elements=["provider_id"])
    await session.execute(stmt)


async def _upsert_service(session: AsyncSession, service_data: dict[str, Any]) -> None:
    """Upsert a cloud service."""
    stmt = insert(CloudService).values(**service_data)
    stmt = stmt.on_conflict_do_update(
        index_elements=["service_id"],
        set_={
            "service_name": stmt.excluded.service_name,
            "official_name": stmt.excluded.official_name,
            "description": stmt.excluded.description,
            "documentation_url": stmt.excluded.documentation_url,
            "last_verified": stmt.excluded.last_verified,
            "modified": stmt.excluded.modified,
        },
    )
    await session.execute(stmt)


async def _upsert_property_with_change_detection(
    session: AsyncSession,
    property_data: dict[str, Any],
    verbose: bool = False,
) -> bool:
    """
    Upsert a property with change detection.

    Returns:
        True if a change was detected, False otherwise
    """
    service_id = property_data["service_id"]
    property_type = property_data["property_type"]
    property_name = property_data["property_name"]

    # Check if property exists
    stmt = select(CloudSecurityProperty).where(
        CloudSecurityProperty.service_id == service_id,
        CloudSecurityProperty.property_type == property_type,
        CloudSecurityProperty.property_name == property_name,
    )
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    change_detected = False

    if existing:
        # Compare property_value to detect changes
        old_value = existing.property_value
        new_value = property_data["property_value"]

        if old_value != new_value:
            change_detected = True

            # Determine change significance
            significance = "minor"  # Default
            breaking = False

            # Check for breaking changes (heuristics)
            if _is_breaking_change(old_value, new_value):
                significance = "major"
                breaking = True

            # Record change
            change_record = {
                "property_id": existing.property_id,
                "change_date": datetime.utcnow(),
                "change_significance": significance,
                "breaking_change": breaking,
                "old_value": old_value,
                "new_value": new_value,
                "detected_by": "scheduled_sync",
                "detection_metadata": {
                    "sync_source": property_data.get("verification_metadata", {}).get("source"),
                },
                "change_notes": None,
                "requires_review": breaking,  # Breaking changes require review
                "reviewed": False,
            }

            await session.execute(insert(CloudSecurityPropertyChange).values(**change_record))

            # Update property with new value
            property_data["previous_value"] = old_value
            property_data["change_significance"] = significance
            property_data["breaking_change"] = breaking
            property_data["change_date"] = datetime.utcnow()

            if verbose:
                logger.info(
                    "property_changed",
                    service=service_id,
                    property=property_name,
                    significance=significance,
                    breaking=breaking,
                )

    # Upsert property
    stmt = insert(CloudSecurityProperty).values(**property_data)
    stmt = stmt.on_conflict_do_update(
        index_elements=["service_id", "property_type", "property_name"],
        set_={k: stmt.excluded[k] for k in property_data.keys() if k not in ["service_id", "property_type", "property_name"]},
    )
    await session.execute(stmt)

    return change_detected


def _is_breaking_change(old_value: dict[str, Any], new_value: dict[str, Any]) -> bool:
    """
    Heuristic to detect breaking changes.

    Breaking changes include:
    - Security feature disabled (was enabled, now disabled)
    - Encryption downgraded
    - Access controls loosened
    """
    # Check for enabled -> disabled transitions
    if old_value.get("enabled_by_default") is True and new_value.get("enabled_by_default") is False:
        return True

    # Check for encryption downgrades
    encryption_strength_order = ["AES-256", "AES-192", "AES-128", "none"]
    old_encryption = old_value.get("algorithm", "")
    new_encryption = new_value.get("algorithm", "")

    if old_encryption in encryption_strength_order and new_encryption in encryption_strength_order:
        if encryption_strength_order.index(new_encryption) > encryption_strength_order.index(old_encryption):
            return True

    return False


async def _update_sync_metadata(
    session: AsyncSession,
    source: str,
    status: str,
    records: int = 0,
    duration: float = 0.0,
    error_message: str | None = None,
) -> None:
    """Update sync metadata table."""
    metadata = SyncMetadata(
        source=source,
        last_sync_time=datetime.utcnow(),
        last_sync_status=status,
        records_synced=records,
        sync_duration_seconds=int(duration),
        error_message=error_message,
    )
    await session.merge(metadata)
    await session.commit()


# ============================================================================
# Celery Tasks
# ============================================================================


@celery_app.task(bind=True, max_retries=2)
def sync_aws_s3_task(self):
    """Celery task: Sync AWS S3 security properties."""

    async def _run():
        async with get_task_session() as session:
            return await sync_aws_s3_security(session, generate_embeddings=False)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        slogger.exception("AWS S3 sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=2)
def sync_azure_blob_task(self):
    """Celery task: Sync Azure Blob Storage security properties."""

    async def _run():
        async with get_task_session() as session:
            return await sync_azure_blob_security(session, generate_embeddings=False)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        slogger.exception("Azure Blob sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=2)
def sync_gcp_storage_task(self):
    """Celery task: Sync GCP Cloud Storage security properties."""

    async def _run():
        async with get_task_session() as session:
            return await sync_gcp_storage_security(session, generate_embeddings=False)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        slogger.exception("GCP Storage sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))


@celery_app.task(bind=True, max_retries=2)
def sync_cloud_service_equivalences_task(self):
    """Celery task: Sync cloud service equivalencies."""

    async def _run():
        async with get_task_session() as session:
            return await sync_service_equivalences(session)

    try:
        return asyncio.run(_run())
    except Exception as exc:
        slogger.exception("Service equivalences sync failed", error=str(exc))
        raise self.retry(exc=exc, countdown=300 * (2 ** self.request.retries))
