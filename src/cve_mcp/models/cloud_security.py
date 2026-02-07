"""Cloud security properties models with quality-first architecture."""

from datetime import datetime
from enum import Enum as PyEnum
from typing import TYPE_CHECKING

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    pass


# ============================================================================
# Enums
# ============================================================================


class CloudProviderEnum(str, PyEnum):
    """Cloud provider identifiers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    MULTI_CLOUD = "multi-cloud"  # For generic patterns


class ServiceCategoryEnum(str, PyEnum):
    """Service categories for equivalency mapping."""

    OBJECT_STORAGE = "object_storage"
    BLOCK_STORAGE = "block_storage"
    FILE_STORAGE = "file_storage"
    COMPUTE = "compute"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    DATABASE_RELATIONAL = "database_relational"
    DATABASE_NOSQL = "database_nosql"
    DATABASE_CACHE = "database_cache"
    NETWORKING_VPC = "networking_vpc"
    NETWORKING_CDN = "networking_cdn"
    NETWORKING_LOAD_BALANCER = "networking_load_balancer"
    IDENTITY_IAM = "identity_iam"
    IDENTITY_DIRECTORY = "identity_directory"
    SECURITY_FIREWALL = "security_firewall"
    SECURITY_WAF = "security_waf"
    LOGGING = "logging"
    MONITORING = "monitoring"
    QUEUE = "queue"
    EVENT_BUS = "event_bus"


class PropertyTypeEnum(str, PyEnum):
    """Security property types for structured organization."""

    ENCRYPTION_AT_REST = "encryption_at_rest"
    ENCRYPTION_IN_TRANSIT = "encryption_in_transit"
    ACCESS_CONTROL = "access_control"
    NETWORK_ISOLATION = "network_isolation"
    AUDIT_LOGGING = "audit_logging"
    THREAT_DETECTION = "threat_detection"
    COMPLIANCE_CERTIFICATION = "compliance_certification"
    SHARED_RESPONSIBILITY = "shared_responsibility"
    SECURITY_DEFAULT = "security_default"
    DATA_RESIDENCY = "data_residency"
    BACKUP_RECOVERY = "backup_recovery"
    INCIDENT_RESPONSE = "incident_response"
    # Added by migration 012 for AWS S3 best practices
    DATA_PROTECTION = "data_protection"
    MONITORING_LOGGING = "monitoring_logging"
    COST_OPTIMIZATION = "cost_optimization"
    RESILIENCE = "resilience"


class VerificationMethodEnum(str, PyEnum):
    """How a property was verified."""

    SCRAPER_ONLY = "scraper_only"
    LLM_ONLY = "llm_only"
    SCRAPER_LLM = "scraper_llm"
    HUMAN_REVIEWED = "human_reviewed"
    ALL_METHODS = "all_methods"  # Scraper + LLM + human


class ChangeSignificanceEnum(str, PyEnum):
    """Significance level for property changes."""

    MAJOR = "major"  # Breaking change, security impact
    MINOR = "minor"  # Feature addition, clarification
    CORRECTION = "correction"  # Bug fix in our data
    REFRESH = "refresh"  # Re-verification without changes


class ResponsibilityLayerEnum(str, PyEnum):
    """Shared responsibility model layers."""

    PHYSICAL = "physical"  # Data center security
    NETWORK = "network"  # Network infrastructure
    HYPERVISOR = "hypervisor"  # Virtualization layer
    OPERATING_SYSTEM = "operating_system"  # OS
    APPLICATION = "application"  # Application layer
    DATA = "data"  # Data classification and encryption
    IDENTITY = "identity"  # Identity and access management
    CLIENT_ENDPOINT = "client_endpoint"  # User device security


class ResponsibilityOwnerEnum(str, PyEnum):
    """Who owns responsibility for a layer."""

    PROVIDER = "provider"  # Cloud provider's responsibility
    CUSTOMER = "customer"  # Customer's responsibility
    SHARED = "shared"  # Joint responsibility


# ============================================================================
# Core Tables
# ============================================================================


class CloudProvider(Base):
    """Cloud provider registry."""

    __tablename__ = "cloud_providers"

    provider_id: Mapped[str] = mapped_column(
        Enum(CloudProviderEnum, name="cloud_provider_enum", values_callable=lambda e: [e.value for e in e]),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text())
    homepage_url: Mapped[str | None] = mapped_column(String(500))
    security_doc_url: Mapped[str | None] = mapped_column(String(500))
    compliance_doc_url: Mapped[str | None] = mapped_column(String(500))

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    # Relationships
    services: Mapped[list["CloudService"]] = relationship(
        "CloudService", back_populates="provider"
    )


class CloudService(Base):
    """Cloud services with equivalency tracking."""

    __tablename__ = "cloud_services"

    # Primary key: composite provider + service name
    service_id: Mapped[str] = mapped_column(String(100), primary_key=True)  # "aws-s3"

    # Core fields
    provider_id: Mapped[str] = mapped_column(
        Enum(CloudProviderEnum, name="cloud_provider_enum", values_callable=lambda e: [e.value for e in e]),
        ForeignKey("cloud_providers.provider_id", ondelete="CASCADE"),
        nullable=False,
    )
    service_name: Mapped[str] = mapped_column(String(200), nullable=False)  # "S3"
    official_name: Mapped[str] = mapped_column(
        String(300), nullable=False
    )  # "Amazon Simple Storage Service"
    description: Mapped[str | None] = mapped_column(Text())

    # Categorization
    service_category: Mapped[str] = mapped_column(
        Enum(ServiceCategoryEnum, name="service_category_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )

    # Equivalency (JSONB for flexible structure)
    equivalent_services: Mapped[dict | None] = mapped_column(JSONB())
    # Example: {"azure": "blob-storage", "gcp": "cloud-storage"}

    # Documentation
    documentation_url: Mapped[str | None] = mapped_column(String(500))
    security_documentation_url: Mapped[str | None] = mapped_column(String(500))
    api_reference_url: Mapped[str | None] = mapped_column(String(500))

    # Search support
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime())
    description_vector: Mapped[str | None] = mapped_column(TSVECTOR())

    # Metadata
    last_verified: Mapped[datetime] = mapped_column(
        DateTime(), nullable=False
    )  # When we last verified this service exists
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    deprecation_date: Mapped[datetime | None] = mapped_column(DateTime())
    replacement_service_id: Mapped[str | None] = mapped_column(String(100))

    # Relationships
    provider: Mapped["CloudProvider"] = relationship(
        "CloudProvider", back_populates="services"
    )
    properties: Mapped[list["CloudSecurityProperty"]] = relationship(
        "CloudSecurityProperty", back_populates="service"
    )

    __table_args__ = (
        Index("idx_cloud_service_category", "service_category"),
        Index("idx_cloud_service_provider", "provider_id"),
        Index(
            "idx_cloud_service_embedding",
            "embedding",
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        Index("idx_cloud_service_fts", "description_vector", postgresql_using="gin"),
    )


class CloudSecurityProperty(Base):
    """Security properties with full quality metadata and provenance."""

    __tablename__ = "cloud_security_properties"

    property_id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    # Service reference
    service_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Property identification
    property_type: Mapped[str] = mapped_column(
        Enum(PropertyTypeEnum, name="property_type_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )
    property_name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Example: "Default Encryption Algorithm", "TLS Version Requirement"

    # Property value (structured JSON)
    property_value: Mapped[dict] = mapped_column(JSONB(), nullable=False)
    # Example: {"algorithm": "AES-256", "mode": "GCM", "key_length": 256, "enabled_by_default": true}

    # Human-readable summary
    summary: Mapped[str | None] = mapped_column(Text())
    # Example: "S3 uses AES-256 encryption in GCM mode by default since January 5, 2023"

    # Quality metadata - Source provenance
    source_url: Mapped[str] = mapped_column(String(500), nullable=False)
    source_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "api", "json", "yaml", "html"
    source_section: Mapped[str | None] = mapped_column(String(500))
    # Example: "Encryption at Rest > Default Behavior"

    source_quote: Mapped[str] = mapped_column(
        Text(), nullable=False
    )  # Verbatim quote from docs

    # Quality metadata - Verification
    confidence_score: Mapped[float] = mapped_column(
        Float(), nullable=False
    )  # 0.0-1.0
    verification_method: Mapped[str] = mapped_column(
        Enum(VerificationMethodEnum, name="verification_method_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )
    verification_metadata: Mapped[dict | None] = mapped_column(JSONB())
    # Example: {"scraper_version": "1.2", "llm_model": "claude-sonnet-4.5", "human_reviewer": "user@domain"}

    extracted_date: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    last_verified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    # Change tracking
    previous_value: Mapped[dict | None] = mapped_column(JSONB())
    change_significance: Mapped[str | None] = mapped_column(
        Enum(ChangeSignificanceEnum, name="change_significance_enum", values_callable=lambda e: [e.value for e in e])
    )
    breaking_change: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    change_date: Mapped[datetime | None] = mapped_column(DateTime())
    change_notes: Mapped[str | None] = mapped_column(Text())

    # Cross-references
    cis_controls: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)))
    # Example: ["CIS-AWS-3.0/2.1.1", "CIS-AWS-3.0/2.1.4"]

    nist_controls: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)))
    # Example: ["AC-3", "SC-8", "SC-13"]

    compliance_frameworks: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)))
    # Example: ["PCI-DSS-v4", "HIPAA", "FedRAMP-High"]

    # CVE impacts (properties affected by specific CVEs)
    affected_by_cves: Mapped[list[str] | None] = mapped_column(ARRAY(String(50)))

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)

    # Relationships
    service: Mapped["CloudService"] = relationship(
        "CloudService", back_populates="properties"
    )
    change_history: Mapped[list["CloudSecurityPropertyChange"]] = relationship(
        "CloudSecurityPropertyChange", back_populates="property"
    )

    __table_args__ = (
        Index("idx_cloud_property_service", "service_id"),
        Index("idx_cloud_property_type", "property_type"),
        Index("idx_cloud_property_confidence", "confidence_score"),
        Index("idx_cloud_property_cis", "cis_controls", postgresql_using="gin"),
        Index("idx_cloud_property_nist", "nist_controls", postgresql_using="gin"),
        Index("idx_cloud_property_compliance", "compliance_frameworks", postgresql_using="gin"),
        Index("idx_cloud_property_cves", "affected_by_cves", postgresql_using="gin"),
        Index("idx_cloud_property_value", "property_value", postgresql_using="gin"),
    )


class CloudSecurityPropertyChange(Base):
    """Audit log for all property changes over time."""

    __tablename__ = "cloud_security_property_changes"

    change_id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    property_id: Mapped[int] = mapped_column(
        Integer(),
        ForeignKey("cloud_security_properties.property_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Change details
    change_date: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    change_significance: Mapped[str] = mapped_column(
        Enum(ChangeSignificanceEnum, name="change_significance_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )
    breaking_change: Mapped[bool] = mapped_column(Boolean(), nullable=False)

    # Before/after values
    old_value: Mapped[dict | None] = mapped_column(JSONB())
    new_value: Mapped[dict] = mapped_column(JSONB(), nullable=False)

    # Change provenance
    detected_by: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "scheduled_sync", "cve_trigger", "manual_update"
    detection_metadata: Mapped[dict | None] = mapped_column(JSONB())

    # Impact notes
    change_notes: Mapped[str | None] = mapped_column(Text())
    requires_review: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(200))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime())

    # Relationships
    property: Mapped["CloudSecurityProperty"] = relationship(
        "CloudSecurityProperty", back_populates="change_history"
    )

    __table_args__ = (
        Index("idx_cloud_change_property", "property_id"),
        Index("idx_cloud_change_date", "change_date"),
        Index("idx_cloud_change_breaking", "breaking_change"),
        Index("idx_cloud_change_review", "requires_review", "reviewed"),
    )


class CloudServiceEquivalence(Base):
    """Explicit equivalency mappings between cloud services."""

    __tablename__ = "cloud_service_equivalences"

    equivalence_id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    # Service category for this equivalency
    service_category: Mapped[str] = mapped_column(
        Enum(ServiceCategoryEnum, name="service_category_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )

    # Services that are equivalent
    service_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)), nullable=False
    )  # ["aws-s3", "azure-blob-storage", "gcp-cloud-storage"]

    # Comparison metadata
    comparable_dimensions: Mapped[list[str]] = mapped_column(ARRAY(String(100)))
    # Example: ["encryption_at_rest", "access_control", "audit_logging"]

    non_comparable_dimensions: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)))
    # Example: ["pricing", "performance_slas"]

    # Nuances (structured differences that matter)
    nuances: Mapped[dict | None] = mapped_column(JSONB())
    # Example: {"aws-s3": "Supports S3 Object Lock (WORM)", "azure-blob": "Immutable storage with legal hold"}

    comparison_notes: Mapped[str | None] = mapped_column(Text())

    # Confidence in this equivalency
    confidence_score: Mapped[float] = mapped_column(Float(), nullable=False)  # 0.0-1.0

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    last_verified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    __table_args__ = (
        Index("idx_equivalence_category", "service_category"),
        Index("idx_equivalence_services", "service_ids", postgresql_using="gin"),
        UniqueConstraint("service_category", name="uq_service_category"),
    )


class CloudSharedResponsibility(Base):
    """Shared responsibility model boundaries for services."""

    __tablename__ = "cloud_shared_responsibilities"

    responsibility_id: Mapped[int] = mapped_column(
        Integer(), primary_key=True, autoincrement=True
    )

    service_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Layer and ownership
    layer: Mapped[str] = mapped_column(
        Enum(ResponsibilityLayerEnum, name="responsibility_layer_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )
    owner: Mapped[str] = mapped_column(
        Enum(ResponsibilityOwnerEnum, name="responsibility_owner_enum", values_callable=lambda e: [e.value for e in e]),
        nullable=False,
    )

    # Details
    description: Mapped[str] = mapped_column(Text(), nullable=False)
    specifics: Mapped[dict | None] = mapped_column(JSONB())
    # Example for SHARED: {"provider": ["Infrastructure encryption"], "customer": ["Key management"]}

    # Documentation
    source_url: Mapped[str] = mapped_column(String(500), nullable=False)
    source_quote: Mapped[str | None] = mapped_column(Text())

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    modified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    last_verified: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    __table_args__ = (
        Index("idx_responsibility_service", "service_id"),
        Index("idx_responsibility_layer", "layer"),
        Index("idx_responsibility_owner", "owner"),
        UniqueConstraint("service_id", "layer", name="uq_service_layer"),
    )


# ============================================================================
# Cross-Reference Tables
# ============================================================================


class CloudServiceAttackMapping(Base):
    """Maps cloud services to MITRE ATT&CK techniques."""

    __tablename__ = "cloud_service_attack_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    service_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
        nullable=False,
    )
    attack_technique_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relationship details
    relationship_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "mitigates", "detects", "vulnerable_to"
    description: Mapped[str | None] = mapped_column(Text())

    # Source
    source_url: Mapped[str | None] = mapped_column(String(500))

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    __table_args__ = (
        Index("idx_cloud_attack_service", "service_id"),
        Index("idx_cloud_attack_technique", "attack_technique_id"),
        UniqueConstraint(
            "service_id",
            "attack_technique_id",
            "relationship_type",
            name="uq_service_attack_rel",
        ),
    )


class CloudServiceCWEMapping(Base):
    """Maps cloud services to CWE weaknesses."""

    __tablename__ = "cloud_service_cwe_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    service_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
        nullable=False,
    )
    cwe_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relationship details
    relationship_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "mitigates", "vulnerable_to"
    description: Mapped[str | None] = mapped_column(Text())

    # Source
    source_url: Mapped[str | None] = mapped_column(String(500))

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    __table_args__ = (
        Index("idx_cloud_cwe_service", "service_id"),
        Index("idx_cloud_cwe_weakness", "cwe_id"),
        UniqueConstraint(
            "service_id", "cwe_id", "relationship_type", name="uq_service_cwe_rel"
        ),
    )


class CloudServiceCAPECMapping(Base):
    """Maps cloud services to CAPEC attack patterns."""

    __tablename__ = "cloud_service_capec_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    service_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
        nullable=False,
    )
    capec_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("capec_patterns.capec_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relationship details
    relationship_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "mitigates", "vulnerable_to"
    description: Mapped[str | None] = mapped_column(Text())

    # Source
    source_url: Mapped[str | None] = mapped_column(String(500))

    # Metadata
    created: Mapped[datetime] = mapped_column(DateTime(), nullable=False)

    __table_args__ = (
        Index("idx_cloud_capec_service", "service_id"),
        Index("idx_cloud_capec_pattern", "capec_id"),
        UniqueConstraint(
            "service_id", "capec_id", "relationship_type", name="uq_service_capec_rel"
        ),
    )
