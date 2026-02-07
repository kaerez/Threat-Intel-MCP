"""Add cloud security tables with quality-first architecture.

Revision ID: 011
Revises: 010
Create Date: 2026-02-07

"""

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add cloud security tables."""

    # ========================================================================
    # Create Enums
    # ========================================================================

    op.execute(
        "CREATE TYPE cloud_provider_enum AS ENUM ('aws', 'azure', 'gcp', 'multi-cloud')"
    )

    op.execute(
        """
        CREATE TYPE service_category_enum AS ENUM (
            'object_storage', 'block_storage', 'file_storage',
            'compute', 'container', 'serverless',
            'database_relational', 'database_nosql', 'database_cache',
            'networking_vpc', 'networking_cdn', 'networking_load_balancer',
            'identity_iam', 'identity_directory',
            'security_firewall', 'security_waf',
            'logging', 'monitoring',
            'queue', 'event_bus'
        )
        """
    )

    op.execute(
        """
        CREATE TYPE property_type_enum AS ENUM (
            'encryption_at_rest', 'encryption_in_transit',
            'access_control', 'network_isolation',
            'audit_logging', 'threat_detection',
            'compliance_certification', 'shared_responsibility',
            'security_default', 'data_residency',
            'backup_recovery', 'incident_response'
        )
        """
    )

    op.execute(
        """
        CREATE TYPE verification_method_enum AS ENUM (
            'scraper_only', 'llm_only', 'scraper_llm',
            'human_reviewed', 'all_methods'
        )
        """
    )

    op.execute(
        "CREATE TYPE change_significance_enum AS ENUM ('major', 'minor', 'correction', 'refresh')"
    )

    op.execute(
        """
        CREATE TYPE responsibility_layer_enum AS ENUM (
            'physical', 'network', 'hypervisor', 'operating_system',
            'application', 'data', 'identity', 'client_endpoint'
        )
        """
    )

    op.execute(
        "CREATE TYPE responsibility_owner_enum AS ENUM ('provider', 'customer', 'shared')"
    )

    # ========================================================================
    # Create Tables
    # ========================================================================

    # CloudProvider
    op.create_table(
        "cloud_providers",
        sa.Column("provider_id", sa.Enum(name="cloud_provider_enum"), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("homepage_url", sa.String(500)),
        sa.Column("security_doc_url", sa.String(500)),
        sa.Column("compliance_doc_url", sa.String(500)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
    )

    # CloudService
    op.create_table(
        "cloud_services",
        sa.Column("service_id", sa.String(100), primary_key=True),
        sa.Column(
            "provider_id",
            sa.Enum(name="cloud_provider_enum"),
            sa.ForeignKey("cloud_providers.provider_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("service_name", sa.String(200), nullable=False),
        sa.Column("official_name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("service_category", sa.Enum(name="service_category_enum"), nullable=False),
        sa.Column("equivalent_services", postgresql.JSONB()),
        sa.Column("documentation_url", sa.String(500)),
        sa.Column("security_documentation_url", sa.String(500)),
        sa.Column("api_reference_url", sa.String(500)),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("last_verified", sa.DateTime(), nullable=False),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("deprecation_date", sa.DateTime()),
        sa.Column("replacement_service_id", sa.String(100)),
    )

    # CloudSecurityProperty
    op.create_table(
        "cloud_security_properties",
        sa.Column("property_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "service_id",
            sa.String(100),
            sa.ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("property_type", sa.Enum(name="property_type_enum"), nullable=False),
        sa.Column("property_name", sa.String(200), nullable=False),
        sa.Column("property_value", postgresql.JSONB(), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("source_url", sa.String(500), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("source_section", sa.String(500)),
        sa.Column("source_quote", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column(
            "verification_method",
            sa.Enum(name="verification_method_enum"),
            nullable=False,
        ),
        sa.Column("verification_metadata", postgresql.JSONB()),
        sa.Column("extracted_date", sa.DateTime(), nullable=False),
        sa.Column("last_verified", sa.DateTime(), nullable=False),
        sa.Column("previous_value", postgresql.JSONB()),
        sa.Column("change_significance", sa.Enum(name="change_significance_enum")),
        sa.Column("breaking_change", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("change_date", sa.DateTime()),
        sa.Column("change_notes", sa.Text()),
        sa.Column("cis_controls", postgresql.ARRAY(sa.String(100))),
        sa.Column("nist_controls", postgresql.ARRAY(sa.String(100))),
        sa.Column("compliance_frameworks", postgresql.ARRAY(sa.String(100))),
        sa.Column("affected_by_cves", postgresql.ARRAY(sa.String(50))),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False, server_default="false"),
    )

    # CloudSecurityPropertyChange
    op.create_table(
        "cloud_security_property_changes",
        sa.Column("change_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "property_id",
            sa.Integer(),
            sa.ForeignKey("cloud_security_properties.property_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("change_date", sa.DateTime(), nullable=False),
        sa.Column(
            "change_significance",
            sa.Enum(name="change_significance_enum"),
            nullable=False,
        ),
        sa.Column("breaking_change", sa.Boolean(), nullable=False),
        sa.Column("old_value", postgresql.JSONB()),
        sa.Column("new_value", postgresql.JSONB(), nullable=False),
        sa.Column("detected_by", sa.String(50), nullable=False),
        sa.Column("detection_metadata", postgresql.JSONB()),
        sa.Column("change_notes", sa.Text()),
        sa.Column("requires_review", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("reviewed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("reviewed_by", sa.String(200)),
        sa.Column("reviewed_at", sa.DateTime()),
    )

    # CloudServiceEquivalence
    op.create_table(
        "cloud_service_equivalences",
        sa.Column("equivalence_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("service_category", sa.Enum(name="service_category_enum"), nullable=False),
        sa.Column("service_ids", postgresql.ARRAY(sa.String(100)), nullable=False),
        sa.Column("comparable_dimensions", postgresql.ARRAY(sa.String(100))),
        sa.Column("non_comparable_dimensions", postgresql.ARRAY(sa.String(100))),
        sa.Column("nuances", postgresql.JSONB()),
        sa.Column("comparison_notes", sa.Text()),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("last_verified", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("service_category", name="uq_service_category"),
    )

    # CloudSharedResponsibility
    op.create_table(
        "cloud_shared_responsibilities",
        sa.Column("responsibility_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "service_id",
            sa.String(100),
            sa.ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("layer", sa.Enum(name="responsibility_layer_enum"), nullable=False),
        sa.Column("owner", sa.Enum(name="responsibility_owner_enum"), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("specifics", postgresql.JSONB()),
        sa.Column("source_url", sa.String(500), nullable=False),
        sa.Column("source_quote", sa.Text()),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("last_verified", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("service_id", "layer", name="uq_service_layer"),
    )

    # CloudServiceAttackMapping
    op.create_table(
        "cloud_service_attack_mappings",
        sa.Column("mapping_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "service_id",
            sa.String(100),
            sa.ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "attack_technique_id",
            sa.String(50),
            sa.ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source_url", sa.String(500)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "service_id",
            "attack_technique_id",
            "relationship_type",
            name="uq_service_attack_rel",
        ),
    )

    # CloudServiceCWEMapping
    op.create_table(
        "cloud_service_cwe_mappings",
        sa.Column("mapping_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "service_id",
            sa.String(100),
            sa.ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cwe_id",
            sa.String(50),
            sa.ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source_url", sa.String(500)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "service_id", "cwe_id", "relationship_type", name="uq_service_cwe_rel"
        ),
    )

    # CloudServiceCAPECMapping
    op.create_table(
        "cloud_service_capec_mappings",
        sa.Column("mapping_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "service_id",
            sa.String(100),
            sa.ForeignKey("cloud_services.service_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "capec_id",
            sa.String(50),
            sa.ForeignKey("capec_patterns.capec_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source_url", sa.String(500)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "service_id", "capec_id", "relationship_type", name="uq_service_capec_rel"
        ),
    )

    # ========================================================================
    # Create Indexes
    # ========================================================================

    # CloudService indexes
    op.create_index(
        "idx_cloud_service_category",
        "cloud_services",
        ["service_category"],
    )
    op.create_index(
        "idx_cloud_service_provider",
        "cloud_services",
        ["provider_id"],
    )
    op.execute(
        """
        CREATE INDEX idx_cloud_service_embedding
        ON cloud_services
        USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 100)
        """
    )
    op.create_index(
        "idx_cloud_service_fts",
        "cloud_services",
        ["description_vector"],
        postgresql_using="gin",
    )

    # CloudSecurityProperty indexes
    op.create_index(
        "idx_cloud_property_service",
        "cloud_security_properties",
        ["service_id"],
    )
    op.create_index(
        "idx_cloud_property_type",
        "cloud_security_properties",
        ["property_type"],
    )
    op.create_index(
        "idx_cloud_property_confidence",
        "cloud_security_properties",
        ["confidence_score"],
    )
    op.create_index(
        "idx_cloud_property_cis",
        "cloud_security_properties",
        ["cis_controls"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cloud_property_nist",
        "cloud_security_properties",
        ["nist_controls"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cloud_property_compliance",
        "cloud_security_properties",
        ["compliance_frameworks"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cloud_property_cves",
        "cloud_security_properties",
        ["affected_by_cves"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cloud_property_value",
        "cloud_security_properties",
        ["property_value"],
        postgresql_using="gin",
    )

    # CloudSecurityPropertyChange indexes
    op.create_index(
        "idx_cloud_change_property",
        "cloud_security_property_changes",
        ["property_id"],
    )
    op.create_index(
        "idx_cloud_change_date",
        "cloud_security_property_changes",
        ["change_date"],
    )
    op.create_index(
        "idx_cloud_change_breaking",
        "cloud_security_property_changes",
        ["breaking_change"],
    )
    op.create_index(
        "idx_cloud_change_review",
        "cloud_security_property_changes",
        ["requires_review", "reviewed"],
    )

    # CloudServiceEquivalence indexes
    op.create_index(
        "idx_equivalence_category",
        "cloud_service_equivalences",
        ["service_category"],
    )
    op.create_index(
        "idx_equivalence_services",
        "cloud_service_equivalences",
        ["service_ids"],
        postgresql_using="gin",
    )

    # CloudSharedResponsibility indexes
    op.create_index(
        "idx_responsibility_service",
        "cloud_shared_responsibilities",
        ["service_id"],
    )
    op.create_index(
        "idx_responsibility_layer",
        "cloud_shared_responsibilities",
        ["layer"],
    )
    op.create_index(
        "idx_responsibility_owner",
        "cloud_shared_responsibilities",
        ["owner"],
    )

    # Mapping table indexes (with reverse lookups)
    op.create_index(
        "idx_cloud_attack_service",
        "cloud_service_attack_mappings",
        ["service_id"],
    )
    op.create_index(
        "idx_cloud_attack_technique",
        "cloud_service_attack_mappings",
        ["attack_technique_id"],
    )

    op.create_index(
        "idx_cloud_cwe_service",
        "cloud_service_cwe_mappings",
        ["service_id"],
    )
    op.create_index(
        "idx_cloud_cwe_weakness",
        "cloud_service_cwe_mappings",
        ["cwe_id"],
    )

    op.create_index(
        "idx_cloud_capec_service",
        "cloud_service_capec_mappings",
        ["service_id"],
    )
    op.create_index(
        "idx_cloud_capec_pattern",
        "cloud_service_capec_mappings",
        ["capec_id"],
    )

    # ========================================================================
    # Create TSVECTOR Trigger (CRITICAL for full-text search)
    # ========================================================================

    op.execute(
        """
        CREATE TRIGGER tsvector_update_cloud_services
        BEFORE INSERT OR UPDATE ON cloud_services
        FOR EACH ROW
        EXECUTE FUNCTION tsvector_update_trigger(
            description_vector, 'pg_catalog.english', description
        )
        """
    )


def downgrade() -> None:
    """Remove cloud security tables."""

    # Drop trigger
    op.execute("DROP TRIGGER IF EXISTS tsvector_update_cloud_services ON cloud_services")

    # Drop tables (in reverse order due to foreign keys)
    op.drop_table("cloud_service_capec_mappings")
    op.drop_table("cloud_service_cwe_mappings")
    op.drop_table("cloud_service_attack_mappings")
    op.drop_table("cloud_shared_responsibilities")
    op.drop_table("cloud_service_equivalences")
    op.drop_table("cloud_security_property_changes")
    op.drop_table("cloud_security_properties")
    op.drop_table("cloud_services")
    op.drop_table("cloud_providers")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS responsibility_owner_enum")
    op.execute("DROP TYPE IF EXISTS responsibility_layer_enum")
    op.execute("DROP TYPE IF EXISTS change_significance_enum")
    op.execute("DROP TYPE IF EXISTS verification_method_enum")
    op.execute("DROP TYPE IF EXISTS property_type_enum")
    op.execute("DROP TYPE IF EXISTS service_category_enum")
    op.execute("DROP TYPE IF EXISTS cloud_provider_enum")
