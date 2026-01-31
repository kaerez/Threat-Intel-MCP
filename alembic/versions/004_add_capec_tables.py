"""Add MITRE CAPEC tables with pgvector semantic search.

Revision ID: 004
Revises: 003
Create Date: 2026-01-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers
revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add CAPEC tables with vector embeddings."""

    # pgvector and pg_trgm extensions already enabled in 002

    # CAPECPattern - Attack patterns
    op.create_table(
        "capec_patterns",
        sa.Column("pattern_id", sa.String(20), primary_key=True),
        sa.Column("capec_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("abstraction", sa.String(50)),
        sa.Column("status", sa.String(50)),
        sa.Column("parent_of", postgresql.ARRAY(sa.Text())),
        sa.Column("child_of", postgresql.ARRAY(sa.Text())),
        sa.Column("can_precede", postgresql.ARRAY(sa.Text())),
        sa.Column("can_follow", postgresql.ARRAY(sa.Text())),
        sa.Column("peer_of", postgresql.ARRAY(sa.Text())),
        sa.Column("related_attack_patterns", postgresql.ARRAY(sa.Text())),
        sa.Column("related_weaknesses", postgresql.ARRAY(sa.Text())),
        sa.Column("attack_likelihood", sa.String(20)),
        sa.Column("typical_severity", sa.String(20)),
        sa.Column("prerequisites", postgresql.ARRAY(sa.Text())),
        sa.Column("skills_required", postgresql.JSONB()),
        sa.Column("resources_required", sa.Text()),
        sa.Column("execution_flow", postgresql.JSONB()),
        sa.Column("consequences", postgresql.JSONB()),
        sa.Column("mitigations", postgresql.ARRAY(sa.Text())),
        sa.Column("examples", postgresql.ARRAY(sa.Text())),
        sa.Column("references", postgresql.ARRAY(sa.Text())),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), default=False),
        sa.Column("stix_extensions", postgresql.JSONB()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create indexes for capec_patterns
    # Vector similarity index (~550 patterns, lists=100)
    op.execute(
        "CREATE INDEX idx_capec_pattern_embedding ON capec_patterns "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
    )
    op.create_index(
        "idx_capec_pattern_description_fts",
        "capec_patterns",
        ["description_vector"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_capec_pattern_name_trgm",
        "capec_patterns",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.create_index("idx_capec_pattern_abstraction", "capec_patterns", ["abstraction"])
    op.create_index("idx_capec_pattern_likelihood", "capec_patterns", ["attack_likelihood"])
    op.create_index("idx_capec_pattern_severity", "capec_patterns", ["typical_severity"])
    op.create_index(
        "idx_capec_pattern_parent_of",
        "capec_patterns",
        ["parent_of"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_capec_pattern_child_of",
        "capec_patterns",
        ["child_of"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_capec_pattern_attack_patterns",
        "capec_patterns",
        ["related_attack_patterns"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_capec_pattern_weaknesses",
        "capec_patterns",
        ["related_weaknesses"],
        postgresql_using="gin",
    )

    # CAPECCategory - Attack pattern categories
    op.create_table(
        "capec_categories",
        sa.Column("category_id", sa.String(20), primary_key=True),
        sa.Column("capec_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("member_patterns", postgresql.ARRAY(sa.Text())),
        sa.Column("parent_category", sa.String(20)),
        sa.Column("child_categories", postgresql.ARRAY(sa.Text())),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create indexes for capec_categories
    op.create_index(
        "idx_capec_category_members",
        "capec_categories",
        ["member_patterns"],
        postgresql_using="gin",
    )

    # CAPECMitigation - Mitigations/courses of action
    op.create_table(
        "capec_mitigations",
        sa.Column("mitigation_id", sa.String(50), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("effectiveness", sa.String(20)),
        sa.Column("mitigates_patterns", postgresql.ARRAY(sa.Text())),
        sa.Column("implementation_phases", postgresql.ARRAY(sa.Text())),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("stix_extensions", postgresql.JSONB()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create indexes for capec_mitigations
    # Vector similarity index (~300 mitigations, lists=50)
    op.execute(
        "CREATE INDEX idx_capec_mitigation_embedding ON capec_mitigations "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50)"
    )
    op.create_index(
        "idx_capec_mitigation_patterns",
        "capec_mitigations",
        ["mitigates_patterns"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_capec_mitigation_name_trgm",
        "capec_mitigations",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )


def downgrade() -> None:
    """Remove CAPEC tables."""
    op.drop_table("capec_mitigations")
    op.drop_table("capec_categories")
    op.drop_table("capec_patterns")
