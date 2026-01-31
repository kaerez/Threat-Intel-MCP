"""Add CWE tables with pgvector semantic search.

Revision ID: 005
Revises: 004
Create Date: 2026-01-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers
revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add CWE tables with vector embeddings."""

    # pgvector and pg_trgm extensions already enabled in 002

    # CWEView - View definitions (~10 records)
    op.create_table(
        "cwe_views",
        sa.Column("view_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("view_type", sa.String(50)),
        sa.Column("status", sa.String(20)),
        sa.Column("description", sa.Text()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # CWECategory - Category definitions (~300 records)
    op.create_table(
        "cwe_categories",
        sa.Column("category_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column(
            "view_id",
            sa.String(20),
            sa.ForeignKey("cwe_views.view_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create index for cwe_categories
    op.create_index("idx_cwe_category_view", "cwe_categories", ["view_id"])

    # CWEWeakness - Main weakness table (~900 records)
    op.create_table(
        "cwe_weaknesses",
        sa.Column("cwe_id", sa.String(20), primary_key=True),
        sa.Column("weakness_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("extended_description", sa.Text()),
        sa.Column("abstraction", sa.String(20)),
        sa.Column("status", sa.String(20)),
        sa.Column("common_consequences", postgresql.JSONB()),
        sa.Column("potential_mitigations", postgresql.JSONB()),
        sa.Column("detection_methods", postgresql.JSONB()),
        sa.Column("likelihood_of_exploit", sa.String(20)),
        sa.Column("parent_of", postgresql.ARRAY(sa.Text())),
        sa.Column("child_of", postgresql.ARRAY(sa.Text())),
        sa.Column("peer_of", postgresql.ARRAY(sa.Text())),
        sa.Column("can_precede", postgresql.ARRAY(sa.Text())),
        sa.Column("can_follow", postgresql.ARRAY(sa.Text())),
        sa.Column("related_attack_patterns", postgresql.ARRAY(sa.Text())),
        sa.Column("created", sa.DateTime()),
        sa.Column("modified", sa.DateTime()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("cwe_version", sa.String(20)),
        sa.Column("deprecated", sa.Boolean(), default=False),
    )

    # Create indexes for cwe_weaknesses
    # Vector similarity index (IVFFlat with cosine distance, ~900 weaknesses, lists=100)
    op.execute(
        "CREATE INDEX idx_cwe_weakness_embedding ON cwe_weaknesses "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
    )

    # GIN indexes for hierarchical relationships
    op.create_index(
        "idx_cwe_parent_of",
        "cwe_weaknesses",
        ["parent_of"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cwe_child_of",
        "cwe_weaknesses",
        ["child_of"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_cwe_peer_of",
        "cwe_weaknesses",
        ["peer_of"],
        postgresql_using="gin",
    )

    # GIN index for CAPEC cross-framework queries
    op.create_index(
        "idx_cwe_related_capec",
        "cwe_weaknesses",
        ["related_attack_patterns"],
        postgresql_using="gin",
    )

    # B-tree indexes for fast lookups
    op.create_index("idx_cwe_weakness_id", "cwe_weaknesses", ["weakness_id"])
    op.create_index("idx_cwe_abstraction", "cwe_weaknesses", ["abstraction"])

    # CWEWeaknessCategory - Join table with view tracking
    op.create_table(
        "cwe_weakness_categories",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "weakness_id",
            sa.String(20),
            sa.ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "category_id",
            sa.String(20),
            sa.ForeignKey("cwe_categories.category_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "view_id",
            sa.String(20),
            sa.ForeignKey("cwe_views.view_id", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    # Create indexes for cwe_weakness_categories
    op.create_index("idx_cwe_wc_weakness", "cwe_weakness_categories", ["weakness_id"])
    op.create_index("idx_cwe_wc_category", "cwe_weakness_categories", ["category_id"])
    op.create_index("idx_cwe_wc_view", "cwe_weakness_categories", ["view_id"])
    op.create_index(
        "idx_cwe_wc_unique",
        "cwe_weakness_categories",
        ["weakness_id", "category_id", "view_id"],
        unique=True,
    )

    # CWEExternalMapping - OWASP/SANS mappings
    op.create_table(
        "cwe_external_mappings",
        sa.Column("mapping_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "weakness_id",
            sa.String(20),
            sa.ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_source", sa.String(100), nullable=False),
        sa.Column("external_id", sa.String(100), nullable=False),
        sa.Column("mapping_type", sa.String(50)),
        sa.Column("rationale", sa.Text()),
    )

    # Create indexes for cwe_external_mappings
    op.create_index("idx_cwe_ext_weakness", "cwe_external_mappings", ["weakness_id"])
    # Composite index for external_source + external_id lookups
    op.create_index(
        "idx_cwe_ext_source_id",
        "cwe_external_mappings",
        ["external_source", "external_id"],
    )


def downgrade() -> None:
    """Remove CWE tables."""
    op.drop_table("cwe_external_mappings")
    op.drop_table("cwe_weakness_categories")
    op.drop_table("cwe_weaknesses")
    op.drop_table("cwe_categories")
    op.drop_table("cwe_views")
