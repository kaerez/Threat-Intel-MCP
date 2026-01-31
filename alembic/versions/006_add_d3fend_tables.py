"""Add MITRE D3FEND tables with pgvector semantic search.

Revision ID: 006
Revises: 005
Create Date: 2026-01-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers
revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add D3FEND tables with vector embeddings."""

    # pgvector and pg_trgm extensions already enabled in 002

    # Create enum types for relationship types
    d3fend_relationship_type = postgresql.ENUM(
        "counters",
        "enables",
        "related-to",
        "produces",
        "uses",
        name="d3fend_relationship_type",
        create_type=False,
    )
    d3fend_artifact_relationship_type = postgresql.ENUM(
        "produces",
        "uses",
        "analyzes",
        name="d3fend_artifact_relationship_type",
        create_type=False,
    )

    # Create the enum types explicitly
    op.execute("CREATE TYPE d3fend_relationship_type AS ENUM ('counters', 'enables', 'related-to', 'produces', 'uses')")
    op.execute("CREATE TYPE d3fend_artifact_relationship_type AS ENUM ('produces', 'uses', 'analyzes')")

    # D3FENDTactic - Defensive tactics (~7 records)
    op.create_table(
        "d3fend_tactics",
        sa.Column("tactic_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("display_order", sa.Integer(), nullable=False),
        sa.Column("created", sa.DateTime()),
        sa.Column("modified", sa.DateTime()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # D3FENDTechnique - Defensive techniques (~200 records)
    op.create_table(
        "d3fend_techniques",
        sa.Column("technique_id", sa.String(20), primary_key=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "tactic_id",
            sa.String(20),
            sa.ForeignKey("d3fend_tactics.tactic_id", ondelete="SET NULL"),
        ),
        sa.Column(
            "parent_id",
            sa.String(20),
            sa.ForeignKey("d3fend_techniques.technique_id", ondelete="SET NULL"),
        ),
        sa.Column("synonyms", postgresql.ARRAY(sa.Text())),
        sa.Column("references", postgresql.JSONB()),
        sa.Column("kb_article_url", sa.String(500)),
        sa.Column("created", sa.DateTime()),
        sa.Column("modified", sa.DateTime()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("d3fend_version", sa.String(20)),
        sa.Column("deprecated", sa.Boolean(), default=False),
    )

    # Create indexes for d3fend_techniques
    # HNSW index for small dataset (~200 techniques, m=16, ef_construction=64)
    op.execute(
        "CREATE INDEX idx_d3fend_embedding ON d3fend_techniques "
        "USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
    )

    # B-tree indexes for fast lookups
    op.create_index("idx_d3fend_tactic", "d3fend_techniques", ["tactic_id"])
    op.create_index("idx_d3fend_parent", "d3fend_techniques", ["parent_id"])

    # GIN trigram index for fuzzy name search
    op.create_index(
        "idx_d3fend_name_trgm",
        "d3fend_techniques",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )

    # D3FENDArtifact - Digital artifacts (~100 records)
    op.create_table(
        "d3fend_artifacts",
        sa.Column("artifact_id", sa.String(50), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("artifact_type", sa.String(50)),
    )

    # D3FENDTechniqueAttackMapping - ATT&CK correlation
    op.create_table(
        "d3fend_technique_attack_mappings",
        sa.Column("mapping_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "d3fend_technique_id",
            sa.String(20),
            sa.ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "attack_technique_id",
            sa.String(20),
            sa.ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "relationship_type",
            d3fend_relationship_type,
            nullable=False,
        ),
        sa.UniqueConstraint(
            "d3fend_technique_id",
            "attack_technique_id",
            "relationship_type",
            name="uq_d3fend_attack_mapping",
        ),
    )

    # B-tree index for reverse lookups (find defenses for an attack technique)
    op.create_index(
        "idx_d3fend_attack_mapping",
        "d3fend_technique_attack_mappings",
        ["attack_technique_id"],
    )

    # D3FENDTechniqueArtifact - Join table with composite PK
    op.create_table(
        "d3fend_technique_artifacts",
        sa.Column(
            "technique_id",
            sa.String(20),
            sa.ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "artifact_id",
            sa.String(50),
            sa.ForeignKey("d3fend_artifacts.artifact_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "relationship_type",
            d3fend_artifact_relationship_type,
            primary_key=True,
        ),
    )


def downgrade() -> None:
    """Remove D3FEND tables."""
    op.drop_table("d3fend_technique_artifacts")
    op.drop_table("d3fend_technique_attack_mappings")
    op.drop_table("d3fend_artifacts")
    op.drop_table("d3fend_techniques")
    op.drop_table("d3fend_tactics")

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS d3fend_artifact_relationship_type")
    op.execute("DROP TYPE IF EXISTS d3fend_relationship_type")
