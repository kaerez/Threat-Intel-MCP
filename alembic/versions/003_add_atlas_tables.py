"""Add MITRE ATLAS tables with pgvector semantic search.

Revision ID: 003
Revises: 002
Create Date: 2026-01-31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from pgvector.sqlalchemy import Vector

# revision identifiers
revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add ATLAS tables with vector embeddings."""

    # pgvector and pg_trgm extensions already enabled in 002

    # ATLASTechnique
    op.create_table(
        "atlas_techniques",
        sa.Column("technique_id", sa.String(20), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.Text())),
        sa.Column("ml_lifecycle_stage", sa.String(100)),
        sa.Column("ai_system_type", postgresql.ARRAY(sa.Text())),
        sa.Column("detection", sa.Text()),
        sa.Column("mitigation", sa.Text()),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), default=False),
        sa.Column("revoked", sa.Boolean(), default=False),
        sa.Column("stix_extensions", postgresql.JSONB()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create indexes for atlas_techniques
    op.execute(
        "CREATE INDEX idx_atlas_tech_embedding ON atlas_techniques "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50)"
    )
    op.create_index(
        "idx_atlas_tech_description_fts",
        "atlas_techniques",
        ["description_vector"],
        postgresql_using="gin",
    )
    op.create_index("idx_atlas_tech_tactics", "atlas_techniques", ["tactics"], postgresql_using="gin")
    op.create_index("idx_atlas_tech_lifecycle", "atlas_techniques", ["ml_lifecycle_stage"])
    op.create_index("idx_atlas_tech_ai_type", "atlas_techniques", ["ai_system_type"], postgresql_using="gin")
    op.create_index(
        "idx_atlas_tech_name_trgm",
        "atlas_techniques",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )

    # ATLASTactic
    op.create_table(
        "atlas_tactics",
        sa.Column("tactic_id", sa.String(50), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("shortname", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # ATLASCaseStudy
    op.create_table(
        "atlas_case_studies",
        sa.Column("case_study_id", sa.String(50), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("incident_date", sa.DateTime()),
        sa.Column("techniques_used", postgresql.ARRAY(sa.Text())),
        sa.Column("target_system", sa.String(200)),
        sa.Column("impact", sa.Text()),
        sa.Column("references", postgresql.ARRAY(sa.Text())),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create indexes for case studies
    op.execute(
        "CREATE INDEX idx_atlas_case_embedding ON atlas_case_studies "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 20)"
    )
    op.create_index("idx_atlas_case_techniques", "atlas_case_studies", ["techniques_used"], postgresql_using="gin")
    op.create_index("idx_atlas_case_date", "atlas_case_studies", ["incident_date"])


def downgrade() -> None:
    """Remove ATLAS tables."""
    op.drop_table("atlas_case_studies")
    op.drop_table("atlas_tactics")
    op.drop_table("atlas_techniques")
