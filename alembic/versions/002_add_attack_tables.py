"""Add MITRE ATT&CK tables with pgvector semantic search

Revision ID: 002
Revises: 001
Create Date: 2026-01-31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from pgvector.sqlalchemy import Vector

# revision identifiers
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable pgvector extension
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # AttackTechnique
    op.create_table(
        "attack_techniques",
        sa.Column("technique_id", sa.String(20), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("is_subtechnique", sa.Boolean(), default=False),
        sa.Column("parent_technique_id", sa.String(20), sa.ForeignKey("attack_techniques.technique_id")),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("embedding", Vector(1536)),
        sa.Column("tactics", postgresql.ARRAY(sa.Text())),
        sa.Column("platforms", postgresql.ARRAY(sa.Text())),
        sa.Column("data_sources", postgresql.ARRAY(sa.Text())),
        sa.Column("detection", sa.Text()),
        sa.Column("permissions_required", postgresql.ARRAY(sa.Text())),
        sa.Column("effective_permissions", postgresql.ARRAY(sa.Text())),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), default=False),
        sa.Column("revoked", sa.Boolean(), default=False),
        sa.Column("stix_extensions", postgresql.JSONB()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
    )

    # Create indexes for attack_techniques
    op.create_index(
        "idx_attack_tech_name",
        "attack_techniques",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.create_index(
        "idx_attack_tech_desc_fts", "attack_techniques", ["description_vector"], postgresql_using="gin"
    )
    op.create_index("idx_attack_tech_tactics", "attack_techniques", ["tactics"], postgresql_using="gin")
    op.create_index("idx_attack_tech_platforms", "attack_techniques", ["platforms"], postgresql_using="gin")
    op.create_index("idx_attack_tech_parent", "attack_techniques", ["parent_technique_id"])
    op.create_index(
        "idx_attack_tech_active",
        "attack_techniques",
        ["technique_id"],
        postgresql_where="(NOT deprecated AND NOT revoked)",
    )
    # Vector similarity index (IVFFlat)
    op.execute(
        "CREATE INDEX idx_attack_tech_embedding ON attack_techniques "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
    )

    # AttackGroup
    op.create_table(
        "attack_groups",
        sa.Column("group_id", sa.String(20), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.Text())),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("embedding", Vector(1536)),
        sa.Column("associated_groups", postgresql.ARRAY(sa.Text())),
        sa.Column("techniques_used", postgresql.ARRAY(sa.Text())),
        sa.Column("software_used", postgresql.ARRAY(sa.Text())),
        sa.Column("attribution_confidence", sa.String(20)),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("revoked", sa.Boolean(), default=False),
        sa.Column("stix_extensions", postgresql.JSONB()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime()),
    )

    op.create_index(
        "idx_attack_group_name",
        "attack_groups",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )
    op.create_index("idx_attack_group_aliases", "attack_groups", ["aliases"], postgresql_using="gin")
    op.create_index("idx_attack_group_techniques", "attack_groups", ["techniques_used"], postgresql_using="gin")
    op.execute(
        "CREATE INDEX idx_attack_group_embedding ON attack_groups "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50)"
    )

    # AttackTactic (no embeddings - small dataset)
    op.create_table(
        "attack_tactics",
        sa.Column("tactic_id", sa.String(50), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("shortname", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # AttackSoftware (no embeddings for MVP)
    op.create_table(
        "attack_software",
        sa.Column("software_id", sa.String(20), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.Text())),
        sa.Column("software_type", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("platforms", postgresql.ARRAY(sa.Text())),
        sa.Column("techniques_used", postgresql.ARRAY(sa.Text())),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("revoked", sa.Boolean(), default=False),
        sa.Column("stix_extensions", postgresql.JSONB()),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_index("idx_attack_software_name", "attack_software", ["name"])
    op.create_index("idx_attack_software_type", "attack_software", ["software_type"])
    op.create_index("idx_attack_software_techniques", "attack_software", ["techniques_used"], postgresql_using="gin")

    # AttackMitigation (no embeddings for MVP)
    op.create_table(
        "attack_mitigations",
        sa.Column("mitigation_id", sa.String(20), primary_key=True),
        sa.Column("stix_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mitigates_techniques", postgresql.ARRAY(sa.Text())),
        sa.Column("version", sa.String(20)),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_index(
        "idx_attack_mitigation_techniques",
        "attack_mitigations",
        ["mitigates_techniques"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_table("attack_mitigations")
    op.drop_table("attack_software")
    op.drop_table("attack_tactics")
    op.drop_table("attack_groups")
    op.drop_table("attack_techniques")
    op.execute("DROP EXTENSION IF EXISTS vector")
