"""Add OWASP LLM Top 10 table.

Revision ID: 013
Revises: 012
Create Date: 2026-02-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add OWASP LLM Top 10 table."""

    op.create_table(
        "owasp_llm_top10",
        sa.Column("llm_id", sa.String(10), primary_key=True),  # LLM01, LLM02, etc.
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("description_vector", postgresql.TSVECTOR()),
        sa.Column("common_examples", postgresql.ARRAY(sa.Text())),
        sa.Column("prevention_strategies", postgresql.ARRAY(sa.Text())),
        sa.Column("example_attack_scenarios", postgresql.ARRAY(sa.Text())),
        sa.Column("related_techniques", postgresql.JSONB()),  # MITRE ATT&CK, ATLAS, CWE mappings
        sa.Column("url", sa.String(500)),
        sa.Column("version", sa.String(20), server_default="1.1"),  # OWASP LLM Top 10 v1.1 (2023)
        sa.Column("data_last_updated", sa.DateTime(), server_default=sa.func.now()),
    )

    # Create indexes for full-text search
    op.create_index(
        "idx_owasp_llm_description_fts",
        "owasp_llm_top10",
        ["description_vector"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_owasp_llm_name_trgm",
        "owasp_llm_top10",
        ["name"],
        postgresql_using="gin",
        postgresql_ops={"name": "gin_trgm_ops"},
    )

    # Create tsvector trigger for automatic full-text indexing
    op.execute("""
        CREATE TRIGGER owasp_llm_description_tsvector_update
        BEFORE INSERT OR UPDATE ON owasp_llm_top10
        FOR EACH ROW EXECUTE FUNCTION
        tsvector_update_trigger(
            description_vector,
            'pg_catalog.english',
            name, description
        );
    """)


def downgrade() -> None:
    """Remove OWASP LLM Top 10 table."""
    op.execute("DROP TRIGGER IF EXISTS owasp_llm_description_tsvector_update ON owasp_llm_top10;")
    op.drop_index("idx_owasp_llm_name_trgm", table_name="owasp_llm_top10")
    op.drop_index("idx_owasp_llm_description_fts", table_name="owasp_llm_top10")
    op.drop_table("owasp_llm_top10")
