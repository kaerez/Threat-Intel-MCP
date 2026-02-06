"""Extend D3FEND relationship types and add CVE tsvector trigger.

1. Add new D3FEND ontology relationship types to the d3fend_relationship_type enum.
   The D3FEND ontology uses granular relationship properties (analyzes, blocks,
   filters, etc.) not present in the original 5-value enum.

2. Add a PostgreSQL trigger to auto-populate cves.description_vector from
   cves.description. Also backfill existing rows with NULL description_vector.

Revision ID: 008
Revises: 007
Create Date: 2026-02-06
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers
revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# New enum values to add (not already in the existing enum)
NEW_RELATIONSHIP_TYPES = [
    "analyzes",
    "blocks",
    "filters",
    "monitors",
    "isolates",
    "restricts",
    "deletes",
    "restores",
    "hardens",
    "verifies",
    "validates",
    "inventories",
    "spoofs",
    "strengthens",
    "encrypts",
    "terminates",
    "updates",
    "modifies",
    "neutralizes",
    "obfuscates",
    "authenticates",
    "quarantines",
]


def upgrade() -> None:
    """Add new D3FEND relationship types and CVE tsvector trigger."""
    # Step 1: Add new enum values to d3fend_relationship_type
    for value in NEW_RELATIONSHIP_TYPES:
        op.execute(
            f"ALTER TYPE d3fend_relationship_type ADD VALUE IF NOT EXISTS '{value}'"
        )

    # Step 2: Create trigger function for auto-populating description_vector
    op.execute("""
        CREATE OR REPLACE FUNCTION cves_description_vector_update()
        RETURNS trigger AS $$
        BEGIN
            NEW.description_vector := to_tsvector('english', COALESCE(NEW.description, ''));
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Step 3: Create trigger on cves table
    op.execute("""
        DROP TRIGGER IF EXISTS cves_description_vector_trigger ON cves
    """)
    op.execute("""
        CREATE TRIGGER cves_description_vector_trigger
        BEFORE INSERT OR UPDATE OF description ON cves
        FOR EACH ROW
        EXECUTE FUNCTION cves_description_vector_update()
    """)

    # Step 4: Backfill existing rows where description_vector is NULL
    op.execute("""
        UPDATE cves
        SET description_vector = to_tsvector('english', COALESCE(description, ''))
        WHERE description_vector IS NULL
    """)


def downgrade() -> None:
    """Remove trigger (enum values cannot be easily removed in PostgreSQL)."""
    op.execute("DROP TRIGGER IF EXISTS cves_description_vector_trigger ON cves")
    op.execute("DROP FUNCTION IF EXISTS cves_description_vector_update()")
