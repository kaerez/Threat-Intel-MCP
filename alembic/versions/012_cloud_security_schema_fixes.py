"""Cloud Security schema fixes for FREE AWS integration

Revision ID: 012
Revises: 011
Create Date: 2026-02-07 10:07:00.000000

Adds missing constraints, defaults, and enum values needed for FREE AWS S3
security property sync.

Changes:
- Add unique constraint for ON CONFLICT upsert
- Add timestamp defaults for created/modified
- Add property_type enum values for AWS best practices

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply schema fixes for cloud security."""

    # Add unique constraint for ON CONFLICT clause
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_property_service_type_name
        ON cloud_security_properties (service_id, property_type, property_name);
    """)

    # Add defaults to timestamp columns
    op.execute("""
        ALTER TABLE cloud_security_properties
        ALTER COLUMN created SET DEFAULT NOW();
    """)

    op.execute("""
        ALTER TABLE cloud_security_properties
        ALTER COLUMN modified SET DEFAULT NOW();
    """)

    # Add new property_type enum values for AWS S3 best practices
    # Note: ALTER TYPE ADD VALUE cannot be run in a transaction
    # These will be added manually if not present
    op.execute("""
        DO $$
        BEGIN
            -- data_protection
            IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'data_protection'
                          AND enumtypid = 'property_type_enum'::regtype) THEN
                ALTER TYPE property_type_enum ADD VALUE 'data_protection';
            END IF;

            -- monitoring_logging
            IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'monitoring_logging'
                          AND enumtypid = 'property_type_enum'::regtype) THEN
                ALTER TYPE property_type_enum ADD VALUE 'monitoring_logging';
            END IF;

            -- cost_optimization
            IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'cost_optimization'
                          AND enumtypid = 'property_type_enum'::regtype) THEN
                ALTER TYPE property_type_enum ADD VALUE 'cost_optimization';
            END IF;

            -- resilience
            IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'resilience'
                          AND enumtypid = 'property_type_enum'::regtype) THEN
                ALTER TYPE property_type_enum ADD VALUE 'resilience';
            END IF;
        END $$;
    """)


def downgrade() -> None:
    """Revert schema fixes."""

    # Remove unique constraint
    op.execute("""
        DROP INDEX IF EXISTS uq_cloud_property_service_type_name;
    """)

    # Remove timestamp defaults
    op.execute("""
        ALTER TABLE cloud_security_properties
        ALTER COLUMN created DROP DEFAULT;
    """)

    op.execute("""
        ALTER TABLE cloud_security_properties
        ALTER COLUMN modified DROP DEFAULT;
    """)

    # Note: Cannot remove enum values in PostgreSQL once added
    # They must remain for backwards compatibility
