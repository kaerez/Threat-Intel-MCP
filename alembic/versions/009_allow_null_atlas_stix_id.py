"""Allow NULL in ATLAS tables for fields that may be missing.

Revision ID: 009
Revises: 008
Create Date: 2026-02-01

ATLAS moved from STIX to YAML format in late 2024, so newer
techniques don't have STIX IDs. Also, some case studies don't
have created/modified timestamps. This migration makes these
columns nullable.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Make ATLAS columns nullable where data may be missing."""

    # atlas_techniques
    op.alter_column(
        "atlas_techniques",
        "stix_id",
        existing_type=sa.String(100),
        nullable=True,
    )

    # atlas_tactics
    op.alter_column(
        "atlas_tactics",
        "stix_id",
        existing_type=sa.String(100),
        nullable=True,
    )

    # atlas_case_studies - make several columns nullable
    op.alter_column(
        "atlas_case_studies",
        "stix_id",
        existing_type=sa.String(100),
        nullable=True,
    )
    op.alter_column(
        "atlas_case_studies",
        "created",
        existing_type=sa.DateTime(),
        nullable=True,
    )
    op.alter_column(
        "atlas_case_studies",
        "modified",
        existing_type=sa.DateTime(),
        nullable=True,
    )
    op.alter_column(
        "atlas_case_studies",
        "version",
        existing_type=sa.String(20),
        nullable=True,
    )


def downgrade() -> None:
    """Make columns NOT NULL again.

    WARNING: This will fail if there are any NULL values.
    """
    op.alter_column(
        "atlas_case_studies",
        "version",
        existing_type=sa.String(20),
        nullable=False,
    )
    op.alter_column(
        "atlas_case_studies",
        "modified",
        existing_type=sa.DateTime(),
        nullable=False,
    )
    op.alter_column(
        "atlas_case_studies",
        "created",
        existing_type=sa.DateTime(),
        nullable=False,
    )
    op.alter_column(
        "atlas_case_studies",
        "stix_id",
        existing_type=sa.String(100),
        nullable=False,
    )

    op.alter_column(
        "atlas_tactics",
        "stix_id",
        existing_type=sa.String(100),
        nullable=False,
    )

    op.alter_column(
        "atlas_techniques",
        "stix_id",
        existing_type=sa.String(100),
        nullable=False,
    )
