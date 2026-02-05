"""Fix remaining ATLAS case study nullable columns.

Revision ID: 010
Revises: 009
Create Date: 2026-02-01

Additional nullable fixes for ATLAS case studies that were
missed in migration 009.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Make remaining ATLAS case study columns nullable."""

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
    """Make columns NOT NULL again."""
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
