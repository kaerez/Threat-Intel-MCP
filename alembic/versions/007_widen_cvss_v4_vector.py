"""Widen cvss_v4_vector column from VARCHAR(150) to VARCHAR(300).

CVSS v4.0 vector strings with supplemental metrics (Safety, Automatable,
Recovery, Value Density, etc.) can exceed 150 characters. Observed max
in NVD data is ~190 characters.

Revision ID: 007
Revises: 006
Create Date: 2026-02-06
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Widen cvss_v4_vector column to accommodate full CVSS 4.0 vectors."""
    op.alter_column(
        "cves",
        "cvss_v4_vector",
        existing_type=sa.String(150),
        type_=sa.String(300),
        existing_nullable=True,
    )


def downgrade() -> None:
    """Revert cvss_v4_vector column to VARCHAR(150)."""
    op.alter_column(
        "cves",
        "cvss_v4_vector",
        existing_type=sa.String(300),
        type_=sa.String(150),
        existing_nullable=True,
    )
