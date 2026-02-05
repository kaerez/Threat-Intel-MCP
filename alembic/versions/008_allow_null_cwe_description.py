"""Allow NULL description in CWE weaknesses.

Revision ID: 008
Revises: 007
Create Date: 2026-02-01

Some CWE entries (e.g., CWE-1004 "Sensitive Cookie Without 'HttpOnly' Flag")
have a name but no description in the source data. This migration makes
the description column nullable to accommodate these entries.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Make cwe_weaknesses.description nullable."""
    op.alter_column(
        "cwe_weaknesses",
        "description",
        existing_type=sa.Text(),
        nullable=True,
    )


def downgrade() -> None:
    """Make cwe_weaknesses.description NOT NULL again.

    WARNING: This will fail if there are any NULL descriptions in the table.
    """
    op.alter_column(
        "cwe_weaknesses",
        "description",
        existing_type=sa.Text(),
        nullable=False,
    )
