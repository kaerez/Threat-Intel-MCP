"""Fix D3FEND column sizes to accommodate longer IDs.

Revision ID: 012
Revises: 011
Create Date: 2026-02-01

D3FEND tactic and technique IDs can be longer than 20 chars
(e.g., D3-NETWORK-TRAFFIC-ANALYSIS = 27 chars).
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Increase D3FEND ID column sizes from varchar(20) to varchar(50)."""

    # d3fend_tactics.tactic_id (primary key)
    op.alter_column(
        "d3fend_tactics",
        "tactic_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )

    # d3fend_techniques.technique_id (primary key)
    op.alter_column(
        "d3fend_techniques",
        "technique_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )

    # d3fend_techniques.tactic_id (foreign key)
    op.alter_column(
        "d3fend_techniques",
        "tactic_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )

    # d3fend_techniques.parent_id (self-referential FK)
    op.alter_column(
        "d3fend_techniques",
        "parent_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )

    # d3fend_technique_attack_mappings.d3fend_technique_id (FK)
    op.alter_column(
        "d3fend_technique_attack_mappings",
        "d3fend_technique_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )

    # d3fend_technique_attack_mappings.attack_technique_id (FK to attack_techniques)
    op.alter_column(
        "d3fend_technique_attack_mappings",
        "attack_technique_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )

    # d3fend_technique_artifacts.technique_id (composite PK/FK)
    op.alter_column(
        "d3fend_technique_artifacts",
        "technique_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
    )


def downgrade() -> None:
    """Revert D3FEND ID column sizes back to varchar(20)."""

    op.alter_column(
        "d3fend_technique_artifacts",
        "technique_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )

    op.alter_column(
        "d3fend_technique_attack_mappings",
        "attack_technique_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )

    op.alter_column(
        "d3fend_technique_attack_mappings",
        "d3fend_technique_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )

    op.alter_column(
        "d3fend_techniques",
        "parent_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )

    op.alter_column(
        "d3fend_techniques",
        "tactic_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )

    op.alter_column(
        "d3fend_techniques",
        "technique_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )

    op.alter_column(
        "d3fend_tactics",
        "tactic_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
    )
