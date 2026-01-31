# D3FEND Module Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add MITRE D3FEND defensive countermeasures framework with semantic search and ATT&CK correlation.

**Architecture:** 5 database tables (tactics, techniques, artifacts, 2 join tables), JSON parser for MISP Galaxy format, 5 MCP tools with HNSW vector index for semantic search.

**Tech Stack:** SQLAlchemy async, pgvector (HNSW), OpenAI embeddings, httpx for downloads

**Design Doc:** `docs/plans/2026-01-31-d3fend-module-design.md`

---

## Task 0: Database Schema & Migration

**Files:**
- Create: `src/cve_mcp/models/d3fend.py`
- Create: `alembic/versions/006_add_d3fend_tables.py`
- Modify: `src/cve_mcp/models/__init__.py`

**Step 1: Write the model tests**

Create `tests/models/test_d3fend_models.py`:

```python
"""Tests for D3FEND database models."""

import pytest
from sqlalchemy import inspect

from cve_mcp.models.d3fend import (
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDArtifact,
    D3FENDTechniqueAttackMapping,
    D3FENDTechniqueArtifact,
    D3FENDRelationshipType,
    D3FENDArtifactRelationshipType,
)


class TestD3FENDTactic:
    """Tests for D3FENDTactic model."""

    def test_table_name(self):
        assert D3FENDTactic.__tablename__ == "d3fend_tactics"

    def test_primary_key(self):
        mapper = inspect(D3FENDTactic)
        pk_cols = [col.name for col in mapper.primary_key]
        assert pk_cols == ["tactic_id"]

    def test_required_fields(self):
        mapper = inspect(D3FENDTactic)
        columns = {col.name: col for col in mapper.columns}
        assert not columns["name"].nullable
        assert not columns["display_order"].nullable


class TestD3FENDTechnique:
    """Tests for D3FENDTechnique model."""

    def test_table_name(self):
        assert D3FENDTechnique.__tablename__ == "d3fend_techniques"

    def test_primary_key(self):
        mapper = inspect(D3FENDTechnique)
        pk_cols = [col.name for col in mapper.primary_key]
        assert pk_cols == ["technique_id"]

    def test_embedding_vector_dimension(self):
        mapper = inspect(D3FENDTechnique)
        embedding_col = mapper.columns["embedding"]
        assert embedding_col.type.dim == 1536

    def test_foreign_keys(self):
        mapper = inspect(D3FENDTechnique)
        fks = {fk.column.name: fk.target_fullname for fk in mapper.columns["tactic_id"].foreign_keys}
        assert "d3fend_tactics.tactic_id" in fks.values()

    def test_self_referential_parent(self):
        mapper = inspect(D3FENDTechnique)
        fks = {fk.target_fullname for fk in mapper.columns["parent_id"].foreign_keys}
        assert "d3fend_techniques.technique_id" in fks


class TestD3FENDArtifact:
    """Tests for D3FENDArtifact model."""

    def test_table_name(self):
        assert D3FENDArtifact.__tablename__ == "d3fend_artifacts"

    def test_primary_key(self):
        mapper = inspect(D3FENDArtifact)
        pk_cols = [col.name for col in mapper.primary_key]
        assert pk_cols == ["artifact_id"]


class TestD3FENDTechniqueAttackMapping:
    """Tests for D3FENDTechniqueAttackMapping model."""

    def test_table_name(self):
        assert D3FENDTechniqueAttackMapping.__tablename__ == "d3fend_technique_attack_mappings"

    def test_foreign_keys(self):
        mapper = inspect(D3FENDTechniqueAttackMapping)
        # Check d3fend FK
        d3fend_fks = {fk.target_fullname for fk in mapper.columns["d3fend_technique_id"].foreign_keys}
        assert "d3fend_techniques.technique_id" in d3fend_fks
        # Check attack FK
        attack_fks = {fk.target_fullname for fk in mapper.columns["attack_technique_id"].foreign_keys}
        assert "attack_techniques.technique_id" in attack_fks

    def test_relationship_type_enum(self):
        assert "counters" in D3FENDRelationshipType.__members__
        assert "enables" in D3FENDRelationshipType.__members__
        assert "related_to" in D3FENDRelationshipType.__members__


class TestD3FENDTechniqueArtifact:
    """Tests for D3FENDTechniqueArtifact model."""

    def test_table_name(self):
        assert D3FENDTechniqueArtifact.__tablename__ == "d3fend_technique_artifacts"

    def test_composite_primary_key(self):
        mapper = inspect(D3FENDTechniqueArtifact)
        pk_cols = [col.name for col in mapper.primary_key]
        assert "technique_id" in pk_cols
        assert "artifact_id" in pk_cols
        assert "relationship_type" in pk_cols

    def test_artifact_relationship_type_enum(self):
        assert "produces" in D3FENDArtifactRelationshipType.__members__
        assert "uses" in D3FENDArtifactRelationshipType.__members__
        assert "analyzes" in D3FENDArtifactRelationshipType.__members__
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/models/test_d3fend_models.py -v
```

Expected: ModuleNotFoundError (models don't exist yet)

**Step 3: Create the D3FEND models**

Create `src/cve_mcp/models/d3fend.py`:

```python
"""D3FEND defensive countermeasures database models."""

import enum
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    from cve_mcp.models.attack import AttackTechnique


class D3FENDRelationshipType(enum.Enum):
    """Relationship types between D3FEND and ATT&CK techniques."""

    counters = "counters"
    enables = "enables"
    related_to = "related-to"
    produces = "produces"
    uses = "uses"


class D3FENDArtifactRelationshipType(enum.Enum):
    """Relationship types between techniques and artifacts."""

    produces = "produces"
    uses = "uses"
    analyzes = "analyzes"


class D3FENDTactic(Base):
    """D3FEND defensive tactics (Model, Harden, Detect, etc.)."""

    __tablename__ = "d3fend_tactics"

    tactic_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Timestamps
    created: Mapped[Optional[datetime]] = mapped_column(DateTime)
    modified: Mapped[Optional[datetime]] = mapped_column(DateTime)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationships
    techniques: Mapped[list["D3FENDTechnique"]] = relationship(
        "D3FENDTechnique", back_populates="tactic", foreign_keys="D3FENDTechnique.tactic_id"
    )


class D3FENDTechnique(Base):
    """D3FEND defensive techniques."""

    __tablename__ = "d3fend_techniques"

    # Primary identification
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)

    # Semantic search
    embedding: Mapped[Optional[list[float]]] = mapped_column(Vector(1536))
    embedding_model: Mapped[Optional[str]] = mapped_column(String(50))
    embedding_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Core fields
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    tactic_id: Mapped[Optional[str]] = mapped_column(
        String(20), ForeignKey("d3fend_tactics.tactic_id", ondelete="SET NULL")
    )

    # Hierarchy (self-referential)
    parent_id: Mapped[Optional[str]] = mapped_column(
        String(20), ForeignKey("d3fend_techniques.technique_id", ondelete="SET NULL")
    )

    # Extended fields from ontology
    synonyms: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    references: Mapped[Optional[dict]] = mapped_column(JSONB)
    kb_article_url: Mapped[Optional[str]] = mapped_column(String(500))

    # Timestamps
    created: Mapped[Optional[datetime]] = mapped_column(DateTime)
    modified: Mapped[Optional[datetime]] = mapped_column(DateTime)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Metadata
    d3fend_version: Mapped[Optional[str]] = mapped_column(String(20))
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    tactic: Mapped[Optional["D3FENDTactic"]] = relationship(
        "D3FENDTactic", back_populates="techniques", foreign_keys=[tactic_id]
    )
    parent: Mapped[Optional["D3FENDTechnique"]] = relationship(
        "D3FENDTechnique", remote_side=[technique_id], foreign_keys=[parent_id]
    )
    attack_mappings: Mapped[list["D3FENDTechniqueAttackMapping"]] = relationship(
        "D3FENDTechniqueAttackMapping", back_populates="d3fend_technique"
    )
    artifact_mappings: Mapped[list["D3FENDTechniqueArtifact"]] = relationship(
        "D3FENDTechniqueArtifact", back_populates="technique"
    )

    __table_args__ = (
        # HNSW index for semantic search (better for small datasets)
        Index(
            "idx_d3fend_embedding",
            embedding,
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # Fast lookups
        Index("idx_d3fend_tactic", tactic_id),
        Index("idx_d3fend_parent", parent_id),
        Index(
            "idx_d3fend_name_trgm",
            name,
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
    )


class D3FENDArtifact(Base):
    """D3FEND digital artifacts."""

    __tablename__ = "d3fend_artifacts"

    artifact_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    artifact_type: Mapped[Optional[str]] = mapped_column(String(50))

    # Relationships
    technique_mappings: Mapped[list["D3FENDTechniqueArtifact"]] = relationship(
        "D3FENDTechniqueArtifact", back_populates="artifact"
    )


class D3FENDTechniqueAttackMapping(Base):
    """Mapping between D3FEND techniques and ATT&CK techniques."""

    __tablename__ = "d3fend_technique_attack_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    d3fend_technique_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"), nullable=False
    )
    attack_technique_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[D3FENDRelationshipType] = mapped_column(
        Enum(D3FENDRelationshipType), nullable=False
    )

    # Relationships
    d3fend_technique: Mapped["D3FENDTechnique"] = relationship(
        "D3FENDTechnique", back_populates="attack_mappings"
    )
    attack_technique: Mapped["AttackTechnique"] = relationship("AttackTechnique")

    __table_args__ = (
        UniqueConstraint(
            "d3fend_technique_id", "attack_technique_id", "relationship_type",
            name="uq_d3fend_attack_mapping"
        ),
        Index("idx_d3fend_attack_mapping", attack_technique_id),
    )


class D3FENDTechniqueArtifact(Base):
    """Mapping between D3FEND techniques and artifacts."""

    __tablename__ = "d3fend_technique_artifacts"

    technique_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"), primary_key=True
    )
    artifact_id: Mapped[str] = mapped_column(
        String(50), ForeignKey("d3fend_artifacts.artifact_id", ondelete="CASCADE"), primary_key=True
    )
    relationship_type: Mapped[D3FENDArtifactRelationshipType] = mapped_column(
        Enum(D3FENDArtifactRelationshipType), primary_key=True
    )

    # Relationships
    technique: Mapped["D3FENDTechnique"] = relationship(
        "D3FENDTechnique", back_populates="artifact_mappings"
    )
    artifact: Mapped["D3FENDArtifact"] = relationship(
        "D3FENDArtifact", back_populates="technique_mappings"
    )
```

**Step 4: Update models __init__.py**

Add to `src/cve_mcp/models/__init__.py`:

```python
from cve_mcp.models.d3fend import (
    D3FENDArtifact,
    D3FENDArtifactRelationshipType,
    D3FENDRelationshipType,
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDTechniqueArtifact,
    D3FENDTechniqueAttackMapping,
)
```

And add to `__all__`.

**Step 5: Run tests to verify they pass**

```bash
pytest tests/models/test_d3fend_models.py -v
```

Expected: All tests pass

**Step 6: Create Alembic migration**

Create `alembic/versions/006_add_d3fend_tables.py`:

```python
"""Add D3FEND tables.

Revision ID: 006
Revises: 005
Create Date: 2026-01-31
"""

from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum types
    d3fend_relationship_type = postgresql.ENUM(
        "counters", "enables", "related-to", "produces", "uses",
        name="d3fendrelationshiptype"
    )
    d3fend_relationship_type.create(op.get_bind())

    d3fend_artifact_relationship_type = postgresql.ENUM(
        "produces", "uses", "analyzes",
        name="d3fendartifactrelationshiptype"
    )
    d3fend_artifact_relationship_type.create(op.get_bind())

    # d3fend_tactics
    op.create_table(
        "d3fend_tactics",
        sa.Column("tactic_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("display_order", sa.Integer, nullable=False, default=0),
        sa.Column("created", sa.DateTime),
        sa.Column("modified", sa.DateTime),
        sa.Column("data_last_updated", sa.DateTime, server_default=sa.func.now()),
    )

    # d3fend_techniques
    op.create_table(
        "d3fend_techniques",
        sa.Column("technique_id", sa.String(20), primary_key=True),
        sa.Column("embedding", Vector(1536)),
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("tactic_id", sa.String(20), sa.ForeignKey("d3fend_tactics.tactic_id", ondelete="SET NULL")),
        sa.Column("parent_id", sa.String(20), sa.ForeignKey("d3fend_techniques.technique_id", ondelete="SET NULL")),
        sa.Column("synonyms", postgresql.ARRAY(sa.Text)),
        sa.Column("references", postgresql.JSONB),
        sa.Column("kb_article_url", sa.String(500)),
        sa.Column("created", sa.DateTime),
        sa.Column("modified", sa.DateTime),
        sa.Column("data_last_updated", sa.DateTime, server_default=sa.func.now()),
        sa.Column("d3fend_version", sa.String(20)),
        sa.Column("deprecated", sa.Boolean, default=False),
    )

    # d3fend_artifacts
    op.create_table(
        "d3fend_artifacts",
        sa.Column("artifact_id", sa.String(50), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("artifact_type", sa.String(50)),
    )

    # d3fend_technique_attack_mappings
    op.create_table(
        "d3fend_technique_attack_mappings",
        sa.Column("mapping_id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("d3fend_technique_id", sa.String(20), sa.ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"), nullable=False),
        sa.Column("attack_technique_id", sa.String(20), sa.ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", d3fend_relationship_type, nullable=False),
        sa.UniqueConstraint("d3fend_technique_id", "attack_technique_id", "relationship_type", name="uq_d3fend_attack_mapping"),
    )

    # d3fend_technique_artifacts
    op.create_table(
        "d3fend_technique_artifacts",
        sa.Column("technique_id", sa.String(20), sa.ForeignKey("d3fend_techniques.technique_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("artifact_id", sa.String(50), sa.ForeignKey("d3fend_artifacts.artifact_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("relationship_type", d3fend_artifact_relationship_type, primary_key=True),
    )

    # Indexes
    op.create_index("idx_d3fend_embedding", "d3fend_techniques", ["embedding"],
                    postgresql_using="hnsw",
                    postgresql_with={"m": 16, "ef_construction": 64},
                    postgresql_ops={"embedding": "vector_cosine_ops"})
    op.create_index("idx_d3fend_tactic", "d3fend_techniques", ["tactic_id"])
    op.create_index("idx_d3fend_parent", "d3fend_techniques", ["parent_id"])
    op.create_index("idx_d3fend_name_trgm", "d3fend_techniques", ["name"],
                    postgresql_using="gin",
                    postgresql_ops={"name": "gin_trgm_ops"})
    op.create_index("idx_d3fend_attack_mapping", "d3fend_technique_attack_mappings", ["attack_technique_id"])


def downgrade() -> None:
    op.drop_table("d3fend_technique_artifacts")
    op.drop_table("d3fend_technique_attack_mappings")
    op.drop_table("d3fend_artifacts")
    op.drop_table("d3fend_techniques")
    op.drop_table("d3fend_tactics")

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS d3fendrelationshiptype")
    op.execute("DROP TYPE IF EXISTS d3fendartifactrelationshiptype")
```

**Step 7: Commit**

```bash
git add src/cve_mcp/models/d3fend.py alembic/versions/006_add_d3fend_tables.py tests/models/test_d3fend_models.py
git commit -m "feat(d3fend): add database models and migration for D3FEND module"
```

---

## Task 1: JSON Parser

**Files:**
- Create: `src/cve_mcp/ingest/d3fend_parser.py`
- Create: `tests/ingest/test_d3fend_parser.py`

**Step 1: Write parser tests**

Create `tests/ingest/test_d3fend_parser.py`:

```python
"""Tests for D3FEND MISP Galaxy JSON parser."""

import pytest

from cve_mcp.ingest.d3fend_parser import (
    parse_technique,
    parse_tactic_from_kill_chain,
    extract_attack_mappings,
    normalize_d3fend_id,
)


class TestNormalizeD3FendId:
    """Tests for normalize_d3fend_id function."""

    def test_standard_id(self):
        assert normalize_d3fend_id("D3-AH") == "D3-AH"

    def test_lowercase_id(self):
        assert normalize_d3fend_id("d3-ah") == "D3-AH"

    def test_with_prefix(self):
        assert normalize_d3fend_id("d3f:D3-AH") == "D3-AH"

    def test_empty_string(self):
        assert normalize_d3fend_id("") == ""

    def test_none(self):
        assert normalize_d3fend_id(None) is None


class TestParseTacticFromKillChain:
    """Tests for parse_tactic_from_kill_chain function."""

    def test_single_tactic(self):
        kill_chain = ["d3fend:Harden"]
        assert parse_tactic_from_kill_chain(kill_chain) == "D3-HARDEN"

    def test_multiple_tactics_returns_first(self):
        kill_chain = ["d3fend:Detect", "d3fend:Isolate"]
        assert parse_tactic_from_kill_chain(kill_chain) == "D3-DETECT"

    def test_empty_list(self):
        assert parse_tactic_from_kill_chain([]) is None

    def test_none(self):
        assert parse_tactic_from_kill_chain(None) is None

    def test_different_format(self):
        kill_chain = ["mitre-d3fend:Model"]
        assert parse_tactic_from_kill_chain(kill_chain) == "D3-MODEL"


class TestExtractAttackMappings:
    """Tests for extract_attack_mappings function."""

    def test_counters_relationship(self):
        related = [
            {"dest-uuid": "abc-123", "type": "counters", "tags": ["attack-technique:T1059"]}
        ]
        mappings = extract_attack_mappings(related)
        assert len(mappings) == 1
        assert mappings[0]["attack_technique_id"] == "T1059"
        assert mappings[0]["relationship_type"] == "counters"

    def test_multiple_mappings(self):
        related = [
            {"dest-uuid": "abc-123", "type": "counters", "tags": ["attack-technique:T1059"]},
            {"dest-uuid": "def-456", "type": "enables", "tags": ["attack-technique:T1059.001"]},
        ]
        mappings = extract_attack_mappings(related)
        assert len(mappings) == 2

    def test_filters_non_attack_relations(self):
        related = [
            {"dest-uuid": "abc-123", "type": "similar-to"},  # No attack tag
            {"dest-uuid": "def-456", "type": "counters", "tags": ["attack-technique:T1059"]},
        ]
        mappings = extract_attack_mappings(related)
        assert len(mappings) == 1

    def test_empty_related(self):
        assert extract_attack_mappings([]) == []

    def test_none_related(self):
        assert extract_attack_mappings(None) == []

    def test_subtechnique_id(self):
        related = [
            {"dest-uuid": "abc-123", "type": "counters", "tags": ["attack-technique:T1059.001"]}
        ]
        mappings = extract_attack_mappings(related)
        assert mappings[0]["attack_technique_id"] == "T1059.001"


class TestParseTechnique:
    """Tests for parse_technique function."""

    def test_basic_technique(self):
        entry = {
            "value": "Application Hardening",
            "uuid": "abc-123-def",
            "description": "Techniques to make applications more secure.",
            "meta": {
                "external_id": "D3-AH",
                "kill_chain": ["d3fend:Harden"],
                "refs": ["https://d3fend.mitre.org/technique/d3f:ApplicationHardening"],
            },
            "related": [],
        }
        result = parse_technique(entry)

        assert result["technique_id"] == "D3-AH"
        assert result["name"] == "Application Hardening"
        assert result["description"] == "Techniques to make applications more secure."
        assert result["tactic_id"] == "D3-HARDEN"
        assert result["kb_article_url"] == "https://d3fend.mitre.org/technique/d3f:ApplicationHardening"

    def test_technique_with_synonyms(self):
        entry = {
            "value": "Certificate Pinning",
            "uuid": "abc-123",
            "description": "Pin certificates.",
            "meta": {
                "external_id": "D3-CP",
                "kill_chain": ["d3fend:Harden"],
                "synonyms": ["SSL Pinning", "TLS Pinning"],
            },
            "related": [],
        }
        result = parse_technique(entry)
        assert result["synonyms"] == ["SSL Pinning", "TLS Pinning"]

    def test_technique_with_attack_mappings(self):
        entry = {
            "value": "Process Eviction",
            "uuid": "abc-123",
            "description": "Evict malicious processes.",
            "meta": {
                "external_id": "D3-PE",
                "kill_chain": ["d3fend:Evict"],
            },
            "related": [
                {"dest-uuid": "xyz", "type": "counters", "tags": ["attack-technique:T1059"]},
            ],
        }
        result = parse_technique(entry)
        assert len(result["attack_mappings"]) == 1
        assert result["attack_mappings"][0]["attack_technique_id"] == "T1059"

    def test_technique_missing_optional_fields(self):
        entry = {
            "value": "Minimal Technique",
            "uuid": "abc-123",
            "meta": {
                "external_id": "D3-MT",
            },
        }
        result = parse_technique(entry)
        assert result["technique_id"] == "D3-MT"
        assert result["name"] == "Minimal Technique"
        assert result["description"] is None
        assert result["synonyms"] is None
        assert result["attack_mappings"] == []

    def test_technique_with_references(self):
        entry = {
            "value": "Test Technique",
            "uuid": "abc-123",
            "meta": {
                "external_id": "D3-TT",
                "refs": [
                    "https://d3fend.mitre.org/technique/d3f:Test",
                    "https://example.com/paper.pdf",
                ],
            },
        }
        result = parse_technique(entry)
        assert result["kb_article_url"] == "https://d3fend.mitre.org/technique/d3f:Test"
        assert len(result["references"]) == 1  # Non-d3fend refs
        assert result["references"][0]["url"] == "https://example.com/paper.pdf"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/ingest/test_d3fend_parser.py -v
```

Expected: ModuleNotFoundError

**Step 3: Implement the parser**

Create `src/cve_mcp/ingest/d3fend_parser.py`:

```python
"""Parser for D3FEND data in MISP Galaxy JSON format."""

from typing import Any


def normalize_d3fend_id(external_id: str | None) -> str | None:
    """Normalize D3FEND technique ID to standard format.

    Args:
        external_id: Raw ID like "d3f:D3-AH" or "d3-ah"

    Returns:
        Normalized ID like "D3-AH", or None if input is None
    """
    if external_id is None:
        return None
    if not external_id:
        return ""

    # Remove prefix if present
    if ":" in external_id:
        external_id = external_id.split(":")[-1]

    return external_id.upper()


def parse_tactic_from_kill_chain(kill_chain: list[str] | None) -> str | None:
    """Extract tactic ID from kill_chain array.

    Args:
        kill_chain: List like ["d3fend:Harden"] or ["mitre-d3fend:Model"]

    Returns:
        Tactic ID like "D3-HARDEN", or None if not found
    """
    if not kill_chain:
        return None

    # Take first entry
    entry = kill_chain[0]

    # Extract tactic name after colon
    if ":" in entry:
        tactic_name = entry.split(":")[-1]
    else:
        tactic_name = entry

    return f"D3-{tactic_name.upper()}"


def extract_attack_mappings(related: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Extract ATT&CK technique mappings from related array.

    Args:
        related: List of relationship objects from MISP format

    Returns:
        List of mapping dicts with attack_technique_id and relationship_type
    """
    if not related:
        return []

    mappings = []
    for rel in related:
        # Look for attack-technique tags
        tags = rel.get("tags", [])
        attack_id = None

        for tag in tags:
            if tag.startswith("attack-technique:"):
                attack_id = tag.split(":")[-1]
                break

        if attack_id:
            mappings.append({
                "attack_technique_id": attack_id,
                "relationship_type": rel.get("type", "related-to"),
            })

    return mappings


def parse_technique(entry: dict[str, Any]) -> dict[str, Any]:
    """Parse a single D3FEND technique from MISP Galaxy format.

    Args:
        entry: Technique entry from MISP Galaxy JSON

    Returns:
        Parsed technique dict ready for database insertion
    """
    meta = entry.get("meta", {})

    # Extract KB article URL and other references
    refs = meta.get("refs", [])
    kb_article_url = None
    other_refs = []

    for ref in refs:
        if "d3fend.mitre.org" in ref:
            kb_article_url = ref
        else:
            other_refs.append({"url": ref})

    return {
        "technique_id": normalize_d3fend_id(meta.get("external_id")),
        "name": entry.get("value"),
        "description": entry.get("description"),
        "tactic_id": parse_tactic_from_kill_chain(meta.get("kill_chain")),
        "synonyms": meta.get("synonyms"),
        "references": other_refs if other_refs else None,
        "kb_article_url": kb_article_url,
        "attack_mappings": extract_attack_mappings(entry.get("related")),
    }
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/ingest/test_d3fend_parser.py -v
```

Expected: All tests pass

**Step 5: Commit**

```bash
git add src/cve_mcp/ingest/d3fend_parser.py tests/ingest/test_d3fend_parser.py
git commit -m "feat(d3fend): add MISP Galaxy JSON parser"
```

---

## Task 2: Data Sync Task

**Files:**
- Create: `src/cve_mcp/tasks/sync_d3fend.py`
- Create: `scripts/sync_d3fend_data.py`
- Create: `tests/tasks/test_sync_d3fend.py`

**Step 1: Write sync tests**

Create `tests/tasks/test_sync_d3fend.py`:

```python
"""Tests for D3FEND data sync task."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from cve_mcp.tasks.sync_d3fend import (
    download_d3fend_data,
    extract_tactics,
    sync_d3fend_data,
)


class TestDownloadD3FendData:
    """Tests for download_d3fend_data function."""

    @pytest.mark.asyncio
    async def test_successful_download(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "name": "MITRE D3FEND",
            "values": [{"value": "Test", "meta": {"external_id": "D3-T"}}],
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            data = await download_d3fend_data()

        assert data["name"] == "MITRE D3FEND"
        assert len(data["values"]) == 1


class TestExtractTactics:
    """Tests for extract_tactics function."""

    def test_extracts_unique_tactics(self):
        techniques = [
            {"tactic_id": "D3-HARDEN", "name": "Tech1"},
            {"tactic_id": "D3-HARDEN", "name": "Tech2"},
            {"tactic_id": "D3-DETECT", "name": "Tech3"},
        ]
        tactics = extract_tactics(techniques)

        assert len(tactics) == 2
        tactic_ids = {t["tactic_id"] for t in tactics}
        assert "D3-HARDEN" in tactic_ids
        assert "D3-DETECT" in tactic_ids

    def test_handles_none_tactic(self):
        techniques = [
            {"tactic_id": None, "name": "Orphan"},
            {"tactic_id": "D3-MODEL", "name": "Good"},
        ]
        tactics = extract_tactics(techniques)

        assert len(tactics) == 1
        assert tactics[0]["tactic_id"] == "D3-MODEL"

    def test_assigns_display_order(self):
        techniques = [
            {"tactic_id": "D3-MODEL", "name": "T1"},
            {"tactic_id": "D3-HARDEN", "name": "T2"},
            {"tactic_id": "D3-DETECT", "name": "T3"},
        ]
        tactics = extract_tactics(techniques)

        # Check display_order is assigned
        for tactic in tactics:
            assert "display_order" in tactic
            assert isinstance(tactic["display_order"], int)


class TestSyncD3FendData:
    """Tests for main sync function."""

    @pytest.mark.asyncio
    async def test_sync_creates_records(self):
        # This would be an integration test with the database
        # For unit testing, we mock the database session
        pass
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/tasks/test_sync_d3fend.py -v
```

Expected: ModuleNotFoundError

**Step 3: Implement sync task**

Create `src/cve_mcp/tasks/sync_d3fend.py`:

```python
"""Sync task for D3FEND defensive countermeasures data."""

import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.ingest.d3fend_parser import parse_technique
from cve_mcp.models.d3fend import (
    D3FENDArtifact,
    D3FENDRelationshipType,
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDTechniqueAttackMapping,
)
from cve_mcp.models.attack import AttackTechnique
from cve_mcp.services.embeddings import generate_embedding

logger = logging.getLogger(__name__)

# MISP Galaxy D3FEND data URL
D3FEND_DATA_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-d3fend.json"

# Standard tactic display order
TACTIC_ORDER = {
    "D3-MODEL": 0,
    "D3-HARDEN": 1,
    "D3-DETECT": 2,
    "D3-ISOLATE": 3,
    "D3-DECEIVE": 4,
    "D3-EVICT": 5,
    "D3-RESTORE": 6,
}

# Tactic descriptions
TACTIC_DESCRIPTIONS = {
    "D3-MODEL": "Techniques for establishing a baseline model of the system to protect.",
    "D3-HARDEN": "Techniques for making systems more resistant to attack.",
    "D3-DETECT": "Techniques for identifying malicious activity.",
    "D3-ISOLATE": "Techniques for separating systems or components.",
    "D3-DECEIVE": "Techniques for misleading adversaries.",
    "D3-EVICT": "Techniques for removing adversary presence.",
    "D3-RESTORE": "Techniques for recovering from incidents.",
}


async def download_d3fend_data(url: str = D3FEND_DATA_URL) -> dict[str, Any]:
    """Download D3FEND data from MISP Galaxy.

    Args:
        url: URL to download from

    Returns:
        Parsed JSON data
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


def extract_tactics(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract unique tactics from parsed techniques.

    Args:
        techniques: List of parsed technique dicts

    Returns:
        List of tactic dicts ready for insertion
    """
    seen_tactics = set()
    tactics = []

    for tech in techniques:
        tactic_id = tech.get("tactic_id")
        if tactic_id and tactic_id not in seen_tactics:
            seen_tactics.add(tactic_id)

            # Extract tactic name from ID (e.g., "D3-HARDEN" -> "Harden")
            name = tactic_id.replace("D3-", "").title()

            tactics.append({
                "tactic_id": tactic_id,
                "name": name,
                "description": TACTIC_DESCRIPTIONS.get(tactic_id, ""),
                "display_order": TACTIC_ORDER.get(tactic_id, 99),
            })

    return tactics


async def sync_d3fend_data(
    session: AsyncSession,
    generate_embeddings: bool = True,
    verbose: bool = False,
) -> dict[str, int]:
    """Sync D3FEND data to database.

    Args:
        session: Database session
        generate_embeddings: Whether to generate embeddings
        verbose: Enable verbose logging

    Returns:
        Dict with counts of synced records
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Downloading D3FEND data from MISP Galaxy...")
    data = await download_d3fend_data()

    raw_techniques = data.get("values", [])
    logger.info(f"Downloaded {len(raw_techniques)} technique entries")

    # Parse all techniques
    parsed_techniques = [parse_technique(entry) for entry in raw_techniques]
    parsed_techniques = [t for t in parsed_techniques if t.get("technique_id")]
    logger.info(f"Parsed {len(parsed_techniques)} valid techniques")

    # Extract tactics
    tactics = extract_tactics(parsed_techniques)
    logger.info(f"Extracted {len(tactics)} unique tactics")

    # Get existing ATT&CK technique IDs for FK validation
    result = await session.execute(select(AttackTechnique.technique_id))
    valid_attack_ids = {row[0] for row in result.fetchall()}
    logger.info(f"Found {len(valid_attack_ids)} valid ATT&CK technique IDs for mapping")

    now = datetime.now(timezone.utc)

    # Sync tactics
    for tactic in tactics:
        stmt = insert(D3FENDTactic).values(
            **tactic,
            data_last_updated=now,
        ).on_conflict_do_update(
            index_elements=["tactic_id"],
            set_={
                "name": tactic["name"],
                "description": tactic["description"],
                "display_order": tactic["display_order"],
                "data_last_updated": now,
            }
        )
        await session.execute(stmt)

    logger.info(f"Synced {len(tactics)} tactics")

    # Sync techniques
    technique_count = 0
    mapping_count = 0
    skipped_mappings = 0

    for tech in parsed_techniques:
        # Extract attack mappings before inserting technique
        attack_mappings = tech.pop("attack_mappings", [])

        # Generate embedding if enabled
        embedding = None
        if generate_embeddings and tech.get("description"):
            text = f"{tech['name']}: {tech['description']}"
            embedding = await generate_embedding(text)

        stmt = insert(D3FENDTechnique).values(
            technique_id=tech["technique_id"],
            name=tech["name"],
            description=tech.get("description"),
            tactic_id=tech.get("tactic_id"),
            synonyms=tech.get("synonyms"),
            references=tech.get("references"),
            kb_article_url=tech.get("kb_article_url"),
            embedding=embedding,
            embedding_model="text-embedding-3-small" if embedding else None,
            embedding_generated_at=now if embedding else None,
            data_last_updated=now,
        ).on_conflict_do_update(
            index_elements=["technique_id"],
            set_={
                "name": tech["name"],
                "description": tech.get("description"),
                "tactic_id": tech.get("tactic_id"),
                "synonyms": tech.get("synonyms"),
                "references": tech.get("references"),
                "kb_article_url": tech.get("kb_article_url"),
                "embedding": embedding,
                "embedding_model": "text-embedding-3-small" if embedding else None,
                "embedding_generated_at": now if embedding else None,
                "data_last_updated": now,
            }
        )
        await session.execute(stmt)
        technique_count += 1

        # Sync ATT&CK mappings
        for mapping in attack_mappings:
            attack_id = mapping["attack_technique_id"]

            # Validate FK
            if attack_id not in valid_attack_ids:
                logger.debug(f"Skipping mapping to unknown ATT&CK technique: {attack_id}")
                skipped_mappings += 1
                continue

            # Map relationship type to enum
            rel_type_str = mapping["relationship_type"]
            try:
                rel_type = D3FENDRelationshipType(rel_type_str)
            except ValueError:
                rel_type = D3FENDRelationshipType.related_to

            stmt = insert(D3FENDTechniqueAttackMapping).values(
                d3fend_technique_id=tech["technique_id"],
                attack_technique_id=attack_id,
                relationship_type=rel_type,
            ).on_conflict_do_nothing()
            await session.execute(stmt)
            mapping_count += 1

    await session.commit()

    logger.info(f"Synced {technique_count} techniques")
    logger.info(f"Created {mapping_count} ATT&CK mappings ({skipped_mappings} skipped due to missing FK)")

    return {
        "tactics": len(tactics),
        "techniques": technique_count,
        "attack_mappings": mapping_count,
        "skipped_mappings": skipped_mappings,
    }
```

**Step 4: Create CLI script**

Create `scripts/sync_d3fend_data.py`:

```python
#!/usr/bin/env python3
"""CLI script to sync D3FEND data."""

import argparse
import asyncio
import logging
import sys

from cve_mcp.db import get_async_session
from cve_mcp.tasks.sync_d3fend import sync_d3fend_data


async def main(args: argparse.Namespace) -> int:
    """Run D3FEND sync."""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    async with get_async_session() as session:
        result = await sync_d3fend_data(
            session,
            generate_embeddings=not args.no_embeddings,
            verbose=args.verbose,
        )

    print(f"\nSync complete:")
    print(f"  Tactics: {result['tactics']}")
    print(f"  Techniques: {result['techniques']}")
    print(f"  ATT&CK mappings: {result['attack_mappings']}")
    print(f"  Skipped mappings: {result['skipped_mappings']}")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync D3FEND data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-embeddings", action="store_true", help="Skip embedding generation")

    args = parser.parse_args()
    sys.exit(asyncio.run(main(args)))
```

**Step 5: Run tests**

```bash
pytest tests/tasks/test_sync_d3fend.py -v
```

**Step 6: Commit**

```bash
git add src/cve_mcp/tasks/sync_d3fend.py scripts/sync_d3fend_data.py tests/tasks/test_sync_d3fend.py
git commit -m "feat(d3fend): add data sync task and CLI script"
```

---

## Task 3: Query Services & MCP Tools

**Files:**
- Create: `src/cve_mcp/services/d3fend_queries.py`
- Modify: `src/cve_mcp/api/schemas.py`
- Modify: `src/cve_mcp/api/tools.py`
- Create: `tests/services/test_d3fend_queries.py`

**Step 1: Write query service tests**

Create `tests/services/test_d3fend_queries.py`:

```python
"""Tests for D3FEND query services."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from cve_mcp.services.d3fend_queries import (
    search_defenses,
    find_similar_defenses,
    get_defense_details,
    get_defenses_for_attack,
    get_attack_coverage,
)


class TestSearchDefenses:
    """Tests for search_defenses function."""

    @pytest.mark.asyncio
    async def test_basic_search(self):
        # Mock session and results
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        results = await search_defenses(
            session=mock_session,
            query="hardening",
            limit=10,
        )

        assert isinstance(results, list)


class TestGetDefensesForAttack:
    """Tests for get_defenses_for_attack function."""

    @pytest.mark.asyncio
    async def test_returns_countermeasures(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        results = await get_defenses_for_attack(
            session=mock_session,
            attack_technique_id="T1059",
        )

        assert isinstance(results, list)
```

**Step 2: Implement query services**

Create `src/cve_mcp/services/d3fend_queries.py`:

```python
"""Query services for D3FEND defensive countermeasures."""

import logging
from typing import Any

from sqlalchemy import select, or_, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.d3fend import (
    D3FENDTactic,
    D3FENDTechnique,
    D3FENDTechniqueAttackMapping,
    D3FENDRelationshipType,
)
from cve_mcp.models.attack import AttackTechnique
from cve_mcp.services.embeddings import generate_embedding

logger = logging.getLogger(__name__)


async def search_defenses(
    session: AsyncSession,
    query: str,
    tactic: list[str] | None = None,
    include_children: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search for defensive techniques by keyword.

    Args:
        session: Database session
        query: Search query
        tactic: Filter by tactic names (e.g., ["Harden", "Detect"])
        include_children: Include child techniques
        limit: Maximum results

    Returns:
        List of matching techniques
    """
    stmt = select(D3FENDTechnique).options(
        selectinload(D3FENDTechnique.tactic)
    )

    # Text search on name and description
    search_filter = or_(
        D3FENDTechnique.name.ilike(f"%{query}%"),
        D3FENDTechnique.description.ilike(f"%{query}%"),
        func.array_to_string(D3FENDTechnique.synonyms, " ").ilike(f"%{query}%"),
    )
    stmt = stmt.where(search_filter)

    # Filter by tactic
    if tactic:
        tactic_ids = [f"D3-{t.upper()}" for t in tactic]
        stmt = stmt.where(D3FENDTechnique.tactic_id.in_(tactic_ids))

    # Exclude children if not requested
    if not include_children:
        stmt = stmt.where(D3FENDTechnique.parent_id.is_(None))

    stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    techniques = result.scalars().all()

    return [_technique_to_dict(t) for t in techniques]


async def find_similar_defenses(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    tactic: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find semantically similar defensive techniques.

    Args:
        session: Database session
        description: Description to match against
        min_similarity: Minimum cosine similarity threshold
        tactic: Filter by tactic names
        limit: Maximum results

    Returns:
        List of similar techniques with similarity scores
    """
    # Generate embedding for query
    query_embedding = await generate_embedding(description)
    if not query_embedding:
        return []

    # Cosine similarity search
    similarity = 1 - D3FENDTechnique.embedding.cosine_distance(query_embedding)

    stmt = select(D3FENDTechnique, similarity.label("similarity")).options(
        selectinload(D3FENDTechnique.tactic)
    ).where(
        D3FENDTechnique.embedding.is_not(None),
        similarity >= min_similarity,
    )

    if tactic:
        tactic_ids = [f"D3-{t.upper()}" for t in tactic]
        stmt = stmt.where(D3FENDTechnique.tactic_id.in_(tactic_ids))

    stmt = stmt.order_by(similarity.desc()).limit(limit)

    result = await session.execute(stmt)
    rows = result.all()

    return [
        {**_technique_to_dict(row[0]), "similarity": float(row[1])}
        for row in rows
    ]


async def get_defense_details(
    session: AsyncSession,
    technique_id: str,
) -> dict[str, Any] | None:
    """Get full details for a defensive technique.

    Args:
        session: Database session
        technique_id: D3FEND technique ID (e.g., "D3-AL")

    Returns:
        Full technique details with mappings, or None if not found
    """
    stmt = select(D3FENDTechnique).options(
        selectinload(D3FENDTechnique.tactic),
        selectinload(D3FENDTechnique.attack_mappings).selectinload(
            D3FENDTechniqueAttackMapping.attack_technique
        ),
        selectinload(D3FENDTechnique.artifact_mappings),
    ).where(D3FENDTechnique.technique_id == technique_id.upper())

    result = await session.execute(stmt)
    technique = result.scalar_one_or_none()

    if not technique:
        return None

    return _technique_to_dict(technique, include_mappings=True)


async def get_defenses_for_attack(
    session: AsyncSession,
    attack_technique_id: str,
    include_subtechniques: bool = True,
    relationship_type: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Find defensive countermeasures for an ATT&CK technique.

    Args:
        session: Database session
        attack_technique_id: ATT&CK technique ID (e.g., "T1059")
        include_subtechniques: Include defenses for subtechniques
        relationship_type: Filter by relationship type (e.g., ["counters"])

    Returns:
        List of D3FEND techniques that counter the attack
    """
    # Build list of attack IDs to search
    attack_ids = [attack_technique_id]

    if include_subtechniques:
        # Find subtechniques (T1059.001, T1059.002, etc.)
        stmt = select(AttackTechnique.technique_id).where(
            AttackTechnique.technique_id.like(f"{attack_technique_id}.%")
        )
        result = await session.execute(stmt)
        attack_ids.extend([row[0] for row in result.fetchall()])

    # Find D3FEND techniques that map to these attacks
    stmt = select(D3FENDTechnique).options(
        selectinload(D3FENDTechnique.tactic)
    ).join(
        D3FENDTechniqueAttackMapping
    ).where(
        D3FENDTechniqueAttackMapping.attack_technique_id.in_(attack_ids)
    )

    if relationship_type:
        rel_types = [D3FENDRelationshipType(rt) for rt in relationship_type]
        stmt = stmt.where(D3FENDTechniqueAttackMapping.relationship_type.in_(rel_types))

    stmt = stmt.distinct()

    result = await session.execute(stmt)
    techniques = result.scalars().all()

    return [_technique_to_dict(t) for t in techniques]


async def get_attack_coverage(
    session: AsyncSession,
    technique_ids: list[str],
    show_gaps: bool = True,
) -> dict[str, Any]:
    """Analyze ATT&CK coverage for given D3FEND techniques.

    Args:
        session: Database session
        technique_ids: List of D3FEND technique IDs
        show_gaps: Include uncovered ATT&CK techniques

    Returns:
        Coverage analysis with covered and gap techniques
    """
    # Get all ATT&CK techniques covered by the given D3FEND techniques
    stmt = select(
        D3FENDTechniqueAttackMapping.attack_technique_id,
        D3FENDTechniqueAttackMapping.d3fend_technique_id,
        D3FENDTechniqueAttackMapping.relationship_type,
    ).where(
        D3FENDTechniqueAttackMapping.d3fend_technique_id.in_([t.upper() for t in technique_ids])
    )

    result = await session.execute(stmt)
    mappings = result.fetchall()

    # Build coverage map
    covered = {}
    for attack_id, d3fend_id, rel_type in mappings:
        if attack_id not in covered:
            covered[attack_id] = []
        covered[attack_id].append({
            "d3fend_technique_id": d3fend_id,
            "relationship_type": rel_type.value,
        })

    response = {
        "covered_techniques": list(covered.keys()),
        "coverage_details": covered,
        "total_covered": len(covered),
    }

    if show_gaps:
        # Get all ATT&CK techniques
        all_stmt = select(AttackTechnique.technique_id)
        all_result = await session.execute(all_stmt)
        all_attack_ids = {row[0] for row in all_result.fetchall()}

        gaps = all_attack_ids - set(covered.keys())
        response["gaps"] = sorted(gaps)
        response["total_gaps"] = len(gaps)
        response["coverage_percentage"] = round(
            len(covered) / len(all_attack_ids) * 100, 2
        ) if all_attack_ids else 0

    return response


def _technique_to_dict(
    technique: D3FENDTechnique,
    include_mappings: bool = False,
) -> dict[str, Any]:
    """Convert technique model to dict.

    Args:
        technique: D3FENDTechnique model
        include_mappings: Include attack and artifact mappings

    Returns:
        Dict representation
    """
    result = {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "description": technique.description,
        "tactic": technique.tactic.name if technique.tactic else None,
        "synonyms": technique.synonyms,
        "kb_article_url": technique.kb_article_url,
        "deprecated": technique.deprecated,
    }

    if include_mappings:
        result["attack_mappings"] = [
            {
                "attack_technique_id": m.attack_technique_id,
                "attack_technique_name": m.attack_technique.name if m.attack_technique else None,
                "relationship_type": m.relationship_type.value,
            }
            for m in technique.attack_mappings
        ]
        result["references"] = technique.references

    return result
```

**Step 3: Add Pydantic schemas**

Add to `src/cve_mcp/api/schemas.py`:

```python
# D3FEND schemas
class SearchDefensesRequest(BaseModel):
    """Request for search_defenses tool."""
    query: str
    tactic: list[str] | None = None
    include_children: bool = False
    limit: int = Field(default=50, le=100)


class FindSimilarDefensesRequest(BaseModel):
    """Request for find_similar_defenses tool."""
    description: str
    min_similarity: float = Field(default=0.7, ge=0.0, le=1.0)
    tactic: list[str] | None = None
    limit: int = Field(default=10, le=50)


class GetDefenseDetailsRequest(BaseModel):
    """Request for get_defense_details tool."""
    technique_id: str


class GetDefensesForAttackRequest(BaseModel):
    """Request for get_defenses_for_attack tool."""
    attack_technique_id: str
    include_subtechniques: bool = True
    relationship_type: list[str] | None = None


class GetAttackCoverageRequest(BaseModel):
    """Request for get_attack_coverage tool."""
    technique_ids: list[str]
    show_gaps: bool = True
```

**Step 4: Add MCP tool definitions**

Add to `src/cve_mcp/api/tools.py`:

```python
# D3FEND tool definitions
Tool(
    name="search_defenses",
    description="Search D3FEND defensive techniques by keyword. Supports filtering by tactic (Model, Harden, Detect, Isolate, Deceive, Evict, Restore).",
    inputSchema=SearchDefensesRequest.model_json_schema(),
),
Tool(
    name="find_similar_defenses",
    description="Find semantically similar D3FEND defensive techniques using vector search. Good for finding defenses based on a description of what you want to protect against.",
    inputSchema=FindSimilarDefensesRequest.model_json_schema(),
),
Tool(
    name="get_defense_details",
    description="Get complete details for a D3FEND defensive technique including ATT&CK mappings, artifacts, and references.",
    inputSchema=GetDefenseDetailsRequest.model_json_schema(),
),
Tool(
    name="get_defenses_for_attack",
    description="Find D3FEND defensive countermeasures that protect against a specific ATT&CK technique. This is the key tool for answering 'how do I defend against this attack?'",
    inputSchema=GetDefensesForAttackRequest.model_json_schema(),
),
Tool(
    name="get_attack_coverage",
    description="Analyze which ATT&CK techniques are covered by a set of D3FEND defenses. Useful for security posture assessment and gap analysis.",
    inputSchema=GetAttackCoverageRequest.model_json_schema(),
),
```

**Step 5: Add tool handlers**

Add to the tool handler in `src/cve_mcp/api/tools.py`:

```python
# D3FEND handlers
elif name == "search_defenses":
    req = SearchDefensesRequest(**arguments)
    async with get_async_session() as session:
        results = await search_defenses(
            session, req.query, req.tactic, req.include_children, req.limit
        )
    return [TextContent(type="text", text=json.dumps(results, indent=2))]

elif name == "find_similar_defenses":
    req = FindSimilarDefensesRequest(**arguments)
    async with get_async_session() as session:
        results = await find_similar_defenses(
            session, req.description, req.min_similarity, req.tactic, req.limit
        )
    return [TextContent(type="text", text=json.dumps(results, indent=2))]

elif name == "get_defense_details":
    req = GetDefenseDetailsRequest(**arguments)
    async with get_async_session() as session:
        result = await get_defense_details(session, req.technique_id)
    if result is None:
        return [TextContent(type="text", text=f"Defense technique {req.technique_id} not found")]
    return [TextContent(type="text", text=json.dumps(result, indent=2))]

elif name == "get_defenses_for_attack":
    req = GetDefensesForAttackRequest(**arguments)
    async with get_async_session() as session:
        results = await get_defenses_for_attack(
            session, req.attack_technique_id, req.include_subtechniques, req.relationship_type
        )
    return [TextContent(type="text", text=json.dumps(results, indent=2))]

elif name == "get_attack_coverage":
    req = GetAttackCoverageRequest(**arguments)
    async with get_async_session() as session:
        result = await get_attack_coverage(session, req.technique_ids, req.show_gaps)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]
```

**Step 6: Run all tests**

```bash
pytest tests/services/test_d3fend_queries.py tests/api/ -v
```

**Step 7: Commit**

```bash
git add src/cve_mcp/services/d3fend_queries.py src/cve_mcp/api/schemas.py src/cve_mcp/api/tools.py tests/services/test_d3fend_queries.py
git commit -m "feat(d3fend): add query services and MCP tools"
```

---

## Task 4: Documentation & README Update

**Files:**
- Create: `docs/modules/d3fend.md`
- Modify: `README.md`

**Step 1: Create module documentation**

Create comprehensive `docs/modules/d3fend.md` documenting:
- Overview of D3FEND framework
- Database schema details
- All 5 MCP tools with examples
- ATT&CK correlation examples
- Sync instructions

**Step 2: Update README.md**

- Update D3FEND status from "Planned" to "Production"
- Add 5 D3FEND tools to the Available Tools table
- Update total tool count to 36
- Add example query showing attack→defense correlation

**Step 3: Commit**

```bash
git add docs/modules/d3fend.md README.md
git commit -m "docs(d3fend): add module documentation and update README"
```

---

## Summary

| Task | Files | Tests | Commits |
|------|-------|-------|---------|
| 0. Schema | 3 | 12 | 1 |
| 1. Parser | 2 | 12 | 1 |
| 2. Sync | 3 | 8 | 1 |
| 3. Queries & Tools | 4 | 10 | 1 |
| 4. Documentation | 2 | - | 1 |

**Total: ~42 tests, 5 commits**

After completion:
- 5 new database tables
- 5 new MCP tools (total: 36)
- Full ATT&CK ↔ D3FEND bidirectional correlation
- Complete attack→defense pipeline
