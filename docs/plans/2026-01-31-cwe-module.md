# MITRE CWE Module Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add MITRE CWE (Common Weakness Enumeration) framework with semantic search, hierarchical navigation, external mappings (OWASP, SANS), and bidirectional CAPEC correlation.

**Architecture:** Unlike ATT&CK/ATLAS/CAPEC which use STIX 2.1 JSON, CWE uses XML format requiring a new parser. Database schema follows established patterns with 5 tables (weaknesses, categories, views, join table, external mappings). Actionable intelligence fields (mitigations, consequences, detection methods) stored as JSONB. Hierarchical search enabled via parent/child arrays.

**Tech Stack:** PostgreSQL + pgvector, lxml for XML parsing, OpenAI embeddings, SQLAlchemy async, existing MCP infrastructure

**Estimated Time:** ~14 hours

---

## Background: MITRE CWE

**What is CWE?**
- Common Weakness Enumeration - catalog of software/hardware weaknesses
- ~900 weaknesses organized hierarchically
- Bridges CVEs (specific vulns) and CAPEC (attack patterns)
- Provides actionable guidance (mitigations, detection methods)

**Data Source:**
- URL: `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`
- Format: XML (custom schema, NOT STIX 2.1)
- Size: ~15MB uncompressed
- Updates: Quarterly

**Abstraction Hierarchy:**
- Pillar (9) → Class (~100) → Base (~400) → Variant (~200) → Compound (~50)
- Example: CWE-20 "Improper Input Validation" (Pillar) → CWE-74 "Injection" (Class) → CWE-89 "SQL Injection" (Base)

---

## Task 0: Database Schema - CWE Tables with Vector Embeddings

**Goal:** Create 5 database tables for CWE with pgvector support and proper indexes

**Files:**
- Create: `src/cve_mcp/models/cwe.py`
- Create: `alembic/versions/005_add_cwe_tables.py`
- Modify: `src/cve_mcp/models/__init__.py`

**Step 1: Create CWE models file**

Create `src/cve_mcp/models/cwe.py`:

```python
"""CWE (Common Weakness Enumeration) database models."""

from datetime import datetime
from typing import TYPE_CHECKING

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_mcp.models.base import Base

if TYPE_CHECKING:
    pass


class CWEView(Base):
    """CWE view definitions (organizational perspectives).

    Views like CWE-1003 (Simplified Mapping), CWE-699 (Software Development),
    CWE-1000 (Research Concepts) provide different organizational structures.
    """

    __tablename__ = "cwe_views"

    view_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CWE-1003
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    view_type: Mapped[str | None] = mapped_column(String(50))  # Graph, Explicit, Implicit
    status: Mapped[str | None] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)

    # Timestamps
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationships
    categories: Mapped[list["CWECategory"]] = relationship(
        "CWECategory", back_populates="view"
    )


class CWECategory(Base):
    """CWE category definitions within views.

    Categories group related weaknesses (e.g., CWE-310 Cryptographic Issues).
    """

    __tablename__ = "cwe_categories"

    category_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CWE-310
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    view_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_views.view_id", ondelete="CASCADE"), nullable=False
    )

    # Timestamps
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Relationships
    view: Mapped["CWEView"] = relationship("CWEView", back_populates="categories")

    __table_args__ = (Index("idx_cwe_category_view", view_id),)


class CWEWeakness(Base):
    """MITRE CWE weakness definitions with semantic search.

    CWE provides a comprehensive catalog of software and hardware
    weakness types with actionable intelligence for developers.
    """

    __tablename__ = "cwe_weaknesses"

    # Primary identification
    cwe_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # CWE-79
    weakness_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)  # 79

    # Semantic search (1536 dimensions for text-embedding-3-small)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))
    embedding_model: Mapped[str | None] = mapped_column(String(50))
    embedding_generated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Core fields
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    extended_description: Mapped[str | None] = mapped_column(Text)

    # Abstraction hierarchy: Pillar > Class > Base > Variant > Compound
    abstraction: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str | None] = mapped_column(String(20))  # Draft, Incomplete, Stable, Deprecated

    # Actionable intelligence (JSONB for structured data)
    common_consequences: Mapped[dict | None] = mapped_column(JSONB)  # [{scope, impact, likelihood}]
    potential_mitigations: Mapped[dict | None] = mapped_column(JSONB)  # [{phase, strategy, description}]
    detection_methods: Mapped[dict | None] = mapped_column(JSONB)  # [{method, effectiveness, description}]
    likelihood_of_exploit: Mapped[str | None] = mapped_column(String(20))  # High, Medium, Low

    # Hierarchical relationships
    parent_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ["CWE-20", "CWE-74"]
    child_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    peer_of: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    can_precede: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    can_follow: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Cross-framework mappings
    related_attack_patterns: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # CAPEC IDs

    # Timestamps
    created: Mapped[datetime | None] = mapped_column(DateTime)
    modified: Mapped[datetime | None] = mapped_column(DateTime)
    data_last_updated: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    # Metadata
    cwe_version: Mapped[str | None] = mapped_column(String(20))  # Dataset version e.g., "4.14"
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def badge_url(self) -> str:
        """URL to official CWE page."""
        return f"https://cwe.mitre.org/data/definitions/{self.weakness_id}.html"

    __table_args__ = (
        # Vector similarity search (IVFFlat for ~900 weaknesses)
        Index(
            "idx_cwe_weakness_embedding",
            embedding,
            postgresql_using="ivfflat",
            postgresql_with={"lists": 100},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        # Hierarchical relationship queries
        Index("idx_cwe_parent_of", parent_of, postgresql_using="gin"),
        Index("idx_cwe_child_of", child_of, postgresql_using="gin"),
        Index("idx_cwe_peer_of", peer_of, postgresql_using="gin"),
        # Cross-framework queries
        Index("idx_cwe_related_capec", related_attack_patterns, postgresql_using="gin"),
        # Fast integer lookups for CVE joins
        Index("idx_cwe_weakness_id", weakness_id),
        # Abstraction filtering
        Index("idx_cwe_abstraction", abstraction),
        # High-risk weaknesses
        Index(
            "idx_cwe_high_likelihood",
            cwe_id,
            postgresql_where=(likelihood_of_exploit == "High"),
        ),
    )


class CWEWeaknessCategory(Base):
    """Many-to-many join table: weakness ↔ category with view tracking.

    Same weakness can appear in different categories across different views.
    """

    __tablename__ = "cwe_weakness_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    weakness_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"), nullable=False
    )
    category_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_categories.category_id", ondelete="CASCADE"), nullable=False
    )
    view_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_views.view_id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (
        Index("idx_cwe_wc_weakness", weakness_id),
        Index("idx_cwe_wc_category", category_id),
        Index("idx_cwe_wc_view", view_id),
        Index("idx_cwe_wc_unique", weakness_id, category_id, view_id, unique=True),
    )


class CWEExternalMapping(Base):
    """External standard mappings (OWASP Top 10, SANS Top 25, etc.)."""

    __tablename__ = "cwe_external_mappings"

    mapping_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    weakness_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"), nullable=False
    )
    external_source: Mapped[str] = mapped_column(String(100), nullable=False)  # "OWASP Top Ten 2021"
    external_id: Mapped[str] = mapped_column(String(100), nullable=False)  # "A03:2021"
    mapping_type: Mapped[str | None] = mapped_column(String(50))  # Primary, Secondary
    rationale: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("idx_cwe_ext_weakness", weakness_id),
        Index("idx_cwe_ext_source_id", external_source, external_id),
    )
```

**Step 2: Update models __init__.py**

Add to `src/cve_mcp/models/__init__.py`:

```python
from cve_mcp.models.cwe import (
    CWECategory,
    CWEExternalMapping,
    CWEView,
    CWEWeakness,
    CWEWeaknessCategory,
)
```

**Step 3: Create migration file**

Create `alembic/versions/005_add_cwe_tables.py`:

```python
"""Add CWE tables.

Revision ID: 005
Revises: 004
Create Date: 2026-01-31
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create cwe_views table
    op.create_table(
        "cwe_views",
        sa.Column("view_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("view_type", sa.String(50)),
        sa.Column("status", sa.String(20)),
        sa.Column("description", sa.Text),
        sa.Column("data_last_updated", sa.DateTime, server_default=sa.func.now()),
    )

    # Create cwe_categories table
    op.create_table(
        "cwe_categories",
        sa.Column("category_id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "view_id",
            sa.String(20),
            sa.ForeignKey("cwe_views.view_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("data_last_updated", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_cwe_category_view", "cwe_categories", ["view_id"])

    # Create cwe_weaknesses table
    op.create_table(
        "cwe_weaknesses",
        sa.Column("cwe_id", sa.String(20), primary_key=True),
        sa.Column("weakness_id", sa.Integer, unique=True, nullable=False),
        sa.Column("embedding", postgresql.ARRAY(sa.Float)),  # Vector type added via raw SQL
        sa.Column("embedding_model", sa.String(50)),
        sa.Column("embedding_generated_at", sa.DateTime),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("extended_description", sa.Text),
        sa.Column("abstraction", sa.String(20)),
        sa.Column("status", sa.String(20)),
        sa.Column("common_consequences", postgresql.JSONB),
        sa.Column("potential_mitigations", postgresql.JSONB),
        sa.Column("detection_methods", postgresql.JSONB),
        sa.Column("likelihood_of_exploit", sa.String(20)),
        sa.Column("parent_of", postgresql.ARRAY(sa.Text)),
        sa.Column("child_of", postgresql.ARRAY(sa.Text)),
        sa.Column("peer_of", postgresql.ARRAY(sa.Text)),
        sa.Column("can_precede", postgresql.ARRAY(sa.Text)),
        sa.Column("can_follow", postgresql.ARRAY(sa.Text)),
        sa.Column("related_attack_patterns", postgresql.ARRAY(sa.Text)),
        sa.Column("created", sa.DateTime),
        sa.Column("modified", sa.DateTime),
        sa.Column("data_last_updated", sa.DateTime, server_default=sa.func.now()),
        sa.Column("cwe_version", sa.String(20)),
        sa.Column("deprecated", sa.Boolean, default=False),
    )

    # Convert embedding column to vector type
    op.execute("ALTER TABLE cwe_weaknesses ALTER COLUMN embedding TYPE vector(1536) USING embedding::vector(1536)")

    # Create indexes
    op.create_index("idx_cwe_weakness_id", "cwe_weaknesses", ["weakness_id"])
    op.create_index("idx_cwe_abstraction", "cwe_weaknesses", ["abstraction"])
    op.create_index(
        "idx_cwe_parent_of", "cwe_weaknesses", ["parent_of"], postgresql_using="gin"
    )
    op.create_index(
        "idx_cwe_child_of", "cwe_weaknesses", ["child_of"], postgresql_using="gin"
    )
    op.create_index(
        "idx_cwe_peer_of", "cwe_weaknesses", ["peer_of"], postgresql_using="gin"
    )
    op.create_index(
        "idx_cwe_related_capec",
        "cwe_weaknesses",
        ["related_attack_patterns"],
        postgresql_using="gin",
    )

    # IVFFlat index for semantic search (after data is loaded, needs ~100 rows)
    # This will be created by the sync task after initial data load
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_cwe_weakness_embedding
        ON cwe_weaknesses USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 100)
    """)

    # Create cwe_weakness_categories join table
    op.create_table(
        "cwe_weakness_categories",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "weakness_id",
            sa.String(20),
            sa.ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "category_id",
            sa.String(20),
            sa.ForeignKey("cwe_categories.category_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "view_id",
            sa.String(20),
            sa.ForeignKey("cwe_views.view_id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    op.create_index("idx_cwe_wc_weakness", "cwe_weakness_categories", ["weakness_id"])
    op.create_index("idx_cwe_wc_category", "cwe_weakness_categories", ["category_id"])
    op.create_index("idx_cwe_wc_view", "cwe_weakness_categories", ["view_id"])
    op.create_index(
        "idx_cwe_wc_unique",
        "cwe_weakness_categories",
        ["weakness_id", "category_id", "view_id"],
        unique=True,
    )

    # Create cwe_external_mappings table
    op.create_table(
        "cwe_external_mappings",
        sa.Column("mapping_id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "weakness_id",
            sa.String(20),
            sa.ForeignKey("cwe_weaknesses.cwe_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_source", sa.String(100), nullable=False),
        sa.Column("external_id", sa.String(100), nullable=False),
        sa.Column("mapping_type", sa.String(50)),
        sa.Column("rationale", sa.Text),
    )
    op.create_index("idx_cwe_ext_weakness", "cwe_external_mappings", ["weakness_id"])
    op.create_index(
        "idx_cwe_ext_source_id",
        "cwe_external_mappings",
        ["external_source", "external_id"],
    )


def downgrade() -> None:
    op.drop_table("cwe_external_mappings")
    op.drop_table("cwe_weakness_categories")
    op.drop_table("cwe_weaknesses")
    op.drop_table("cwe_categories")
    op.drop_table("cwe_views")
```

**Step 4: Run migration**

Run: `alembic upgrade head`
Expected: Migration completes successfully

**Step 5: Verify schema**

Run: `python -c "from cve_mcp.models.cwe import CWEWeakness, CWECategory, CWEView, CWEWeaknessCategory, CWEExternalMapping; print('Models loaded successfully')"`
Expected: "Models loaded successfully"

**Step 6: Commit**

```bash
git add src/cve_mcp/models/cwe.py src/cve_mcp/models/__init__.py alembic/versions/005_add_cwe_tables.py
git commit -m "feat(cwe): add database schema with pgvector semantic search"
```

---

## Task 1: XML Parser for CWE Data

**Goal:** Create XML parser for CWE data (unlike STIX JSON used by ATT&CK/ATLAS/CAPEC)

**Files:**
- Create: `src/cve_mcp/ingest/cwe_parser.py`
- Create: `tests/ingest/test_cwe_parser.py`

**Step 1: Write failing parser tests**

Create `tests/ingest/test_cwe_parser.py`:

```python
"""Tests for CWE XML parser."""

import pytest
from lxml import etree

from cve_mcp.ingest.cwe_parser import (
    parse_weakness,
    parse_category,
    parse_view,
    parse_external_mapping,
)


class TestParseWeakness:
    """Tests for parse_weakness function."""

    def test_parse_weakness_basic(self):
        """Test parsing basic weakness fields."""
        xml = """
        <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation"
                  Abstraction="Base" Status="Stable">
            <Description>The product does not neutralize user-controllable input.</Description>
            <Extended_Description>This weakness describes a broad category.</Extended_Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["cwe_id"] == "CWE-79"
        assert result["weakness_id"] == 79
        assert result["name"] == "Improper Neutralization of Input During Web Page Generation"
        assert result["abstraction"] == "Base"
        assert result["status"] == "Stable"
        assert "does not neutralize" in result["description"]

    def test_parse_weakness_with_consequences(self):
        """Test parsing weakness with common consequences."""
        xml = """
        <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
            <Description>SQL injection vulnerability.</Description>
            <Common_Consequences>
                <Consequence>
                    <Scope>Confidentiality</Scope>
                    <Impact>Read Application Data</Impact>
                </Consequence>
                <Consequence>
                    <Scope>Integrity</Scope>
                    <Impact>Modify Application Data</Impact>
                </Consequence>
            </Common_Consequences>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["common_consequences"] is not None
        assert len(result["common_consequences"]) == 2
        assert result["common_consequences"][0]["scope"] == "Confidentiality"
        assert result["common_consequences"][0]["impact"] == "Read Application Data"

    def test_parse_weakness_with_mitigations(self):
        """Test parsing weakness with potential mitigations."""
        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability.</Description>
            <Potential_Mitigations>
                <Mitigation>
                    <Phase>Implementation</Phase>
                    <Strategy>Input Validation</Strategy>
                    <Description>Validate all input before use.</Description>
                </Mitigation>
            </Potential_Mitigations>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["potential_mitigations"] is not None
        assert len(result["potential_mitigations"]) == 1
        assert result["potential_mitigations"][0]["phase"] == "Implementation"
        assert result["potential_mitigations"][0]["strategy"] == "Input Validation"

    def test_parse_weakness_with_detection_methods(self):
        """Test parsing weakness with detection methods."""
        xml = """
        <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
            <Description>SQL injection vulnerability.</Description>
            <Detection_Methods>
                <Detection_Method>
                    <Method>Automated Static Analysis</Method>
                    <Effectiveness>High</Effectiveness>
                    <Description>Use SAST tools to detect.</Description>
                </Detection_Method>
            </Detection_Methods>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["detection_methods"] is not None
        assert len(result["detection_methods"]) == 1
        assert result["detection_methods"][0]["method"] == "Automated Static Analysis"
        assert result["detection_methods"][0]["effectiveness"] == "High"

    def test_parse_weakness_with_relationships(self):
        """Test parsing weakness with hierarchical relationships."""
        xml = """
        <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
            <Description>SQL injection vulnerability.</Description>
            <Related_Weaknesses>
                <Related_Weakness Nature="ChildOf" CWE_ID="74"/>
                <Related_Weakness Nature="ParentOf" CWE_ID="564"/>
                <Related_Weakness Nature="PeerOf" CWE_ID="77"/>
            </Related_Weaknesses>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["child_of"] == ["CWE-74"]
        assert result["parent_of"] == ["CWE-564"]
        assert result["peer_of"] == ["CWE-77"]

    def test_parse_weakness_deprecated(self):
        """Test parsing deprecated weakness."""
        xml = """
        <Weakness ID="999" Name="Deprecated Weakness" Abstraction="Base" Status="Deprecated">
            <Description>This weakness is deprecated.</Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["status"] == "Deprecated"
        assert result["deprecated"] is True

    def test_parse_weakness_with_taxonomy_mappings(self):
        """Test parsing weakness with external taxonomy mappings."""
        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability.</Description>
            <Taxonomy_Mappings>
                <Taxonomy_Mapping Taxonomy_Name="OWASP Top Ten 2021">
                    <Entry_ID>A03:2021</Entry_ID>
                    <Entry_Name>Injection</Entry_Name>
                </Taxonomy_Mapping>
                <Taxonomy_Mapping Taxonomy_Name="SANS Top 25">
                    <Entry_ID>1</Entry_ID>
                </Taxonomy_Mapping>
            </Taxonomy_Mappings>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["taxonomy_mappings"] is not None
        assert len(result["taxonomy_mappings"]) == 2


class TestParseCategory:
    """Tests for parse_category function."""

    def test_parse_category_basic(self):
        """Test parsing basic category."""
        xml = """
        <Category ID="310" Name="Cryptographic Issues" Status="Draft">
            <Summary>Weaknesses related to cryptographic issues.</Summary>
        </Category>
        """
        element = etree.fromstring(xml)
        result = parse_category(element)

        assert result is not None
        assert result["category_id"] == "CWE-310"
        assert result["name"] == "Cryptographic Issues"
        assert "cryptographic" in result["description"].lower()


class TestParseView:
    """Tests for parse_view function."""

    def test_parse_view_basic(self):
        """Test parsing basic view."""
        xml = """
        <View ID="1003" Name="Weaknesses for Simplified Mapping of Published Vulnerabilities"
              Type="Graph" Status="Stable">
            <Objective>Provide a simplified view for CVE mapping.</Objective>
        </View>
        """
        element = etree.fromstring(xml)
        result = parse_view(element)

        assert result is not None
        assert result["view_id"] == "CWE-1003"
        assert result["name"] == "Weaknesses for Simplified Mapping of Published Vulnerabilities"
        assert result["view_type"] == "Graph"


class TestParseExternalMapping:
    """Tests for parse_external_mapping function."""

    def test_parse_owasp_mapping(self):
        """Test parsing OWASP Top 10 mapping."""
        mapping_data = {
            "taxonomy_name": "OWASP Top Ten 2021",
            "entry_id": "A03:2021",
            "entry_name": "Injection",
        }
        result = parse_external_mapping("CWE-79", mapping_data)

        assert result is not None
        assert result["weakness_id"] == "CWE-79"
        assert result["external_source"] == "OWASP Top Ten 2021"
        assert result["external_id"] == "A03:2021"


class TestParserEdgeCases:
    """Edge case tests for parser."""

    def test_parse_weakness_missing_optional_fields(self):
        """Test parsing weakness with minimal fields."""
        xml = """
        <Weakness ID="1" Name="Test" Abstraction="Class" Status="Draft">
            <Description>Test description.</Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["common_consequences"] is None
        assert result["potential_mitigations"] is None
        assert result["detection_methods"] is None

    def test_parse_weakness_all_abstraction_levels(self):
        """Test parsing all abstraction levels."""
        for level in ["Pillar", "Class", "Base", "Variant", "Compound"]:
            xml = f"""
            <Weakness ID="1" Name="Test" Abstraction="{level}" Status="Stable">
                <Description>Test.</Description>
            </Weakness>
            """
            element = etree.fromstring(xml)
            result = parse_weakness(element)
            assert result["abstraction"] == level

    def test_parse_weakness_with_likelihood(self):
        """Test parsing weakness with likelihood of exploit."""
        xml = """
        <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
            <Description>SQL injection.</Description>
            <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["likelihood_of_exploit"] == "High"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/ingest/test_cwe_parser.py -v`
Expected: FAIL (module not found)

**Step 3: Create the parser implementation**

Create `src/cve_mcp/ingest/cwe_parser.py`:

```python
"""MITRE CWE XML parser.

Parses CWE XML data from MITRE into database models.
Unlike ATT&CK/ATLAS/CAPEC which use STIX 2.1 JSON, CWE uses custom XML format.
"""

from typing import Any

from lxml import etree


def _get_text(element: etree._Element | None) -> str | None:
    """Extract text content from an element, stripping whitespace."""
    if element is None:
        return None
    text = element.text
    if text:
        return text.strip()
    return None


def _get_all_text(element: etree._Element | None) -> str | None:
    """Extract all text content including nested elements."""
    if element is None:
        return None
    # Get all text including tail text of children
    text_parts = []
    if element.text:
        text_parts.append(element.text.strip())
    for child in element:
        if child.text:
            text_parts.append(child.text.strip())
        if child.tail:
            text_parts.append(child.tail.strip())
    return " ".join(text_parts) if text_parts else None


def parse_weakness(element: etree._Element) -> dict[str, Any] | None:
    """Parse CWE weakness element.

    Args:
        element: lxml Element for a Weakness

    Returns:
        Dictionary with weakness data ready for CWEWeakness model,
        or None if invalid
    """
    weakness_id_str = element.get("ID")
    if not weakness_id_str:
        return None

    try:
        weakness_id = int(weakness_id_str)
    except ValueError:
        return None

    cwe_id = f"CWE-{weakness_id}"
    name = element.get("Name", "")
    abstraction = element.get("Abstraction")
    status = element.get("Status")

    # Core text fields
    description = _get_all_text(element.find("Description")) or ""
    extended_description = _get_all_text(element.find("Extended_Description"))

    # Likelihood of exploit
    likelihood_elem = element.find("Likelihood_Of_Exploit")
    likelihood_of_exploit = _get_text(likelihood_elem)

    # Parse common consequences
    common_consequences = None
    consequences_elem = element.find("Common_Consequences")
    if consequences_elem is not None:
        common_consequences = []
        for consequence in consequences_elem.findall("Consequence"):
            cons_data = {
                "scope": _get_text(consequence.find("Scope")),
                "impact": _get_text(consequence.find("Impact")),
                "likelihood": _get_text(consequence.find("Likelihood")),
                "note": _get_text(consequence.find("Note")),
            }
            # Filter out None values
            cons_data = {k: v for k, v in cons_data.items() if v is not None}
            if cons_data:
                common_consequences.append(cons_data)
        if not common_consequences:
            common_consequences = None

    # Parse potential mitigations
    potential_mitigations = None
    mitigations_elem = element.find("Potential_Mitigations")
    if mitigations_elem is not None:
        potential_mitigations = []
        for mitigation in mitigations_elem.findall("Mitigation"):
            mit_data = {
                "phase": _get_text(mitigation.find("Phase")),
                "strategy": _get_text(mitigation.find("Strategy")),
                "effectiveness": _get_text(mitigation.find("Effectiveness")),
                "description": _get_all_text(mitigation.find("Description")),
            }
            mit_data = {k: v for k, v in mit_data.items() if v is not None}
            if mit_data:
                potential_mitigations.append(mit_data)
        if not potential_mitigations:
            potential_mitigations = None

    # Parse detection methods
    detection_methods = None
    detection_elem = element.find("Detection_Methods")
    if detection_elem is not None:
        detection_methods = []
        for method in detection_elem.findall("Detection_Method"):
            det_data = {
                "method": _get_text(method.find("Method")),
                "effectiveness": _get_text(method.find("Effectiveness")),
                "description": _get_all_text(method.find("Description")),
            }
            det_data = {k: v for k, v in det_data.items() if v is not None}
            if det_data:
                detection_methods.append(det_data)
        if not detection_methods:
            detection_methods = None

    # Parse relationships
    parent_of = []
    child_of = []
    peer_of = []
    can_precede = []
    can_follow = []

    related_elem = element.find("Related_Weaknesses")
    if related_elem is not None:
        for related in related_elem.findall("Related_Weakness"):
            nature = related.get("Nature")
            related_cwe_id = related.get("CWE_ID")
            if related_cwe_id:
                cwe_ref = f"CWE-{related_cwe_id}"
                if nature == "ParentOf":
                    parent_of.append(cwe_ref)
                elif nature == "ChildOf":
                    child_of.append(cwe_ref)
                elif nature == "PeerOf":
                    peer_of.append(cwe_ref)
                elif nature == "CanPrecede":
                    can_precede.append(cwe_ref)
                elif nature == "CanFollow":
                    can_follow.append(cwe_ref)

    # Parse taxonomy mappings (for external standards like OWASP, SANS)
    taxonomy_mappings = None
    taxonomy_elem = element.find("Taxonomy_Mappings")
    if taxonomy_elem is not None:
        taxonomy_mappings = []
        for mapping in taxonomy_elem.findall("Taxonomy_Mapping"):
            tax_data = {
                "taxonomy_name": mapping.get("Taxonomy_Name"),
                "entry_id": _get_text(mapping.find("Entry_ID")),
                "entry_name": _get_text(mapping.find("Entry_Name")),
            }
            tax_data = {k: v for k, v in tax_data.items() if v is not None}
            if tax_data:
                taxonomy_mappings.append(tax_data)
        if not taxonomy_mappings:
            taxonomy_mappings = None

    return {
        "cwe_id": cwe_id,
        "weakness_id": weakness_id,
        "name": name,
        "description": description,
        "extended_description": extended_description,
        "abstraction": abstraction,
        "status": status,
        "common_consequences": common_consequences,
        "potential_mitigations": potential_mitigations,
        "detection_methods": detection_methods,
        "likelihood_of_exploit": likelihood_of_exploit,
        "parent_of": parent_of if parent_of else None,
        "child_of": child_of if child_of else None,
        "peer_of": peer_of if peer_of else None,
        "can_precede": can_precede if can_precede else None,
        "can_follow": can_follow if can_follow else None,
        "taxonomy_mappings": taxonomy_mappings,
        "deprecated": status == "Deprecated",
    }


def parse_category(element: etree._Element) -> dict[str, Any] | None:
    """Parse CWE category element.

    Args:
        element: lxml Element for a Category

    Returns:
        Dictionary with category data ready for CWECategory model,
        or None if invalid
    """
    category_id_str = element.get("ID")
    if not category_id_str:
        return None

    try:
        int(category_id_str)  # Validate it's a number
    except ValueError:
        return None

    category_id = f"CWE-{category_id_str}"
    name = element.get("Name", "")
    status = element.get("Status")

    # Description comes from Summary element in categories
    description = _get_all_text(element.find("Summary"))

    return {
        "category_id": category_id,
        "name": name,
        "description": description,
        "status": status,
    }


def parse_view(element: etree._Element) -> dict[str, Any] | None:
    """Parse CWE view element.

    Args:
        element: lxml Element for a View

    Returns:
        Dictionary with view data ready for CWEView model,
        or None if invalid
    """
    view_id_str = element.get("ID")
    if not view_id_str:
        return None

    try:
        int(view_id_str)  # Validate it's a number
    except ValueError:
        return None

    view_id = f"CWE-{view_id_str}"
    name = element.get("Name", "")
    view_type = element.get("Type")
    status = element.get("Status")

    # Description comes from Objective element in views
    description = _get_all_text(element.find("Objective"))

    return {
        "view_id": view_id,
        "name": name,
        "view_type": view_type,
        "status": status,
        "description": description,
    }


def parse_external_mapping(
    weakness_id: str, mapping_data: dict[str, Any]
) -> dict[str, Any] | None:
    """Parse external taxonomy mapping for a weakness.

    Args:
        weakness_id: CWE ID (e.g., "CWE-79")
        mapping_data: Dictionary with taxonomy_name, entry_id, entry_name

    Returns:
        Dictionary ready for CWEExternalMapping model,
        or None if invalid
    """
    taxonomy_name = mapping_data.get("taxonomy_name")
    entry_id = mapping_data.get("entry_id")

    if not taxonomy_name or not entry_id:
        return None

    return {
        "weakness_id": weakness_id,
        "external_source": taxonomy_name,
        "external_id": entry_id,
        "mapping_type": "Primary",  # Could be inferred from data
        "rationale": mapping_data.get("entry_name"),
    }
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/ingest/test_cwe_parser.py -v`
Expected: All 15 tests PASS

**Step 5: Commit**

```bash
git add src/cve_mcp/ingest/cwe_parser.py tests/ingest/test_cwe_parser.py
git commit -m "feat(cwe): add XML parser for CWE data"
```

---

## Task 2: Data Sync Task

**Goal:** Create sync task to download, parse, and store CWE data with embeddings

**Files:**
- Create: `src/cve_mcp/tasks/sync_cwe.py`
- Create: `scripts/sync_cwe_data.py`
- Modify: `src/cve_mcp/tasks/__init__.py`

**Step 1: Create sync task**

Create `src/cve_mcp/tasks/sync_cwe.py`:

```python
"""CWE data synchronization task.

Downloads and processes CWE data from MITRE, generating semantic embeddings.
"""

import io
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from lxml import etree
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.ingest.cwe_parser import (
    parse_category,
    parse_external_mapping,
    parse_view,
    parse_weakness,
)
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.models.cwe import (
    CWECategory,
    CWEExternalMapping,
    CWEView,
    CWEWeakness,
    CWEWeaknessCategory,
)
from cve_mcp.services.embeddings import generate_embeddings_batch

logger = logging.getLogger(__name__)

CWE_DATA_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_CACHE_DIR = Path.home() / ".cache" / "cve-mcp" / "cwe"


async def download_cwe_data(
    cache_dir: Path = CWE_CACHE_DIR,
    force_download: bool = False,
) -> bytes:
    """Download CWE XML data from MITRE.

    Args:
        cache_dir: Directory to cache downloaded file
        force_download: Force re-download even if cached

    Returns:
        Raw XML content as bytes
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "cwec_latest.xml"

    if cache_file.exists() and not force_download:
        logger.info(f"Using cached CWE data from {cache_file}")
        return cache_file.read_bytes()

    logger.info(f"Downloading CWE data from {CWE_DATA_URL}")
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.get(CWE_DATA_URL)
        response.raise_for_status()

    # Unzip the content
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        # Find the XML file in the archive
        xml_files = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_files:
            raise ValueError("No XML file found in CWE archive")
        xml_content = zf.read(xml_files[0])

    # Cache the unzipped XML
    cache_file.write_bytes(xml_content)
    logger.info(f"Cached CWE data to {cache_file}")

    return xml_content


def parse_cwe_xml(xml_content: bytes) -> dict[str, list[dict[str, Any]]]:
    """Parse CWE XML content into structured data.

    Args:
        xml_content: Raw XML bytes

    Returns:
        Dictionary with 'weaknesses', 'categories', 'views' lists
    """
    root = etree.fromstring(xml_content)

    # Extract version from root element
    cwe_version = root.get("Version", "unknown")
    logger.info(f"Parsing CWE version {cwe_version}")

    weaknesses = []
    categories = []
    views = []

    # Parse weaknesses
    weaknesses_elem = root.find("Weaknesses")
    if weaknesses_elem is not None:
        for weakness_elem in weaknesses_elem.findall("Weakness"):
            parsed = parse_weakness(weakness_elem)
            if parsed:
                parsed["cwe_version"] = cwe_version
                weaknesses.append(parsed)

    # Parse categories
    categories_elem = root.find("Categories")
    if categories_elem is not None:
        for category_elem in categories_elem.findall("Category"):
            parsed = parse_category(category_elem)
            if parsed:
                categories.append(parsed)

    # Parse views
    views_elem = root.find("Views")
    if views_elem is not None:
        for view_elem in views_elem.findall("View"):
            parsed = parse_view(view_elem)
            if parsed:
                views.append(parsed)

    logger.info(
        f"Parsed {len(weaknesses)} weaknesses, {len(categories)} categories, {len(views)} views"
    )

    return {
        "weaknesses": weaknesses,
        "categories": categories,
        "views": views,
        "version": cwe_version,
    }


async def sync_views(session: AsyncSession, views: list[dict[str, Any]]) -> int:
    """Sync CWE views to database.

    Args:
        session: Database session
        views: List of parsed view data

    Returns:
        Number of views synced
    """
    count = 0
    for view_data in views:
        view = CWEView(
            view_id=view_data["view_id"],
            name=view_data["name"],
            view_type=view_data.get("view_type"),
            status=view_data.get("status"),
            description=view_data.get("description"),
            data_last_updated=datetime.utcnow(),
        )
        await session.merge(view)
        count += 1

    await session.commit()
    logger.info(f"Synced {count} views")
    return count


async def sync_categories(
    session: AsyncSession, categories: list[dict[str, Any]], default_view_id: str = "CWE-1000"
) -> int:
    """Sync CWE categories to database.

    Args:
        session: Database session
        categories: List of parsed category data
        default_view_id: Default view to assign categories to

    Returns:
        Number of categories synced
    """
    count = 0
    for cat_data in categories:
        category = CWECategory(
            category_id=cat_data["category_id"],
            name=cat_data["name"],
            description=cat_data.get("description"),
            view_id=default_view_id,  # Categories assigned to research view by default
            data_last_updated=datetime.utcnow(),
        )
        await session.merge(category)
        count += 1

    await session.commit()
    logger.info(f"Synced {count} categories")
    return count


async def sync_weaknesses(
    session: AsyncSession,
    weaknesses: list[dict[str, Any]],
    generate_embeddings: bool = True,
) -> int:
    """Sync CWE weaknesses to database with optional embeddings.

    Args:
        session: Database session
        weaknesses: List of parsed weakness data
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Number of weaknesses synced
    """
    count = 0

    # Prepare embedding texts
    if generate_embeddings:
        embedding_texts = []
        for w in weaknesses:
            text = f"{w['name']}: {w['description']}"
            if w.get("extended_description"):
                text += f" {w['extended_description']}"
            embedding_texts.append(text)

        logger.info(f"Generating embeddings for {len(embedding_texts)} weaknesses")
        embeddings = await generate_embeddings_batch(embedding_texts)
    else:
        embeddings = [None] * len(weaknesses)

    # Sync weaknesses
    for weakness_data, embedding in zip(weaknesses, embeddings):
        weakness = CWEWeakness(
            cwe_id=weakness_data["cwe_id"],
            weakness_id=weakness_data["weakness_id"],
            name=weakness_data["name"],
            description=weakness_data["description"],
            extended_description=weakness_data.get("extended_description"),
            abstraction=weakness_data.get("abstraction"),
            status=weakness_data.get("status"),
            common_consequences=weakness_data.get("common_consequences"),
            potential_mitigations=weakness_data.get("potential_mitigations"),
            detection_methods=weakness_data.get("detection_methods"),
            likelihood_of_exploit=weakness_data.get("likelihood_of_exploit"),
            parent_of=weakness_data.get("parent_of"),
            child_of=weakness_data.get("child_of"),
            peer_of=weakness_data.get("peer_of"),
            can_precede=weakness_data.get("can_precede"),
            can_follow=weakness_data.get("can_follow"),
            cwe_version=weakness_data.get("cwe_version"),
            deprecated=weakness_data.get("deprecated", False),
            embedding=embedding,
            embedding_model="text-embedding-3-small" if embedding else None,
            embedding_generated_at=datetime.utcnow() if embedding else None,
            data_last_updated=datetime.utcnow(),
        )
        await session.merge(weakness)
        count += 1

        if count % 100 == 0:
            logger.info(f"Synced {count}/{len(weaknesses)} weaknesses")

    await session.commit()
    logger.info(f"Synced {count} weaknesses")
    return count


async def sync_external_mappings(
    session: AsyncSession, weaknesses: list[dict[str, Any]]
) -> int:
    """Sync external mappings (OWASP, SANS, etc.) to database.

    Args:
        session: Database session
        weaknesses: List of parsed weakness data with taxonomy_mappings

    Returns:
        Number of mappings synced
    """
    # First, clear existing mappings
    await session.execute(
        CWEExternalMapping.__table__.delete()
    )

    count = 0
    for weakness_data in weaknesses:
        taxonomy_mappings = weakness_data.get("taxonomy_mappings") or []
        for mapping_data in taxonomy_mappings:
            parsed = parse_external_mapping(weakness_data["cwe_id"], mapping_data)
            if parsed:
                mapping = CWEExternalMapping(
                    weakness_id=parsed["weakness_id"],
                    external_source=parsed["external_source"],
                    external_id=parsed["external_id"],
                    mapping_type=parsed.get("mapping_type"),
                    rationale=parsed.get("rationale"),
                )
                session.add(mapping)
                count += 1

    await session.commit()
    logger.info(f"Synced {count} external mappings")
    return count


async def update_capec_cwe_links(session: AsyncSession) -> int:
    """Update CAPEC patterns with CWE linkages.

    Reads CWE references from CAPEC and updates related_attack_patterns
    on CWE weaknesses for bidirectional linking.

    Args:
        session: Database session

    Returns:
        Number of links updated
    """
    try:
        from cve_mcp.models.capec import CAPECPattern
    except ImportError:
        logger.warning("CAPEC models not available, skipping CWE-CAPEC linking")
        return 0

    # Get all CAPEC patterns with CWE references
    result = await session.execute(
        select(CAPECPattern.pattern_id, CAPECPattern.related_weaknesses).where(
            CAPECPattern.related_weaknesses.is_not(None)
        )
    )
    capec_patterns = result.all()

    # Build reverse mapping: CWE -> [CAPEC IDs]
    cwe_to_capec: dict[str, list[str]] = {}
    for pattern_id, related_weaknesses in capec_patterns:
        for cwe_id in related_weaknesses:
            if cwe_id not in cwe_to_capec:
                cwe_to_capec[cwe_id] = []
            cwe_to_capec[cwe_id].append(pattern_id)

    # Update CWE weaknesses
    count = 0
    for cwe_id, capec_ids in cwe_to_capec.items():
        result = await session.execute(
            select(CWEWeakness).where(CWEWeakness.cwe_id == cwe_id)
        )
        weakness = result.scalar_one_or_none()
        if weakness:
            weakness.related_attack_patterns = capec_ids
            count += 1

    await session.commit()
    logger.info(f"Updated {count} CWE weaknesses with CAPEC links")
    return count


async def sync_cwe_full(
    cache_dir: Path = CWE_CACHE_DIR,
    force_download: bool = False,
    generate_embeddings: bool = True,
) -> dict[str, int]:
    """Run full CWE synchronization.

    Args:
        cache_dir: Directory for cached downloads
        force_download: Force re-download of data
        generate_embeddings: Whether to generate semantic embeddings

    Returns:
        Dictionary with sync statistics
    """
    logger.info("Starting full CWE sync")

    # Download data
    xml_content = await download_cwe_data(cache_dir, force_download)

    # Parse XML
    parsed = parse_cwe_xml(xml_content)

    # Sync to database
    async with AsyncSessionLocal() as session:
        views_count = await sync_views(session, parsed["views"])
        categories_count = await sync_categories(session, parsed["categories"])
        weaknesses_count = await sync_weaknesses(
            session, parsed["weaknesses"], generate_embeddings
        )
        mappings_count = await sync_external_mappings(session, parsed["weaknesses"])
        links_count = await update_capec_cwe_links(session)

    stats = {
        "views": views_count,
        "categories": categories_count,
        "weaknesses": weaknesses_count,
        "external_mappings": mappings_count,
        "capec_links": links_count,
        "version": parsed["version"],
    }

    logger.info(f"CWE sync complete: {stats}")
    return stats
```

**Step 2: Create CLI script**

Create `scripts/sync_cwe_data.py`:

```python
#!/usr/bin/env python3
"""CLI script to sync CWE data."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cve_mcp.tasks.sync_cwe import sync_cwe_full, CWE_CACHE_DIR


def main():
    parser = argparse.ArgumentParser(description="Sync CWE data from MITRE")
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Skip generating semantic embeddings",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if cached",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=CWE_CACHE_DIR,
        help=f"Cache directory (default: {CWE_CACHE_DIR})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run sync
    stats = asyncio.run(
        sync_cwe_full(
            cache_dir=args.cache_dir,
            force_download=args.force,
            generate_embeddings=not args.no_embeddings,
        )
    )

    print("\nSync Statistics:")
    print(f"  CWE Version: {stats['version']}")
    print(f"  Views: {stats['views']}")
    print(f"  Categories: {stats['categories']}")
    print(f"  Weaknesses: {stats['weaknesses']}")
    print(f"  External Mappings: {stats['external_mappings']}")
    print(f"  CAPEC Links: {stats['capec_links']}")


if __name__ == "__main__":
    main()
```

**Step 3: Make script executable**

Run: `chmod +x scripts/sync_cwe_data.py`

**Step 4: Update tasks __init__.py**

Add to `src/cve_mcp/tasks/__init__.py`:

```python
from cve_mcp.tasks.sync_cwe import sync_cwe_full
```

**Step 5: Commit**

```bash
git add src/cve_mcp/tasks/sync_cwe.py scripts/sync_cwe_data.py src/cve_mcp/tasks/__init__.py
git commit -m "feat(cwe): add data sync with semantic embeddings"
```

---

## Task 3: Query Service and MCP Tools

**Goal:** Create query service with 6 MCP tools for CWE data

**Files:**
- Create: `src/cve_mcp/services/cwe_queries.py`
- Modify: `src/cve_mcp/api/schemas.py`
- Modify: `src/cve_mcp/api/tools.py`
- Modify: `tests/test_integration.py`

**Step 1: Create query service**

Create `src/cve_mcp/services/cwe_queries.py`:

```python
"""CWE query service with traditional and semantic search."""

import logging
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cve_mcp.models.cwe import CWEExternalMapping, CWEWeakness
from cve_mcp.services.embeddings import generate_embedding

logger = logging.getLogger(__name__)


async def search_weaknesses(
    session: AsyncSession,
    query: str | None = None,
    abstraction: list[str] | None = None,
    include_children: bool = False,
    view: str | None = None,
    active_only: bool = True,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search CWE weaknesses with traditional keyword search.

    Args:
        session: Database session
        query: Text to search in name/description
        abstraction: Filter by abstraction levels (Pillar, Class, Base, Variant, Compound)
        include_children: Include child weaknesses in results
        view: Filter by view ID (not yet implemented)
        active_only: Exclude deprecated weaknesses
        limit: Maximum results

    Returns:
        List of matching weaknesses
    """
    stmt = select(CWEWeakness)

    # Text search
    if query:
        search_pattern = f"%{query}%"
        stmt = stmt.where(
            or_(
                CWEWeakness.name.ilike(search_pattern),
                CWEWeakness.description.ilike(search_pattern),
            )
        )

    # Abstraction filter
    if abstraction:
        stmt = stmt.where(CWEWeakness.abstraction.in_(abstraction))

    # Status filter
    if active_only:
        stmt = stmt.where(CWEWeakness.deprecated.is_(False))

    stmt = stmt.order_by(CWEWeakness.weakness_id).limit(limit)

    result = await session.execute(stmt)
    weaknesses = result.scalars().all()

    # If include_children, also fetch child weaknesses
    results = []
    seen_ids = set()

    for weakness in weaknesses:
        if weakness.cwe_id not in seen_ids:
            results.append(_weakness_to_dict(weakness))
            seen_ids.add(weakness.cwe_id)

        if include_children and weakness.parent_of:
            for child_id in weakness.parent_of:
                if child_id not in seen_ids:
                    child_result = await session.execute(
                        select(CWEWeakness).where(CWEWeakness.cwe_id == child_id)
                    )
                    child = child_result.scalar_one_or_none()
                    if child:
                        results.append(_weakness_to_dict(child))
                        seen_ids.add(child_id)

    return results[:limit]


async def find_similar_weaknesses(
    session: AsyncSession,
    description: str,
    min_similarity: float = 0.7,
    abstraction: list[str] | None = None,
    active_only: bool = True,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find CWE weaknesses semantically similar to a description.

    Args:
        session: Database session
        description: Natural language description to match
        min_similarity: Minimum cosine similarity threshold
        abstraction: Filter by abstraction levels
        active_only: Exclude deprecated weaknesses
        limit: Maximum results

    Returns:
        List of similar weaknesses with similarity scores
    """
    # Generate embedding for query
    query_embedding = await generate_embedding(description)

    # Build query with vector similarity
    stmt = (
        select(CWEWeakness)
        .where(CWEWeakness.embedding.is_not(None))
        .where(
            1 - CWEWeakness.embedding.cosine_distance(query_embedding) >= min_similarity
        )
        .order_by(CWEWeakness.embedding.cosine_distance(query_embedding))
        .limit(limit)
    )

    # Filters
    if abstraction:
        stmt = stmt.where(CWEWeakness.abstraction.in_(abstraction))

    if active_only:
        stmt = stmt.where(CWEWeakness.deprecated.is_(False))

    result = await session.execute(stmt)
    weaknesses = result.scalars().all()

    return [
        {
            **_weakness_to_dict(weakness),
            "similarity_score": round(
                float(1 - weakness.embedding.cosine_distance(query_embedding)), 3
            ),
        }
        for weakness in weaknesses
    ]


async def get_weakness_details(
    session: AsyncSession, weakness_id: str
) -> dict[str, Any] | None:
    """Get full details for a CWE weakness.

    Args:
        session: Database session
        weakness_id: CWE ID (e.g., "CWE-79")

    Returns:
        Full weakness details including actionable intelligence
    """
    # Normalize ID
    if not weakness_id.startswith("CWE-"):
        weakness_id = f"CWE-{weakness_id}"

    result = await session.execute(
        select(CWEWeakness).where(CWEWeakness.cwe_id == weakness_id)
    )
    weakness = result.scalar_one_or_none()

    if not weakness:
        return None

    # Get external mappings
    mappings_result = await session.execute(
        select(CWEExternalMapping).where(
            CWEExternalMapping.weakness_id == weakness_id
        )
    )
    mappings = mappings_result.scalars().all()

    return {
        "cwe_id": weakness.cwe_id,
        "weakness_id": weakness.weakness_id,
        "name": weakness.name,
        "description": weakness.description,
        "extended_description": weakness.extended_description,
        "abstraction": weakness.abstraction,
        "status": weakness.status,
        "likelihood_of_exploit": weakness.likelihood_of_exploit,
        "common_consequences": weakness.common_consequences,
        "potential_mitigations": weakness.potential_mitigations,
        "detection_methods": weakness.detection_methods,
        "parent_of": weakness.parent_of,
        "child_of": weakness.child_of,
        "peer_of": weakness.peer_of,
        "related_attack_patterns": weakness.related_attack_patterns,
        "external_mappings": [
            {
                "source": m.external_source,
                "id": m.external_id,
                "type": m.mapping_type,
            }
            for m in mappings
        ],
        "badge_url": weakness.badge_url,
        "cwe_version": weakness.cwe_version,
        "deprecated": weakness.deprecated,
    }


async def search_by_external_mapping(
    session: AsyncSession,
    source: str,
    external_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search weaknesses by external standard mapping.

    Args:
        session: Database session
        source: External source (e.g., "OWASP Top Ten 2021")
        external_id: Specific entry ID (e.g., "A03:2021")
        limit: Maximum results

    Returns:
        List of weaknesses matching the external mapping
    """
    stmt = select(CWEExternalMapping).where(
        CWEExternalMapping.external_source.ilike(f"%{source}%")
    )

    if external_id:
        stmt = stmt.where(CWEExternalMapping.external_id == external_id)

    stmt = stmt.limit(limit)

    result = await session.execute(stmt)
    mappings = result.scalars().all()

    # Get full weakness details for each mapping
    results = []
    seen_ids = set()

    for mapping in mappings:
        if mapping.weakness_id not in seen_ids:
            weakness_result = await session.execute(
                select(CWEWeakness).where(CWEWeakness.cwe_id == mapping.weakness_id)
            )
            weakness = weakness_result.scalar_one_or_none()
            if weakness:
                results.append({
                    **_weakness_to_dict(weakness),
                    "mapping_source": mapping.external_source,
                    "mapping_id": mapping.external_id,
                })
                seen_ids.add(mapping.weakness_id)

    return results


async def get_weakness_hierarchy(
    session: AsyncSession,
    weakness_id: str,
    direction: str = "both",
    depth: int = 3,
) -> dict[str, Any]:
    """Get hierarchical relationships for a weakness.

    Args:
        session: Database session
        weakness_id: CWE ID (e.g., "CWE-89")
        direction: "parents", "children", or "both"
        depth: How many levels to traverse

    Returns:
        Hierarchy tree structure
    """
    # Normalize ID
    if not weakness_id.startswith("CWE-"):
        weakness_id = f"CWE-{weakness_id}"

    result = await session.execute(
        select(CWEWeakness).where(CWEWeakness.cwe_id == weakness_id)
    )
    weakness = result.scalar_one_or_none()

    if not weakness:
        return {"error": f"Weakness {weakness_id} not found"}

    hierarchy = {
        "weakness": _weakness_to_dict(weakness),
        "parents": [],
        "children": [],
    }

    # Get parents
    if direction in ("parents", "both") and depth > 0:
        hierarchy["parents"] = await _get_related_weaknesses(
            session, weakness.child_of or [], depth - 1, "parents"
        )

    # Get children
    if direction in ("children", "both") and depth > 0:
        hierarchy["children"] = await _get_related_weaknesses(
            session, weakness.parent_of or [], depth - 1, "children"
        )

    return hierarchy


async def _get_related_weaknesses(
    session: AsyncSession,
    cwe_ids: list[str],
    depth: int,
    direction: str,
) -> list[dict[str, Any]]:
    """Recursively get related weaknesses."""
    results = []

    for cwe_id in cwe_ids:
        result = await session.execute(
            select(CWEWeakness).where(CWEWeakness.cwe_id == cwe_id)
        )
        weakness = result.scalar_one_or_none()
        if weakness:
            item = _weakness_to_dict(weakness)

            if depth > 0:
                if direction == "parents" and weakness.child_of:
                    item["parents"] = await _get_related_weaknesses(
                        session, weakness.child_of, depth - 1, direction
                    )
                elif direction == "children" and weakness.parent_of:
                    item["children"] = await _get_related_weaknesses(
                        session, weakness.parent_of, depth - 1, direction
                    )

            results.append(item)

    return results


async def find_weaknesses_for_capec(
    session: AsyncSession,
    pattern_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Find CWE weaknesses related to a CAPEC attack pattern.

    Args:
        session: Database session
        pattern_id: CAPEC pattern ID (e.g., "CAPEC-66")
        limit: Maximum results

    Returns:
        List of weaknesses exploited by the attack pattern
    """
    # Normalize ID
    if not pattern_id.startswith("CAPEC-"):
        pattern_id = f"CAPEC-{pattern_id}"

    # Find weaknesses that reference this CAPEC pattern
    stmt = (
        select(CWEWeakness)
        .where(CWEWeakness.related_attack_patterns.contains([pattern_id]))
        .limit(limit)
    )

    result = await session.execute(stmt)
    weaknesses = result.scalars().all()

    # If no direct links, try to get from CAPEC's related_weaknesses
    if not weaknesses:
        try:
            from cve_mcp.models.capec import CAPECPattern

            capec_result = await session.execute(
                select(CAPECPattern.related_weaknesses).where(
                    CAPECPattern.pattern_id == pattern_id
                )
            )
            row = capec_result.first()
            if row and row[0]:
                cwe_ids = row[0]
                stmt = select(CWEWeakness).where(CWEWeakness.cwe_id.in_(cwe_ids)).limit(limit)
                result = await session.execute(stmt)
                weaknesses = result.scalars().all()
        except ImportError:
            pass

    return [_weakness_to_dict(w) for w in weaknesses]


def _weakness_to_dict(weakness: CWEWeakness) -> dict[str, Any]:
    """Convert CWEWeakness model to dictionary."""
    return {
        "cwe_id": weakness.cwe_id,
        "weakness_id": weakness.weakness_id,
        "name": weakness.name,
        "description": weakness.description[:500] + "..." if len(weakness.description) > 500 else weakness.description,
        "abstraction": weakness.abstraction,
        "status": weakness.status,
        "likelihood_of_exploit": weakness.likelihood_of_exploit,
        "badge_url": weakness.badge_url,
    }
```

**Step 2: Add request schemas**

Add to `src/cve_mcp/api/schemas.py`:

```python
# CWE Schemas

class SearchCWEWeaknessesRequest(BaseModel):
    """Request schema for search_cwe_weaknesses tool."""

    query: str | None = Field(None, description="Full-text search in name/description")
    abstraction: list[str] | None = Field(
        None, description="Filter by abstraction levels (Pillar, Class, Base, Variant, Compound)"
    )
    include_children: bool = Field(
        False, description="Include child weaknesses in results (hierarchical search)"
    )
    active_only: bool = Field(True, description="Exclude deprecated weaknesses")
    limit: int = Field(50, ge=1, le=500, description="Max results")


class FindSimilarCWEWeaknessesRequest(BaseModel):
    """Request schema for find_similar_cwe_weaknesses tool (semantic search)."""

    description: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="Natural language description of weakness or vulnerability",
    )
    min_similarity: float = Field(0.7, ge=0.0, le=1.0, description="Minimum similarity threshold")
    abstraction: list[str] | None = Field(None, description="Filter by abstraction levels")
    active_only: bool = Field(True, description="Exclude deprecated weaknesses")
    limit: int = Field(10, ge=1, le=100, description="Max results")


class GetCWEWeaknessDetailsRequest(BaseModel):
    """Request schema for get_cwe_weakness_details tool."""

    weakness_id: str = Field(
        ..., description="CWE ID (e.g., CWE-79 or 79)", pattern=r"^(CWE-)?\d+$"
    )


class SearchByExternalMappingRequest(BaseModel):
    """Request schema for search_by_external_mapping tool."""

    source: str = Field(
        ..., description="External source name (e.g., 'OWASP Top Ten 2021', 'SANS Top 25')"
    )
    external_id: str | None = Field(
        None, description="Specific entry ID (e.g., 'A03:2021')"
    )
    limit: int = Field(50, ge=1, le=500, description="Max results")


class GetCWEHierarchyRequest(BaseModel):
    """Request schema for get_cwe_hierarchy tool."""

    weakness_id: str = Field(
        ..., description="CWE ID (e.g., CWE-89 or 89)", pattern=r"^(CWE-)?\d+$"
    )
    direction: str = Field(
        "both", description="Direction to traverse: 'parents', 'children', or 'both'"
    )
    depth: int = Field(3, ge=1, le=5, description="How many levels to traverse")


class FindWeaknessesForCAPECRequest(BaseModel):
    """Request schema for find_weaknesses_for_capec tool."""

    pattern_id: str = Field(
        ..., description="CAPEC pattern ID (e.g., CAPEC-66)", pattern=r"^(CAPEC-)?\d+$"
    )
    limit: int = Field(50, ge=1, le=500, description="Max results")
```

**Step 3: Add MCP tool definitions and handlers**

Add to `src/cve_mcp/api/tools.py` (tool definitions section):

```python
# CWE Intelligence Tools

MCPToolDefinition(
    name="search_cwe_weaknesses",
    description="Search CWE software weaknesses by keyword with hierarchical support. Returns weaknesses matching query with optional child weakness expansion.",
    inputSchema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search text (name/description)"},
            "abstraction": {
                "type": "array",
                "items": {"type": "string", "enum": ["Pillar", "Class", "Base", "Variant", "Compound"]},
                "description": "Filter by abstraction levels",
            },
            "include_children": {"type": "boolean", "description": "Include child weaknesses", "default": False},
            "active_only": {"type": "boolean", "description": "Exclude deprecated", "default": True},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
        },
    },
),
MCPToolDefinition(
    name="find_similar_cwe_weaknesses",
    description="Find CWE weaknesses semantically similar to a description using AI embeddings. Use for: 'Find weaknesses like buffer overflow', 'What CWE matches this vulnerability?'",
    inputSchema={
        "type": "object",
        "properties": {
            "description": {"type": "string", "minLength": 10, "maxLength": 5000, "description": "Natural language description"},
            "min_similarity": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.7},
            "abstraction": {
                "type": "array",
                "items": {"type": "string", "enum": ["Pillar", "Class", "Base", "Variant", "Compound"]},
            },
            "active_only": {"type": "boolean", "default": True},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
        },
        "required": ["description"],
    },
),
MCPToolDefinition(
    name="get_cwe_weakness_details",
    description="Get full CWE weakness details including mitigations, detection methods, consequences, and external mappings (OWASP, SANS).",
    inputSchema={
        "type": "object",
        "properties": {
            "weakness_id": {"type": "string", "pattern": "^(CWE-)?\\d+$", "description": "CWE ID (e.g., CWE-79)"},
        },
        "required": ["weakness_id"],
    },
),
MCPToolDefinition(
    name="search_by_external_mapping",
    description="Find CWE weaknesses by external standard mapping (OWASP Top 10, SANS Top 25, etc.).",
    inputSchema={
        "type": "object",
        "properties": {
            "source": {"type": "string", "description": "External source (e.g., 'OWASP Top Ten 2021')"},
            "external_id": {"type": "string", "description": "Entry ID (e.g., 'A03:2021')"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
        },
        "required": ["source"],
    },
),
MCPToolDefinition(
    name="get_cwe_hierarchy",
    description="Navigate CWE weakness hierarchy (parents/children). Use to understand weakness relationships and find related weaknesses.",
    inputSchema={
        "type": "object",
        "properties": {
            "weakness_id": {"type": "string", "pattern": "^(CWE-)?\\d+$"},
            "direction": {"type": "string", "enum": ["parents", "children", "both"], "default": "both"},
            "depth": {"type": "integer", "minimum": 1, "maximum": 5, "default": 3},
        },
        "required": ["weakness_id"],
    },
),
MCPToolDefinition(
    name="find_weaknesses_for_capec",
    description="Find CWE weaknesses exploited by a CAPEC attack pattern. Cross-framework correlation for threat analysis.",
    inputSchema={
        "type": "object",
        "properties": {
            "pattern_id": {"type": "string", "pattern": "^(CAPEC-)?\\d+$", "description": "CAPEC pattern ID"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
        },
        "required": ["pattern_id"],
    },
),
```

Add handler functions (in handlers section):

```python
async def handle_search_cwe_weaknesses(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Handle search_cwe_weaknesses tool."""
    from cve_mcp.api.schemas import SearchCWEWeaknessesRequest
    from cve_mcp.services.cwe_queries import search_weaknesses

    request = SearchCWEWeaknessesRequest(**arguments)
    async with AsyncSessionLocal() as session:
        return await search_weaknesses(
            session,
            query=request.query,
            abstraction=request.abstraction,
            include_children=request.include_children,
            active_only=request.active_only,
            limit=request.limit,
        )


async def handle_find_similar_cwe_weaknesses(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Handle find_similar_cwe_weaknesses tool."""
    from cve_mcp.api.schemas import FindSimilarCWEWeaknessesRequest
    from cve_mcp.services.cwe_queries import find_similar_weaknesses

    request = FindSimilarCWEWeaknessesRequest(**arguments)
    async with AsyncSessionLocal() as session:
        return await find_similar_weaknesses(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            abstraction=request.abstraction,
            active_only=request.active_only,
            limit=request.limit,
        )


async def handle_get_cwe_weakness_details(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cwe_weakness_details tool."""
    from cve_mcp.api.schemas import GetCWEWeaknessDetailsRequest
    from cve_mcp.services.cwe_queries import get_weakness_details

    request = GetCWEWeaknessDetailsRequest(**arguments)
    async with AsyncSessionLocal() as session:
        result = await get_weakness_details(session, request.weakness_id)
        if not result:
            return {"error": f"Weakness {request.weakness_id} not found"}
        return result


async def handle_search_by_external_mapping(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Handle search_by_external_mapping tool."""
    from cve_mcp.api.schemas import SearchByExternalMappingRequest
    from cve_mcp.services.cwe_queries import search_by_external_mapping

    request = SearchByExternalMappingRequest(**arguments)
    async with AsyncSessionLocal() as session:
        return await search_by_external_mapping(
            session,
            source=request.source,
            external_id=request.external_id,
            limit=request.limit,
        )


async def handle_get_cwe_hierarchy(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cwe_hierarchy tool."""
    from cve_mcp.api.schemas import GetCWEHierarchyRequest
    from cve_mcp.services.cwe_queries import get_weakness_hierarchy

    request = GetCWEHierarchyRequest(**arguments)
    async with AsyncSessionLocal() as session:
        return await get_weakness_hierarchy(
            session,
            weakness_id=request.weakness_id,
            direction=request.direction,
            depth=request.depth,
        )


async def handle_find_weaknesses_for_capec(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Handle find_weaknesses_for_capec tool."""
    from cve_mcp.api.schemas import FindWeaknessesForCAPECRequest
    from cve_mcp.services.cwe_queries import find_weaknesses_for_capec

    request = FindWeaknessesForCAPECRequest(**arguments)
    async with AsyncSessionLocal() as session:
        return await find_weaknesses_for_capec(
            session,
            pattern_id=request.pattern_id,
            limit=request.limit,
        )
```

Add to TOOL_HANDLERS mapping:

```python
"search_cwe_weaknesses": handle_search_cwe_weaknesses,
"find_similar_cwe_weaknesses": handle_find_similar_cwe_weaknesses,
"get_cwe_weakness_details": handle_get_cwe_weakness_details,
"search_by_external_mapping": handle_search_by_external_mapping,
"get_cwe_hierarchy": handle_get_cwe_hierarchy,
"find_weaknesses_for_capec": handle_find_weaknesses_for_capec,
```

**Step 4: Update integration test**

Update `tests/test_integration.py` tool count from 25 to 31.

**Step 5: Run tests**

Run: `pytest tests/test_integration.py -v`
Expected: All tests pass

**Step 6: Commit**

```bash
git add src/cve_mcp/services/cwe_queries.py src/cve_mcp/api/schemas.py src/cve_mcp/api/tools.py tests/test_integration.py
git commit -m "feat(cwe): add MCP tools with semantic search"
```

---

## Task 4: Documentation

**Goal:** Create module documentation and update README

**Files:**
- Create: `docs/modules/cwe.md`
- Modify: `README.md`

**Step 1: Create module documentation**

Create comprehensive `docs/modules/cwe.md` (~1,000 lines) documenting:
- All 6 MCP tools with request/response examples
- Hierarchical search examples
- External mapping queries (OWASP, SANS)
- Cross-framework correlation examples
- Troubleshooting guide
- Database schema reference

**Step 2: Update README**

- Change CWE status from "Planned" to "✅ Production"
- Add "900+ CWE weaknesses 🆕" to Key Features
- Add CWE section with example queries
- Add 6 CWE tools to Available Tools table
- Update total tool count to 31

**Step 3: Commit**

```bash
git add docs/modules/cwe.md README.md
git commit -m "docs(cwe): add module documentation"
```

---

## Summary

| Task | Component | Files | Tests |
|------|-----------|-------|-------|
| Task 0 | Database Schema | 3 files (model, migration, __init__) | Schema validation |
| Task 1 | XML Parser | 2 files (parser, tests) | 15 tests |
| Task 2 | Data Sync | 3 files (sync, CLI, __init__) | Sync validation |
| Task 3 | MCP Tools | 3 files (queries, schemas, tools) | Integration tests |
| Task 4 | Documentation | 2 files (module docs, README) | - |

**Total New Files:** 8
**Total Modified Files:** 5
**Total Tests:** ~45
**Total MCP Tools After:** 31
