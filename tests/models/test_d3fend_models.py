"""Tests for D3FEND database models.

TDD: Tests written before implementation.
"""

from sqlalchemy import inspect


class TestD3FENDEnums:
    """Test D3FEND enum types."""

    def test_relationship_type_enum_values(self):
        """D3FENDRelationshipType has correct values."""
        from cve_mcp.models.d3fend import D3FENDRelationshipType

        expected_values = {"counters", "enables", "related-to", "produces", "uses"}
        actual_values = {e.value for e in D3FENDRelationshipType}
        assert actual_values == expected_values

    def test_artifact_relationship_type_enum_values(self):
        """D3FENDArtifactRelationshipType has correct values."""
        from cve_mcp.models.d3fend import D3FENDArtifactRelationshipType

        expected_values = {"produces", "uses", "analyzes"}
        actual_values = {e.value for e in D3FENDArtifactRelationshipType}
        assert actual_values == expected_values


class TestD3FENDTactic:
    """Test D3FENDTactic model."""

    def test_table_name(self):
        """D3FENDTactic has correct table name."""
        from cve_mcp.models.d3fend import D3FENDTactic

        assert D3FENDTactic.__tablename__ == "d3fend_tactics"

    def test_primary_key(self):
        """D3FENDTactic has tactic_id as primary key."""
        from cve_mcp.models.d3fend import D3FENDTactic

        mapper = inspect(D3FENDTactic)
        pk_columns = [col.name for col in mapper.primary_key]
        assert pk_columns == ["tactic_id"]

    def test_required_columns(self):
        """D3FENDTactic has required columns."""
        from cve_mcp.models.d3fend import D3FENDTactic

        mapper = inspect(D3FENDTactic)
        column_names = {col.name for col in mapper.columns}
        required = {"tactic_id", "name", "description", "display_order"}
        assert required.issubset(column_names)


class TestD3FENDTechnique:
    """Test D3FENDTechnique model."""

    def test_table_name(self):
        """D3FENDTechnique has correct table name."""
        from cve_mcp.models.d3fend import D3FENDTechnique

        assert D3FENDTechnique.__tablename__ == "d3fend_techniques"

    def test_primary_key(self):
        """D3FENDTechnique has technique_id as primary key."""
        from cve_mcp.models.d3fend import D3FENDTechnique

        mapper = inspect(D3FENDTechnique)
        pk_columns = [col.name for col in mapper.primary_key]
        assert pk_columns == ["technique_id"]

    def test_vector_embedding_dimension(self):
        """D3FENDTechnique embedding has 1536 dimensions."""
        from cve_mcp.models.d3fend import D3FENDTechnique

        mapper = inspect(D3FENDTechnique)
        embedding_col = mapper.columns["embedding"]
        # pgvector Vector type stores dimension in .dim attribute
        assert embedding_col.type.dim == 1536

    def test_tactic_foreign_key(self):
        """D3FENDTechnique has FK to d3fend_tactics."""
        from cve_mcp.models.d3fend import D3FENDTechnique

        mapper = inspect(D3FENDTechnique)
        tactic_id_col = mapper.columns["tactic_id"]
        fks = list(tactic_id_col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "d3fend_tactics.tactic_id"

    def test_self_referential_parent_fk(self):
        """D3FENDTechnique has self-referential parent_id FK."""
        from cve_mcp.models.d3fend import D3FENDTechnique

        mapper = inspect(D3FENDTechnique)
        parent_id_col = mapper.columns["parent_id"]
        fks = list(parent_id_col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "d3fend_techniques.technique_id"

    def test_required_columns(self):
        """D3FENDTechnique has required columns."""
        from cve_mcp.models.d3fend import D3FENDTechnique

        mapper = inspect(D3FENDTechnique)
        column_names = {col.name for col in mapper.columns}
        required = {
            "technique_id",
            "embedding",
            "name",
            "description",
            "tactic_id",
            "parent_id",
            "synonyms",
            "references",
            "kb_article_url",
            "d3fend_version",
            "deprecated",
        }
        assert required.issubset(column_names)


class TestD3FENDArtifact:
    """Test D3FENDArtifact model."""

    def test_table_name(self):
        """D3FENDArtifact has correct table name."""
        from cve_mcp.models.d3fend import D3FENDArtifact

        assert D3FENDArtifact.__tablename__ == "d3fend_artifacts"

    def test_primary_key(self):
        """D3FENDArtifact has artifact_id as primary key."""
        from cve_mcp.models.d3fend import D3FENDArtifact

        mapper = inspect(D3FENDArtifact)
        pk_columns = [col.name for col in mapper.primary_key]
        assert pk_columns == ["artifact_id"]

    def test_required_columns(self):
        """D3FENDArtifact has required columns."""
        from cve_mcp.models.d3fend import D3FENDArtifact

        mapper = inspect(D3FENDArtifact)
        column_names = {col.name for col in mapper.columns}
        required = {"artifact_id", "name", "description", "artifact_type"}
        assert required.issubset(column_names)


class TestD3FENDTechniqueAttackMapping:
    """Test D3FENDTechniqueAttackMapping model."""

    def test_table_name(self):
        """D3FENDTechniqueAttackMapping has correct table name."""
        from cve_mcp.models.d3fend import D3FENDTechniqueAttackMapping

        assert D3FENDTechniqueAttackMapping.__tablename__ == "d3fend_technique_attack_mappings"

    def test_primary_key_autoincrement(self):
        """D3FENDTechniqueAttackMapping has mapping_id as autoincrement PK."""
        from cve_mcp.models.d3fend import D3FENDTechniqueAttackMapping

        mapper = inspect(D3FENDTechniqueAttackMapping)
        pk_columns = [col.name for col in mapper.primary_key]
        assert pk_columns == ["mapping_id"]

    def test_d3fend_technique_foreign_key(self):
        """D3FENDTechniqueAttackMapping has FK to d3fend_techniques."""
        from cve_mcp.models.d3fend import D3FENDTechniqueAttackMapping

        mapper = inspect(D3FENDTechniqueAttackMapping)
        d3fend_tech_col = mapper.columns["d3fend_technique_id"]
        fks = list(d3fend_tech_col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "d3fend_techniques.technique_id"

    def test_attack_technique_foreign_key(self):
        """D3FENDTechniqueAttackMapping has FK to attack_techniques."""
        from cve_mcp.models.d3fend import D3FENDTechniqueAttackMapping

        mapper = inspect(D3FENDTechniqueAttackMapping)
        attack_tech_col = mapper.columns["attack_technique_id"]
        fks = list(attack_tech_col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "attack_techniques.technique_id"


class TestD3FENDTechniqueArtifact:
    """Test D3FENDTechniqueArtifact model."""

    def test_table_name(self):
        """D3FENDTechniqueArtifact has correct table name."""
        from cve_mcp.models.d3fend import D3FENDTechniqueArtifact

        assert D3FENDTechniqueArtifact.__tablename__ == "d3fend_technique_artifacts"

    def test_composite_primary_key(self):
        """D3FENDTechniqueArtifact has composite PK (technique_id, artifact_id, relationship_type)."""
        from cve_mcp.models.d3fend import D3FENDTechniqueArtifact

        mapper = inspect(D3FENDTechniqueArtifact)
        pk_columns = {col.name for col in mapper.primary_key}
        expected = {"technique_id", "artifact_id", "relationship_type"}
        assert pk_columns == expected

    def test_technique_foreign_key(self):
        """D3FENDTechniqueArtifact has FK to d3fend_techniques."""
        from cve_mcp.models.d3fend import D3FENDTechniqueArtifact

        mapper = inspect(D3FENDTechniqueArtifact)
        technique_col = mapper.columns["technique_id"]
        fks = list(technique_col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "d3fend_techniques.technique_id"

    def test_artifact_foreign_key(self):
        """D3FENDTechniqueArtifact has FK to d3fend_artifacts."""
        from cve_mcp.models.d3fend import D3FENDTechniqueArtifact

        mapper = inspect(D3FENDTechniqueArtifact)
        artifact_col = mapper.columns["artifact_id"]
        fks = list(artifact_col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "d3fend_artifacts.artifact_id"
