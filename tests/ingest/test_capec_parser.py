"""Tests for CAPEC STIX parser."""

from datetime import datetime


class TestParseAttackPattern:
    """Tests for parse_attack_pattern function."""

    def test_parse_attack_pattern_basic(self):
        """Test parsing basic CAPEC attack pattern."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--7b423f65-c808-4c66-a534-95f06fb9b06d",
            "type": "attack-pattern",
            "name": "SQL Injection",
            "description": "An attacker manipulates SQL queries",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-66"}],
            "x_capec_abstraction": "Detailed",
            "x_capec_status": "Stable",
            "x_capec_likelihood_of_attack": "High",
            "x_capec_typical_severity": "Very High",
            "x_capec_prerequisites": ["SQL database is used"],
            "x_capec_version": "3.9",
        }

        result = parse_attack_pattern(stix_obj)

        assert result is not None
        assert result["pattern_id"] == "CAPEC-66"
        assert result["capec_id"] == 66
        assert result["stix_id"] == "attack-pattern--7b423f65-c808-4c66-a534-95f06fb9b06d"
        assert result["name"] == "SQL Injection"
        assert result["description"] == "An attacker manipulates SQL queries"
        assert result["abstraction"] == "Detailed"
        assert result["status"] == "Stable"
        assert result["likelihood_of_attack"] == "High"
        assert result["typical_severity"] == "Very High"
        assert result["prerequisites"] == ["SQL database is used"]
        assert result["version"] == "3.9"
        assert result["deprecated"] is False
        assert result["revoked"] is False
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)

    def test_parse_attack_pattern_without_prefix(self):
        """Test parsing pattern with numeric ID (no CAPEC- prefix)."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--12345678-1234-1234-1234-123456789012",
            "type": "attack-pattern",
            "name": "Buffer Overflow",
            "description": "Overflow a buffer to execute arbitrary code",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "100"}],
            "x_capec_abstraction": "Standard",
        }

        result = parse_attack_pattern(stix_obj)

        assert result is not None
        assert result["pattern_id"] == "CAPEC-100"
        assert result["capec_id"] == 100

    def test_parse_attack_pattern_with_relationships(self):
        """Test parsing pattern with parent/child relationships."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--test-uuid",
            "type": "attack-pattern",
            "name": "Test Pattern with Relations",
            "description": "Test pattern with parent/child relationships",
            "created": "2022-01-01T00:00:00Z",  # No milliseconds
            "modified": "2022-01-01T00:00:00Z",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-200"}],
            "x_capec_parent_of_refs": ["attack-pattern--child1", "attack-pattern--child2"],
            "x_capec_child_of_refs": ["attack-pattern--parent1"],
            "x_capec_can_precede_refs": ["attack-pattern--next1"],
            "x_capec_can_follow_refs": ["attack-pattern--prev1"],
            "x_capec_peer_of_refs": ["attack-pattern--peer1"],
        }

        result = parse_attack_pattern(stix_obj)

        assert result is not None
        assert result["parent_of"] == ["attack-pattern--child1", "attack-pattern--child2"]
        assert result["child_of"] == ["attack-pattern--parent1"]
        assert result["can_precede"] == ["attack-pattern--next1"]
        assert result["can_follow"] == ["attack-pattern--prev1"]
        assert result["peer_of"] == ["attack-pattern--peer1"]

    def test_parse_attack_pattern_deprecated(self):
        """Test parsing deprecated pattern."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--deprecated-uuid",
            "type": "attack-pattern",
            "name": "Deprecated Pattern",
            "description": "This pattern is deprecated",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-999"}],
            "x_capec_status": "Deprecated",
            "revoked": False,
        }

        result = parse_attack_pattern(stix_obj)

        assert result is not None
        assert result["deprecated"] is True
        assert result["status"] == "Deprecated"


class TestParseCategory:
    """Tests for parse_category function."""

    def test_parse_category(self):
        """Test parsing CAPEC category."""
        from cve_mcp.ingest.capec_parser import parse_category

        stix_obj = {
            "id": "x-capec-category--12345678-1234-1234-1234-123456789012",
            "type": "x-capec-category",
            "name": "Injection Attacks",
            "description": "Category for injection-based attacks",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-1000"}],
        }

        result = parse_category(stix_obj)

        assert result is not None
        assert result["category_id"] == "CAPEC-1000"
        assert result["stix_id"] == "x-capec-category--12345678-1234-1234-1234-123456789012"
        assert result["name"] == "Injection Attacks"
        assert result["summary"] == "Category for injection-based attacks"
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)

    def test_parse_category_without_prefix(self):
        """Test parsing category with numeric ID (no CAPEC- prefix)."""
        from cve_mcp.ingest.capec_parser import parse_category

        stix_obj = {
            "id": "x-capec-category--test-uuid",
            "type": "x-capec-category",
            "name": "Test Category",
            "description": "Test category description",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "1001"}],
        }

        result = parse_category(stix_obj)

        assert result is not None
        assert result["category_id"] == "CAPEC-1001"


class TestParseMitigation:
    """Tests for parse_mitigation function."""

    def test_parse_mitigation(self):
        """Test parsing CAPEC mitigation."""
        from cve_mcp.ingest.capec_parser import parse_mitigation

        stix_obj = {
            "id": "course-of-action--abc12345-1234-1234-1234-123456789012",
            "type": "course-of-action",
            "name": "Input Validation",
            "description": "Validate all user inputs before processing",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "x_capec_version": "3.9",
        }

        result = parse_mitigation(stix_obj)

        assert result is not None
        assert result["mitigation_id"] == "COA-abc12345-1234-1234-1234-123456789012"
        assert result["stix_id"] == "course-of-action--abc12345-1234-1234-1234-123456789012"
        assert result["name"] == "Input Validation"
        assert result["description"] == "Validate all user inputs before processing"
        assert result["version"] == "3.9"
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)

    def test_parse_mitigation_without_version(self):
        """Test parsing mitigation without version field."""
        from cve_mcp.ingest.capec_parser import parse_mitigation

        stix_obj = {
            "id": "course-of-action--def67890-1234-1234-1234-123456789012",
            "type": "course-of-action",
            "name": "Simple Mitigation",
            "description": "A simple mitigation",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
        }

        result = parse_mitigation(stix_obj)

        assert result is not None
        assert result["version"] is None


class TestParserEdgeCases:
    """Tests for parser edge cases."""

    def test_parse_attack_pattern_missing_external_id(self):
        """Test parsing pattern without external_id returns None."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--12345",
            "type": "attack-pattern",
            "name": "Test Pattern",
            "description": "Test",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [],
        }

        result = parse_attack_pattern(stix_obj)

        assert result is None

    def test_parse_attack_pattern_wrong_source(self):
        """Test parsing pattern with wrong source name returns None."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--12345",
            "type": "attack-pattern",
            "name": "Test Pattern",
            "description": "Test",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
        }

        result = parse_attack_pattern(stix_obj)

        assert result is None

    def test_parse_category_missing_external_id(self):
        """Test parsing category without external_id returns None."""
        from cve_mcp.ingest.capec_parser import parse_category

        stix_obj = {
            "id": "x-capec-category--12345",
            "type": "x-capec-category",
            "name": "Test Category",
            "description": "Test",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [],
        }

        result = parse_category(stix_obj)

        assert result is None

    def test_parse_mitigation_missing_stix_id(self):
        """Test parsing mitigation without stix_id returns None."""
        from cve_mcp.ingest.capec_parser import parse_mitigation

        stix_obj = {
            "type": "course-of-action",
            "name": "Test Mitigation",
            "description": "Test",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
        }

        result = parse_mitigation(stix_obj)

        assert result is None

    def test_parse_attack_pattern_with_invalid_capec_id(self):
        """Test parsing pattern with non-numeric CAPEC ID returns None."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--12345",
            "type": "attack-pattern",
            "name": "Test Pattern",
            "description": "Test",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-invalid"}],
        }

        result = parse_attack_pattern(stix_obj)

        assert result is None

    def test_parse_attack_pattern_with_complex_fields(self):
        """Test parsing pattern with all complex fields."""
        from cve_mcp.ingest.capec_parser import parse_attack_pattern

        stix_obj = {
            "id": "attack-pattern--complex-uuid",
            "type": "attack-pattern",
            "name": "Complex Pattern",
            "description": "Pattern with all fields",
            "created": "2022-01-01T00:00:00.000Z",
            "modified": "2022-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "capec", "external_id": "CAPEC-300"}],
            "x_capec_abstraction": "Meta",
            "x_capec_status": "Stable",
            "x_capec_extended_description": "This is an extended description",
            "x_capec_prerequisites": ["Prerequisite 1", "Prerequisite 2"],
            "x_capec_skills_required": {"Low": "Basic knowledge", "High": "Expert knowledge"},
            "x_capec_consequences": {"Confidentiality": ["Read Data"]},
            "x_capec_example_instances": ["Example 1", "Example 2"],
            "x_capec_execution_flow": {"step1": "Do something", "step2": "Do more"},
        }

        result = parse_attack_pattern(stix_obj)

        assert result is not None
        assert result["abstraction"] == "Meta"
        assert result["extended_description"] == "This is an extended description"
        assert result["prerequisites"] == ["Prerequisite 1", "Prerequisite 2"]
        assert result["skills_required"] == {"Low": "Basic knowledge", "High": "Expert knowledge"}
        assert result["consequences"] == {"Confidentiality": ["Read Data"]}
        assert result["example_instances"] == ["Example 1", "Example 2"]
        assert result["execution_flow"] == {"step1": "Do something", "step2": "Do more"}
