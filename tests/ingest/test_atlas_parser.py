"""Tests for MITRE ATLAS YAML parser."""

from datetime import date, datetime


class TestParseTechnique:
    """Test parse_technique function for ATLAS."""

    def test_parse_technique_basic(self):
        """Test parsing a basic ATLAS technique (new YAML format)."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        yaml_obj = {
            "id": "AML.T0010",
            "name": "ML Supply Chain Compromise",
            "description": "Adversaries may compromise ML supply chain components.",
            "object-type": "technique",
            "tactics": ["AML.TA0001"],
            "ATT&CK-reference": {
                "id": "T1195",
                "url": "https://attack.mitre.org/techniques/T1195",
            },
            "platforms": ["computer-vision", "nlp"],
            "created_date": date(2022, 3, 1),
            "modified_date": date(2023, 6, 15),
            "maturity": "demonstrated",
            "deprecated": False,
        }

        result = parse_technique(yaml_obj)

        assert result is not None
        assert result["technique_id"] == "AML.T0010"
        assert result["stix_id"] is None  # No STIX ID in new format
        assert result["name"] == "ML Supply Chain Compromise"
        assert result["description"].startswith("Adversaries may compromise")
        assert result["tactics"] == ["AML.TA0001"]
        assert result["ai_system_type"] == ["computer-vision", "nlp"]
        assert result["deprecated"] is False
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)
        assert result["stix_extensions"]["maturity"] == "demonstrated"
        assert result["stix_extensions"]["attack_reference"] == "T1195"

    def test_parse_technique_with_string_dates(self):
        """Test parsing technique with ISO string dates (fallback)."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        yaml_obj = {
            "id": "AML.T0011",
            "name": "Test Technique",
            "description": "Test description.",
            "tactics": ["AML.TA0002"],
            "created_date": "2022-03-01",
            "modified_date": "2023-06-15",
        }

        result = parse_technique(yaml_obj)

        assert result is not None
        assert result["technique_id"] == "AML.T0011"
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)

    def test_parse_subtechnique(self):
        """Test parsing a subtechnique."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        yaml_obj = {
            "id": "AML.T0010.001",
            "name": "Subtechnique of Supply Chain",
            "description": "A subtechnique.",
            "tactics": ["AML.TA0001"],
            "created_date": date(2022, 3, 1),
            "modified_date": date(2023, 6, 15),
        }

        result = parse_technique(yaml_obj)

        assert result is not None
        assert result["technique_id"] == "AML.T0010.001"
        assert result["stix_extensions"]["is_subtechnique"] is True
        assert result["stix_extensions"]["parent_id"] == "AML.T0010"


class TestParseTactic:
    """Test parse_tactic function for ATLAS."""

    def test_parse_tactic(self):
        """Test parsing an ATLAS tactic (new YAML format)."""
        from cve_mcp.ingest.atlas_parser import parse_tactic

        yaml_obj = {
            "id": "AML.TA0002",
            "name": "ML Attack Staging",
            "description": "The adversary is staging an ML-specific attack.",
            "object-type": "tactic",
            "created_date": date(2022, 2, 1),
            "modified_date": date(2023, 1, 15),
        }

        result = parse_tactic(yaml_obj)

        assert result is not None
        assert result["tactic_id"] == "AML.TA0002"
        assert result["stix_id"] is None  # No STIX ID in new format
        assert result["name"] == "ML Attack Staging"
        assert result["shortname"] == "ml-attack-staging"  # Auto-generated
        assert result["description"].startswith("The adversary is staging")
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)


class TestParseCaseStudy:
    """Test parse_case_study function for ATLAS."""

    def test_parse_case_study(self):
        """Test parsing an ATLAS case study (new YAML format)."""
        from cve_mcp.ingest.atlas_parser import parse_case_study

        yaml_obj = {
            "id": "AML.CS0001",
            "name": "Evasion Attack on Traffic Sign Classifier",
            "summary": "Researchers demonstrated adversarial patches on stop signs.",
            "object-type": "case-study",
            "incident-date": date(2019, 4, 1),
            "incident-date-granularity": "MONTH",
            "procedure": [
                {"technique": "AML.T0043", "description": "Step 1"},
                {"technique": "AML.T0022", "description": "Step 2"},
            ],
            "reporter": "Academic Research Team",
            "target": "Autonomous Vehicle Vision System",
            "actor": "Researchers",
            "case-study-type": "exercise",
            "references": [
                {"title": "Research Paper", "url": "https://example.com/research-paper"},
                {"title": "Blog Post", "url": "https://example.com/blog"},
            ],
            "created_date": date(2022, 6, 1),
            "modified_date": date(2023, 3, 20),
        }

        result = parse_case_study(yaml_obj)

        assert result is not None
        assert result["case_study_id"] == "AML.CS0001"
        assert result["stix_id"] is None  # No STIX ID in new format
        assert result["name"] == "Evasion Attack on Traffic Sign Classifier"
        assert result["summary"].startswith("Researchers demonstrated")
        assert result["techniques_used"] == ["AML.T0043", "AML.T0022"]
        assert result["target_system"] == "Autonomous Vehicle Vision System"
        assert result["impact"] == "Researchers"  # Maps actor to impact
        assert "https://example.com/research-paper" in result["references"]
        assert "https://example.com/blog" in result["references"]
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)
        assert isinstance(result["incident_date"], datetime)
        assert result["stix_extensions"]["reporter"] == "Academic Research Team"
        assert result["stix_extensions"]["case_study_type"] == "exercise"


class TestParserEdgeCases:
    """Test parser edge cases and error handling."""

    def test_parse_technique_missing_id(self):
        """Test handling technique without id."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        yaml_obj = {
            "name": "Test",
            "description": "Test description.",
            "tactics": ["AML.TA0001"],
            "created_date": date(2022, 3, 1),
            "modified_date": date(2023, 6, 15),
        }

        result = parse_technique(yaml_obj)

        # Should return None for missing id
        assert result is None

    def test_parse_tactic_missing_id(self):
        """Test handling tactic without id."""
        from cve_mcp.ingest.atlas_parser import parse_tactic

        yaml_obj = {
            "name": "Test Tactic",
            "description": "Test description.",
            "created_date": date(2022, 2, 1),
            "modified_date": date(2023, 1, 15),
        }

        result = parse_tactic(yaml_obj)

        # Should return None for missing id
        assert result is None

    def test_parse_case_study_missing_id(self):
        """Test handling case study without id."""
        from cve_mcp.ingest.atlas_parser import parse_case_study

        yaml_obj = {
            "name": "Test Case Study",
            "summary": "Test summary.",
            "created_date": date(2022, 6, 1),
            "modified_date": date(2023, 3, 20),
        }

        result = parse_case_study(yaml_obj)

        # Should return None for missing id
        assert result is None

    def test_parse_technique_minimal(self):
        """Test parsing technique with minimal fields."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        yaml_obj = {
            "id": "AML.T0099",
        }

        result = parse_technique(yaml_obj)

        assert result is not None
        assert result["technique_id"] == "AML.T0099"
        assert result["name"] == ""
        assert result["description"] == ""
        assert result["tactics"] is None
        assert result["created"] is None
        assert result["modified"] is None
