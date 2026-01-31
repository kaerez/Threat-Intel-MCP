"""Tests for MITRE ATLAS STIX parser."""

from datetime import datetime


class TestParseTechnique:
    """Test parse_technique function for ATLAS."""

    def test_parse_technique_basic(self):
        """Test parsing a basic ATLAS technique."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--00cfcfef-5f13-4deb-a4c5-e0a0af1e0437",
            "created": "2022-03-01T14:00:00.000Z",
            "modified": "2023-06-15T10:30:00.000Z",
            "name": "ML Supply Chain Compromise",
            "description": "Adversaries may compromise ML supply chain components.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-atlas", "phase_name": "ml-attack-staging"}
            ],
            "external_references": [
                {
                    "source_name": "ATLAS",
                    "url": "https://atlas.mitre.org/techniques/AML.T0010",
                    "external_id": "AML.T0010",
                }
            ],
            "x_mitre_platforms": ["computer-vision", "nlp"],
            "x_mitre_version": "1.0",
            "x_mitre_deprecated": False,
        }

        result = parse_technique(stix_obj)

        assert result is not None
        assert result["technique_id"] == "AML.T0010"
        assert result["stix_id"] == "attack-pattern--00cfcfef-5f13-4deb-a4c5-e0a0af1e0437"
        assert result["name"] == "ML Supply Chain Compromise"
        assert result["description"].startswith("Adversaries may compromise")
        assert result["tactics"] == ["ml-attack-staging"]
        assert result["ai_system_type"] == ["computer-vision", "nlp"]
        assert result["version"] == "1.0"
        assert result["deprecated"] is False
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)


class TestParseTactic:
    """Test parse_tactic function for ATLAS."""

    def test_parse_tactic(self):
        """Test parsing an ATLAS tactic."""
        from cve_mcp.ingest.atlas_parser import parse_tactic

        stix_obj = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--5e3552d7-eb91-4a9d-a8c4-8a3a7e0d1b3c",
            "created": "2022-02-01T12:00:00.000Z",
            "modified": "2023-01-15T08:00:00.000Z",
            "name": "ML Attack Staging",
            "description": "The adversary is staging an ML-specific attack.",
            "x_mitre_shortname": "ml-attack-staging",
            "external_references": [
                {
                    "source_name": "ATLAS",
                    "url": "https://atlas.mitre.org/tactics/AML.TA0002",
                    "external_id": "AML.TA0002",
                }
            ],
        }

        result = parse_tactic(stix_obj)

        assert result is not None
        assert result["tactic_id"] == "AML.TA0002"
        assert result["stix_id"] == "x-mitre-tactic--5e3552d7-eb91-4a9d-a8c4-8a3a7e0d1b3c"
        assert result["name"] == "ML Attack Staging"
        assert result["shortname"] == "ml-attack-staging"
        assert result["description"].startswith("The adversary is staging")
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)


class TestParseCaseStudy:
    """Test parse_case_study function for ATLAS."""

    def test_parse_case_study(self):
        """Test parsing an ATLAS case study."""
        from cve_mcp.ingest.atlas_parser import parse_case_study

        stix_obj = {
            "type": "x-mitre-case-study",
            "id": "x-mitre-case-study--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "created": "2022-06-01T09:00:00.000Z",
            "modified": "2023-03-20T14:30:00.000Z",
            "name": "Evasion Attack on Traffic Sign Classifier",
            "description": "Researchers demonstrated adversarial patches on stop signs.",
            "external_references": [
                {
                    "source_name": "ATLAS",
                    "url": "https://atlas.mitre.org/studies/AML.CS0001",
                    "external_id": "AML.CS0001",
                },
                {"source_name": "Research Paper", "url": "https://example.com/research-paper"},
            ],
            "x_mitre_techniques": ["AML.T0043", "AML.T0022"],
            "x_mitre_target_system": "Autonomous Vehicle Vision System",
            "x_mitre_impact": "Misclassification of traffic signs",
            "x_mitre_version": "1.0",
        }

        result = parse_case_study(stix_obj)

        assert result is not None
        assert result["case_study_id"] == "AML.CS0001"
        assert result["stix_id"] == "x-mitre-case-study--a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert result["name"] == "Evasion Attack on Traffic Sign Classifier"
        assert result["summary"].startswith("Researchers demonstrated")
        assert result["techniques_used"] == ["AML.T0043", "AML.T0022"]
        assert result["target_system"] == "Autonomous Vehicle Vision System"
        assert result["impact"] == "Misclassification of traffic signs"
        assert result["version"] == "1.0"
        assert "https://example.com/research-paper" in result["references"]
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)


class TestParserEdgeCases:
    """Test parser edge cases and error handling."""

    def test_parse_technique_missing_external_id(self):
        """Test handling technique without external_id."""
        from cve_mcp.ingest.atlas_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--test",
            "created": "2022-03-01T14:00:00.000Z",
            "modified": "2023-06-15T10:30:00.000Z",
            "name": "Test",
            "description": "Test description.",
            "external_references": [{"source_name": "other-source", "url": "https://example.com"}],
        }

        result = parse_technique(stix_obj)

        # Should return None for missing external_id
        assert result is None

    def test_parse_tactic_missing_external_id(self):
        """Test handling tactic without external_id."""
        from cve_mcp.ingest.atlas_parser import parse_tactic

        stix_obj = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--test",
            "created": "2022-02-01T12:00:00.000Z",
            "modified": "2023-01-15T08:00:00.000Z",
            "name": "Test Tactic",
            "description": "Test description.",
            "x_mitre_shortname": "test-tactic",
            "external_references": [],
        }

        result = parse_tactic(stix_obj)

        # Should return None for missing external_id
        assert result is None
