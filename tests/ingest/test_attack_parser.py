"""Tests for MITRE ATT&CK STIX parser."""

from datetime import datetime


class TestParseTechnique:
    """Test parse_technique function."""

    def test_parse_technique_basic(self):
        """Test parsing a basic ATT&CK technique."""
        from cve_mcp.ingest.attack_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--0c8ab3eb-df48-4b9c-ace7-beacaac81cc5",
            "created": "2020-03-11T14:26:15.113Z",
            "modified": "2021-10-17T16:31:52.968Z",
            "name": "Spearphishing Attachment",
            "description": "Adversaries may send spearphishing emails with a malicious attachment.",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1566/001",
                    "external_id": "T1566.001"
                }
            ],
            "x_mitre_platforms": ["Windows", "macOS", "Linux"],
            "x_mitre_data_sources": ["File: File Creation", "Network Traffic: Network Traffic Content"],
            "x_mitre_detection": "Network intrusion detection and email gateway filtering.",
            "x_mitre_version": "1.2",
            "x_mitre_is_subtechnique": True,
            "x_mitre_permissions_required": ["User"],
        }

        result = parse_technique(stix_obj)

        assert result["technique_id"] == "T1566.001"
        assert result["stix_id"] == "attack-pattern--0c8ab3eb-df48-4b9c-ace7-beacaac81cc5"
        assert result["name"] == "Spearphishing Attachment"
        assert result["description"].startswith("Adversaries may send")
        assert result["is_subtechnique"] is True
        assert result["parent_technique_id"] == "T1566"
        assert result["tactics"] == ["initial-access"]
        assert result["platforms"] == ["Windows", "macOS", "Linux"]
        assert result["detection"] == "Network intrusion detection and email gateway filtering."
        assert result["version"] == "1.2"
        assert result["permissions_required"] == ["User"]
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)

    def test_parse_technique_parent(self):
        """Test parsing a parent technique (not subtechnique)."""
        from cve_mcp.ingest.attack_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "created": "2020-03-11T14:26:15.113Z",
            "modified": "2021-10-17T16:31:52.968Z",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages to gain access.",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1566",
                    "external_id": "T1566"
                }
            ],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_version": "2.0",
            "x_mitre_is_subtechnique": False,
        }

        result = parse_technique(stix_obj)

        assert result["technique_id"] == "T1566"
        assert result["is_subtechnique"] is False
        assert result["parent_technique_id"] is None

    def test_parse_technique_deprecated(self):
        """Test parsing deprecated technique."""
        from cve_mcp.ingest.attack_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--deprecated",
            "created": "2020-03-11T14:26:15.113Z",
            "modified": "2021-10-17T16:31:52.968Z",
            "name": "Deprecated Technique",
            "description": "This technique is deprecated.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T9999"
                }
            ],
            "x_mitre_deprecated": True,
            "x_mitre_version": "1.0",
        }

        result = parse_technique(stix_obj)

        assert result["deprecated"] is True


class TestParseGroup:
    """Test parse_group function."""

    def test_parse_group_basic(self):
        """Test parsing a threat actor group."""
        from cve_mcp.ingest.attack_parser import parse_group

        stix_obj = {
            "type": "intrusion-set",
            "id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
            "created": "2017-05-31T21:31:43.540Z",
            "modified": "2021-10-12T20:04:52.596Z",
            "name": "APT1",
            "description": "APT1 is a Chinese threat group that has been active since 2006.",
            "aliases": ["APT1", "Comment Crew", "Comment Panda"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/groups/G0006",
                    "external_id": "G0006"
                }
            ],
            "x_mitre_version": "2.1",
        }

        result = parse_group(stix_obj)

        assert result["group_id"] == "G0006"
        assert result["stix_id"] == "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
        assert result["name"] == "APT1"
        assert result["description"].startswith("APT1 is a Chinese")
        assert result["aliases"] == ["APT1", "Comment Crew", "Comment Panda"]
        assert result["version"] == "2.1"
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)

    def test_parse_group_no_aliases(self):
        """Test parsing group without aliases."""
        from cve_mcp.ingest.attack_parser import parse_group

        stix_obj = {
            "type": "intrusion-set",
            "id": "intrusion-set--test",
            "created": "2017-05-31T21:31:43.540Z",
            "modified": "2021-10-12T20:04:52.596Z",
            "name": "Test Group",
            "description": "Test group description.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "G9999"
                }
            ],
        }

        result = parse_group(stix_obj)

        assert result["aliases"] is None or result["aliases"] == []


class TestParseTactic:
    """Test parse_tactic function."""

    def test_parse_tactic_basic(self):
        """Test parsing an ATT&CK tactic."""
        from cve_mcp.ingest.attack_parser import parse_tactic

        stix_obj = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
            "created": "2018-10-17T00:14:20.652Z",
            "modified": "2019-07-19T17:44:53.176Z",
            "name": "Initial Access",
            "description": "The adversary is trying to get into your network.",
            "x_mitre_shortname": "initial-access",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0001",
                    "external_id": "TA0001"
                }
            ],
        }

        result = parse_tactic(stix_obj)

        assert result["tactic_id"] == "TA0001"
        assert result["stix_id"] == "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca"
        assert result["name"] == "Initial Access"
        assert result["shortname"] == "initial-access"
        assert result["description"].startswith("The adversary is trying")
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)


class TestParseSoftware:
    """Test parse_software function."""

    def test_parse_software_malware(self):
        """Test parsing malware software."""
        from cve_mcp.ingest.attack_parser import parse_software

        stix_obj = {
            "type": "malware",
            "id": "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
            "created": "2017-05-31T21:33:27.049Z",
            "modified": "2020-03-30T02:38:21.144Z",
            "name": "CHOPSTICK",
            "description": "CHOPSTICK is malware that establishes persistence.",
            "labels": ["malware"],
            "x_mitre_aliases": ["CHOPSTICK", "Backdoor.APT.CookieCutter"],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_version": "1.2",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/software/S0023",
                    "external_id": "S0023"
                }
            ],
        }

        result = parse_software(stix_obj)

        assert result["software_id"] == "S0023"
        assert result["stix_id"] == "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
        assert result["name"] == "CHOPSTICK"
        assert result["software_type"] == "malware"
        assert result["description"].startswith("CHOPSTICK is malware")
        assert result["platforms"] == ["Windows"]
        assert result["version"] == "1.2"

    def test_parse_software_tool(self):
        """Test parsing tool software."""
        from cve_mcp.ingest.attack_parser import parse_software

        stix_obj = {
            "type": "tool",
            "id": "tool--03342581-f790-4f03-ba41-e82e67392e23",
            "created": "2017-05-31T21:33:27.049Z",
            "modified": "2020-03-30T02:38:21.144Z",
            "name": "Mimikatz",
            "description": "Mimikatz is a credential dumper.",
            "labels": ["tool"],
            "x_mitre_platforms": ["Windows"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "S0002"
                }
            ],
        }

        result = parse_software(stix_obj)

        assert result["software_type"] == "tool"
        assert result["software_id"] == "S0002"


class TestParseMitigation:
    """Test parse_mitigation function."""

    def test_parse_mitigation_basic(self):
        """Test parsing an ATT&CK mitigation."""
        from cve_mcp.ingest.attack_parser import parse_mitigation

        stix_obj = {
            "type": "course-of-action",
            "id": "course-of-action--90f39ee1-d5a3-4aaa-9f28-3b42815b0d46",
            "created": "2019-06-11T17:15:52.138Z",
            "modified": "2019-07-24T19:17:13.879Z",
            "name": "User Training",
            "description": "Train users to identify social engineering techniques.",
            "x_mitre_version": "1.0",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/M1017",
                    "external_id": "M1017"
                }
            ],
        }

        result = parse_mitigation(stix_obj)

        assert result["mitigation_id"] == "M1017"
        assert result["stix_id"] == "course-of-action--90f39ee1-d5a3-4aaa-9f28-3b42815b0d46"
        assert result["name"] == "User Training"
        assert result["description"].startswith("Train users")
        assert result["version"] == "1.0"
        assert isinstance(result["created"], datetime)
        assert isinstance(result["modified"], datetime)


class TestParserEdgeCases:
    """Test parser edge cases and error handling."""

    def test_parse_technique_missing_external_id(self):
        """Test handling technique without external_id."""
        from cve_mcp.ingest.attack_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--test",
            "created": "2020-03-11T14:26:15.113Z",
            "modified": "2021-10-17T16:31:52.968Z",
            "name": "Test",
            "description": "Test description.",
            "external_references": [
                {
                    "source_name": "other-source",
                    "url": "https://example.com"
                }
            ],
        }

        result = parse_technique(stix_obj)

        # Should handle missing external_id gracefully
        assert result is None or "technique_id" not in result or result["technique_id"] is None

    def test_parse_technique_multiple_tactics(self):
        """Test parsing technique with multiple tactics."""
        from cve_mcp.ingest.attack_parser import parse_technique

        stix_obj = {
            "type": "attack-pattern",
            "id": "attack-pattern--test",
            "created": "2020-03-11T14:26:15.113Z",
            "modified": "2021-10-17T16:31:52.968Z",
            "name": "Multi-Tactic Technique",
            "description": "Test description.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T9999"
                }
            ],
        }

        result = parse_technique(stix_obj)

        assert result["tactics"] == ["persistence", "privilege-escalation"]
