"""Tests for D3FEND MISP Galaxy JSON parser."""


class TestNormalizeD3FendId:
    """Tests for normalize_d3fend_id function."""

    def test_standard_id(self):
        """Test normalizing already standard D3FEND ID."""
        from cve_mcp.ingest.d3fend_parser import normalize_d3fend_id

        result = normalize_d3fend_id("D3-AH")

        assert result == "D3-AH"

    def test_lowercase_id(self):
        """Test normalizing lowercase D3FEND ID."""
        from cve_mcp.ingest.d3fend_parser import normalize_d3fend_id

        result = normalize_d3fend_id("d3-ah")

        assert result == "D3-AH"

    def test_with_prefix(self):
        """Test normalizing D3FEND ID with d3f: prefix."""
        from cve_mcp.ingest.d3fend_parser import normalize_d3fend_id

        result = normalize_d3fend_id("d3f:D3-AH")

        assert result == "D3-AH"

    def test_empty_string(self):
        """Test normalizing empty string returns empty string."""
        from cve_mcp.ingest.d3fend_parser import normalize_d3fend_id

        result = normalize_d3fend_id("")

        assert result == ""

    def test_none(self):
        """Test normalizing None returns None."""
        from cve_mcp.ingest.d3fend_parser import normalize_d3fend_id

        result = normalize_d3fend_id(None)

        assert result is None


class TestParseTacticFromKillChain:
    """Tests for parse_tactic_from_kill_chain function."""

    def test_single_tactic(self):
        """Test extracting tactic from single kill_chain entry."""
        from cve_mcp.ingest.d3fend_parser import parse_tactic_from_kill_chain

        result = parse_tactic_from_kill_chain(["d3fend:Harden"])

        assert result == "D3-HARDEN"

    def test_multiple_tactics_returns_first(self):
        """Test that multiple tactics returns the first one."""
        from cve_mcp.ingest.d3fend_parser import parse_tactic_from_kill_chain

        result = parse_tactic_from_kill_chain(["d3fend:Harden", "d3fend:Detect"])

        assert result == "D3-HARDEN"

    def test_empty_list(self):
        """Test that empty list returns None."""
        from cve_mcp.ingest.d3fend_parser import parse_tactic_from_kill_chain

        result = parse_tactic_from_kill_chain([])

        assert result is None

    def test_none(self):
        """Test that None input returns None."""
        from cve_mcp.ingest.d3fend_parser import parse_tactic_from_kill_chain

        result = parse_tactic_from_kill_chain(None)

        assert result is None

    def test_different_format(self):
        """Test extracting tactic with mitre-d3fend format."""
        from cve_mcp.ingest.d3fend_parser import parse_tactic_from_kill_chain

        result = parse_tactic_from_kill_chain(["mitre-d3fend:Model"])

        assert result == "D3-MODEL"


class TestExtractAttackMappings:
    """Tests for extract_attack_mappings function."""

    def test_counters_relationship(self):
        """Test extracting counters relationship with ATT&CK mapping."""
        from cve_mcp.ingest.d3fend_parser import extract_attack_mappings

        related = [
            {
                "dest-uuid": "xyz-123",
                "type": "counters",
                "tags": ["attack-technique:T1059"],
            }
        ]

        result = extract_attack_mappings(related)

        assert len(result) == 1
        assert result[0]["attack_technique_id"] == "T1059"
        assert result[0]["relationship_type"] == "counters"

    def test_multiple_mappings(self):
        """Test extracting multiple ATT&CK mappings."""
        from cve_mcp.ingest.d3fend_parser import extract_attack_mappings

        related = [
            {
                "dest-uuid": "xyz-123",
                "type": "counters",
                "tags": ["attack-technique:T1059"],
            },
            {
                "dest-uuid": "abc-456",
                "type": "detects",
                "tags": ["attack-technique:T1027"],
            },
        ]

        result = extract_attack_mappings(related)

        assert len(result) == 2
        assert result[0]["attack_technique_id"] == "T1059"
        assert result[0]["relationship_type"] == "counters"
        assert result[1]["attack_technique_id"] == "T1027"
        assert result[1]["relationship_type"] == "detects"

    def test_filters_non_attack_relations(self):
        """Test that entries without attack-technique tags are filtered out."""
        from cve_mcp.ingest.d3fend_parser import extract_attack_mappings

        related = [
            {
                "dest-uuid": "xyz-123",
                "type": "counters",
                "tags": ["attack-technique:T1059"],
            },
            {
                "dest-uuid": "abc-456",
                "type": "related-to",
                "tags": ["some-other-tag"],
            },
        ]

        result = extract_attack_mappings(related)

        assert len(result) == 1
        assert result[0]["attack_technique_id"] == "T1059"

    def test_empty_related(self):
        """Test that empty related list returns empty list."""
        from cve_mcp.ingest.d3fend_parser import extract_attack_mappings

        result = extract_attack_mappings([])

        assert result == []

    def test_none_related(self):
        """Test that None related returns empty list."""
        from cve_mcp.ingest.d3fend_parser import extract_attack_mappings

        result = extract_attack_mappings(None)

        assert result == []

    def test_subtechnique_id(self):
        """Test extracting subtechnique ID like T1059.001."""
        from cve_mcp.ingest.d3fend_parser import extract_attack_mappings

        related = [
            {
                "dest-uuid": "xyz-123",
                "type": "counters",
                "tags": ["attack-technique:T1059.001"],
            }
        ]

        result = extract_attack_mappings(related)

        assert len(result) == 1
        assert result[0]["attack_technique_id"] == "T1059.001"


class TestParseTechnique:
    """Tests for parse_technique function."""

    def test_basic_technique(self):
        """Test parsing a basic D3FEND technique."""
        from cve_mcp.ingest.d3fend_parser import parse_technique

        entry = {
            "value": "Application Hardening",
            "uuid": "abc-123-def",
            "description": "Techniques to make applications more secure.",
            "meta": {
                "external_id": "D3-AH",
                "kill_chain": ["d3fend:Harden"],
            },
        }

        result = parse_technique(entry)

        assert result["technique_id"] == "D3-AH"
        assert result["name"] == "Application Hardening"
        assert result["description"] == "Techniques to make applications more secure."
        assert result["tactic_id"] == "D3-HARDEN"

    def test_technique_with_synonyms(self):
        """Test parsing technique with synonyms."""
        from cve_mcp.ingest.d3fend_parser import parse_technique

        entry = {
            "value": "Application Hardening",
            "uuid": "abc-123-def",
            "description": "Techniques to make applications more secure.",
            "meta": {
                "external_id": "D3-AH",
                "kill_chain": ["d3fend:Harden"],
                "synonyms": ["App Hardening", "Application Security"],
            },
        }

        result = parse_technique(entry)

        assert result["synonyms"] == ["App Hardening", "Application Security"]

    def test_technique_with_attack_mappings(self):
        """Test parsing technique with ATT&CK mappings."""
        from cve_mcp.ingest.d3fend_parser import parse_technique

        entry = {
            "value": "Application Hardening",
            "uuid": "abc-123-def",
            "description": "Techniques to make applications more secure.",
            "meta": {
                "external_id": "D3-AH",
                "kill_chain": ["d3fend:Harden"],
            },
            "related": [
                {
                    "dest-uuid": "xyz",
                    "type": "counters",
                    "tags": ["attack-technique:T1059"],
                }
            ],
        }

        result = parse_technique(entry)

        assert len(result["attack_mappings"]) == 1
        assert result["attack_mappings"][0]["attack_technique_id"] == "T1059"
        assert result["attack_mappings"][0]["relationship_type"] == "counters"

    def test_technique_missing_optional_fields(self):
        """Test parsing technique with missing optional fields."""
        from cve_mcp.ingest.d3fend_parser import parse_technique

        entry = {
            "value": "Minimal Technique",
            "uuid": "min-uuid",
            "meta": {
                "external_id": "D3-MT",
            },
        }

        result = parse_technique(entry)

        assert result["technique_id"] == "D3-MT"
        assert result["name"] == "Minimal Technique"
        assert result["description"] is None
        assert result["tactic_id"] is None
        assert result["synonyms"] is None
        assert result["references"] == []
        assert result["kb_article_url"] is None
        assert result["attack_mappings"] == []

    def test_technique_with_references(self):
        """Test parsing technique with references, separating d3fend KB URL from other refs."""
        from cve_mcp.ingest.d3fend_parser import parse_technique

        entry = {
            "value": "Application Hardening",
            "uuid": "abc-123-def",
            "description": "Techniques to make applications more secure.",
            "meta": {
                "external_id": "D3-AH",
                "kill_chain": ["d3fend:Harden"],
                "refs": [
                    "https://d3fend.mitre.org/technique/d3f:ApplicationHardening",
                    "https://example.com/paper.pdf",
                    "https://nvd.nist.gov/some-reference",
                ],
            },
        }

        result = parse_technique(entry)

        # d3fend.mitre.org URL should be the kb_article_url
        assert (
            result["kb_article_url"]
            == "https://d3fend.mitre.org/technique/d3f:ApplicationHardening"
        )

        # Other refs should be in references list
        assert len(result["references"]) == 2
        assert result["references"][0]["url"] == "https://example.com/paper.pdf"
        assert result["references"][1]["url"] == "https://nvd.nist.gov/some-reference"
