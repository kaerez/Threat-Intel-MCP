"""Tests for CWE XML parser."""

from lxml import etree


class TestParseWeaknessBasic:
    """Tests for parse_weakness function - basic functionality."""

    def test_parse_weakness_basic(self):
        """Test parsing basic CWE weakness with minimal fields."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation"
                  Abstraction="Base" Status="Stable">
            <Description>The product does not neutralize or incorrectly neutralizes
            user-controllable input before it is placed in output.</Description>
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
        assert result["deprecated"] is False

    def test_parse_weakness_missing_id(self):
        """Test parsing weakness without ID returns None."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness Name="Test Weakness" Abstraction="Base" Status="Stable">
            <Description>Test description</Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is None

    def test_parse_weakness_invalid_id(self):
        """Test parsing weakness with non-numeric ID returns None."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="invalid" Name="Test" Abstraction="Base" Status="Stable">
            <Description>Test</Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is None


class TestParseWeaknessWithConsequences:
    """Tests for parse_weakness with Common_Consequences."""

    def test_parse_weakness_with_consequences(self):
        """Test parsing weakness with common consequences."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability</Description>
            <Common_Consequences>
                <Consequence>
                    <Scope>Confidentiality</Scope>
                    <Impact>Read Application Data</Impact>
                </Consequence>
                <Consequence>
                    <Scope>Integrity</Scope>
                    <Scope>Availability</Scope>
                    <Impact>Execute Unauthorized Code</Impact>
                    <Impact>Modify Application Data</Impact>
                    <Likelihood>High</Likelihood>
                    <Note>Attackers can steal session cookies.</Note>
                </Consequence>
            </Common_Consequences>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["common_consequences"] is not None
        assert len(result["common_consequences"]) == 2

        # First consequence - single scope and impact
        cons1 = result["common_consequences"][0]
        assert cons1["scope"] == "Confidentiality"
        assert cons1["impact"] == "Read Application Data"

        # Second consequence - multiple scopes and impacts
        cons2 = result["common_consequences"][1]
        assert cons2["scope"] == ["Integrity", "Availability"]
        assert cons2["impact"] == ["Execute Unauthorized Code", "Modify Application Data"]
        assert cons2["likelihood"] == "High"
        assert "steal session cookies" in cons2["note"]


class TestParseWeaknessWithMitigations:
    """Tests for parse_weakness with Potential_Mitigations."""

    def test_parse_weakness_with_mitigations(self):
        """Test parsing weakness with potential mitigations."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
            <Description>SQL injection vulnerability</Description>
            <Potential_Mitigations>
                <Mitigation>
                    <Phase>Implementation</Phase>
                    <Strategy>Input Validation</Strategy>
                    <Effectiveness>High</Effectiveness>
                    <Description>Validate all input before using in queries.</Description>
                </Mitigation>
                <Mitigation>
                    <Phase>Architecture and Design</Phase>
                    <Phase>Implementation</Phase>
                    <Strategy>Parameterization</Strategy>
                    <Description>Use parameterized queries.</Description>
                </Mitigation>
            </Potential_Mitigations>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["potential_mitigations"] is not None
        assert len(result["potential_mitigations"]) == 2

        # First mitigation - single phase
        mit1 = result["potential_mitigations"][0]
        assert mit1["phase"] == "Implementation"
        assert mit1["strategy"] == "Input Validation"
        assert mit1["effectiveness"] == "High"
        assert "Validate all input" in mit1["description"]

        # Second mitigation - multiple phases
        mit2 = result["potential_mitigations"][1]
        assert mit2["phase"] == ["Architecture and Design", "Implementation"]
        assert mit2["strategy"] == "Parameterization"


class TestParseWeaknessWithDetectionMethods:
    """Tests for parse_weakness with Detection_Methods."""

    def test_parse_weakness_with_detection_methods(self):
        """Test parsing weakness with detection methods."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability</Description>
            <Detection_Methods>
                <Detection_Method>
                    <Method>Automated Static Analysis</Method>
                    <Effectiveness>High</Effectiveness>
                    <Description>Static analysis tools can detect this.</Description>
                </Detection_Method>
                <Detection_Method>
                    <Method>Manual Analysis</Method>
                    <Description>Code review can identify XSS.</Description>
                </Detection_Method>
            </Detection_Methods>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["detection_methods"] is not None
        assert len(result["detection_methods"]) == 2

        # First detection method - with effectiveness
        det1 = result["detection_methods"][0]
        assert det1["method"] == "Automated Static Analysis"
        assert det1["effectiveness"] == "High"
        assert "Static analysis tools" in det1["description"]

        # Second detection method - without effectiveness
        det2 = result["detection_methods"][1]
        assert det2["method"] == "Manual Analysis"
        assert "effectiveness" not in det2
        assert "Code review" in det2["description"]


class TestParseWeaknessWithRelationships:
    """Tests for parse_weakness with Related_Weaknesses."""

    def test_parse_weakness_with_relationships(self):
        """Test parsing weakness with related weaknesses."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability</Description>
            <Related_Weaknesses>
                <Related_Weakness Nature="ChildOf" CWE_ID="74"/>
                <Related_Weakness Nature="ParentOf" CWE_ID="80"/>
                <Related_Weakness Nature="ParentOf" CWE_ID="81"/>
                <Related_Weakness Nature="PeerOf" CWE_ID="352"/>
                <Related_Weakness Nature="CanPrecede" CWE_ID="494"/>
                <Related_Weakness Nature="CanFollow" CWE_ID="20"/>
            </Related_Weaknesses>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["child_of"] == ["CWE-74"]
        assert result["parent_of"] == ["CWE-80", "CWE-81"]
        assert result["peer_of"] == ["CWE-352"]
        assert result["can_precede"] == ["CWE-494"]
        assert result["can_follow"] == ["CWE-20"]


class TestParseWeaknessDeprecated:
    """Tests for deprecated weakness handling."""

    def test_parse_weakness_deprecated(self):
        """Test parsing deprecated weakness."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="999" Name="Deprecated Weakness" Abstraction="Base" Status="Deprecated">
            <Description>This weakness is deprecated.</Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["deprecated"] is True
        assert result["status"] == "Deprecated"


class TestParseWeaknessWithTaxonomyMappings:
    """Tests for parse_weakness with Taxonomy_Mappings."""

    def test_parse_weakness_with_taxonomy_mappings(self):
        """Test parsing weakness with taxonomy mappings."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability</Description>
            <Taxonomy_Mappings>
                <Taxonomy_Mapping Taxonomy_Name="OWASP Top Ten 2021">
                    <Entry_ID>A03:2021</Entry_ID>
                    <Entry_Name>Injection</Entry_Name>
                    <Mapping_Fit>Exact</Mapping_Fit>
                </Taxonomy_Mapping>
                <Taxonomy_Mapping Taxonomy_Name="SANS Top 25">
                    <Entry_ID>SANS-1</Entry_ID>
                </Taxonomy_Mapping>
            </Taxonomy_Mappings>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["taxonomy_mappings"] is not None
        assert len(result["taxonomy_mappings"]) == 2

        # OWASP mapping
        owasp = result["taxonomy_mappings"][0]
        assert owasp["taxonomy_name"] == "OWASP Top Ten 2021"
        assert owasp["entry_id"] == "A03:2021"
        assert owasp["entry_name"] == "Injection"
        assert owasp["mapping_fit"] == "Exact"

        # SANS mapping
        sans = result["taxonomy_mappings"][1]
        assert sans["taxonomy_name"] == "SANS Top 25"
        assert sans["entry_id"] == "SANS-1"


class TestParseCategoryBasic:
    """Tests for parse_category function."""

    def test_parse_category_basic(self):
        """Test parsing basic CWE category."""
        from cve_mcp.ingest.cwe_parser import parse_category

        xml = """
        <Category ID="1000" Name="Research Concepts" Status="Stable">
            <Summary>Weaknesses in this category are used for research purposes.</Summary>
            <Relationships>
                <Has_Member CWE_ID="79"/>
                <Has_Member CWE_ID="89"/>
                <Has_Member CWE_ID="352"/>
            </Relationships>
        </Category>
        """
        element = etree.fromstring(xml)
        result = parse_category(element)

        assert result is not None
        assert result["category_id"] == "CWE-1000"
        assert result["name"] == "Research Concepts"
        assert result["status"] == "Stable"
        assert "research purposes" in result["summary"]
        assert result["members"] == ["CWE-79", "CWE-89", "CWE-352"]

    def test_parse_category_missing_id(self):
        """Test parsing category without ID returns None."""
        from cve_mcp.ingest.cwe_parser import parse_category

        xml = """
        <Category Name="Test Category" Status="Stable">
            <Summary>Test summary</Summary>
        </Category>
        """
        element = etree.fromstring(xml)
        result = parse_category(element)

        assert result is None


class TestParseViewBasic:
    """Tests for parse_view function."""

    def test_parse_view_basic(self):
        """Test parsing basic CWE view."""
        from cve_mcp.ingest.cwe_parser import parse_view

        xml = """
        <View ID="1003" Name="Weaknesses for Simplified Mapping" Type="Graph" Status="Stable">
            <Objective>This view provides a simplified mapping of weaknesses.</Objective>
            <Members>
                <Has_Member CWE_ID="79"/>
                <Has_Member CWE_ID="89"/>
            </Members>
        </View>
        """
        element = etree.fromstring(xml)
        result = parse_view(element)

        assert result is not None
        assert result["view_id"] == "CWE-1003"
        assert result["name"] == "Weaknesses for Simplified Mapping"
        assert result["view_type"] == "Graph"
        assert result["status"] == "Stable"
        assert "simplified mapping" in result["objective"]
        assert result["members"] == ["CWE-79", "CWE-89"]

    def test_parse_view_missing_id(self):
        """Test parsing view without ID returns None."""
        from cve_mcp.ingest.cwe_parser import parse_view

        xml = """
        <View Name="Test View" Type="Graph" Status="Stable">
            <Objective>Test objective</Objective>
        </View>
        """
        element = etree.fromstring(xml)
        result = parse_view(element)

        assert result is None


class TestParseExternalMapping:
    """Tests for parse_external_mapping function."""

    def test_parse_external_mapping_owasp(self):
        """Test parsing OWASP taxonomy mapping."""
        from cve_mcp.ingest.cwe_parser import parse_external_mapping

        mapping_data = {
            "taxonomy_name": "OWASP Top Ten 2021",
            "entry_id": "A03:2021",
            "entry_name": "Injection",
            "mapping_fit": "Exact",
        }

        result = parse_external_mapping("CWE-79", mapping_data)

        assert result is not None
        assert result["weakness_id"] == "CWE-79"
        assert result["taxonomy_name"] == "OWASP Top Ten 2021"
        assert result["entry_id"] == "A03:2021"
        assert result["entry_name"] == "Injection"
        assert result["framework_type"] == "owasp"
        assert result["mapping_fit"] == "Exact"

    def test_parse_external_mapping_sans(self):
        """Test parsing SANS taxonomy mapping."""
        from cve_mcp.ingest.cwe_parser import parse_external_mapping

        mapping_data = {
            "taxonomy_name": "CWE Top 25 2023",
            "entry_id": "1",
        }

        result = parse_external_mapping("CWE-89", mapping_data)

        assert result is not None
        assert result["framework_type"] == "sans"

    def test_parse_external_mapping_invalid(self):
        """Test parsing invalid mapping returns None."""
        from cve_mcp.ingest.cwe_parser import parse_external_mapping

        # Missing taxonomy_name
        result = parse_external_mapping("CWE-79", {"entry_id": "A01"})
        assert result is None

        # Empty weakness_id
        result = parse_external_mapping("", {"taxonomy_name": "OWASP"})
        assert result is None

        # None mapping_data
        result = parse_external_mapping("CWE-79", None)
        assert result is None


class TestParseWeaknessMissingOptionalFields:
    """Tests for handling missing optional fields."""

    def test_parse_weakness_missing_optional_fields(self):
        """Test parsing weakness with only required fields."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="123" Name="Minimal Weakness" Abstraction="Class" Status="Draft">
            <Description>Minimal description</Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["cwe_id"] == "CWE-123"
        assert result["weakness_id"] == 123
        assert result["name"] == "Minimal Weakness"
        assert result["description"] == "Minimal description"
        assert result["extended_description"] is None
        assert result["likelihood_of_exploit"] is None
        assert result["common_consequences"] is None
        assert result["potential_mitigations"] is None
        assert result["detection_methods"] is None
        assert result["parent_of"] is None
        assert result["child_of"] is None
        assert result["peer_of"] is None
        assert result["can_precede"] is None
        assert result["can_follow"] is None
        assert result["taxonomy_mappings"] is None


class TestParseWeaknessAbstractionLevels:
    """Tests for all abstraction levels."""

    def test_parse_weakness_all_abstraction_levels(self):
        """Test parsing weaknesses with all abstraction levels."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        abstraction_levels = ["Pillar", "Class", "Base", "Variant", "Compound"]

        for i, level in enumerate(abstraction_levels, start=1):
            xml = f"""
            <Weakness ID="{i}" Name="Test {level}" Abstraction="{level}" Status="Stable">
                <Description>Test description for {level}</Description>
            </Weakness>
            """
            element = etree.fromstring(xml)
            result = parse_weakness(element)

            assert result is not None
            assert result["cwe_id"] == f"CWE-{i}"
            assert result["abstraction"] == level


class TestParseWeaknessWithLikelihood:
    """Tests for likelihood of exploit field."""

    def test_parse_weakness_with_likelihood(self):
        """Test parsing weakness with likelihood of exploit."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>XSS vulnerability</Description>
            <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["likelihood_of_exploit"] == "High"

    def test_parse_weakness_likelihood_values(self):
        """Test parsing different likelihood values."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        likelihood_values = ["High", "Medium", "Low"]

        for likelihood in likelihood_values:
            xml = f"""
            <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
                <Description>XSS</Description>
                <Likelihood_Of_Exploit>{likelihood}</Likelihood_Of_Exploit>
            </Weakness>
            """
            element = etree.fromstring(xml)
            result = parse_weakness(element)

            assert result is not None
            assert result["likelihood_of_exploit"] == likelihood


class TestParseWeaknessExtendedDescription:
    """Tests for extended description handling."""

    def test_parse_weakness_with_extended_description(self):
        """Test parsing weakness with extended description."""
        from cve_mcp.ingest.cwe_parser import parse_weakness

        xml = """
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
            <Description>Short description</Description>
            <Extended_Description>
                This is a longer description that provides more context.
                It can span multiple lines and contains additional details.
            </Extended_Description>
        </Weakness>
        """
        element = etree.fromstring(xml)
        result = parse_weakness(element)

        assert result is not None
        assert result["description"] == "Short description"
        assert "longer description" in result["extended_description"]
        assert "additional details" in result["extended_description"]


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_text_with_content(self):
        """Test _get_text with element that has text."""
        from cve_mcp.ingest.cwe_parser import _get_text

        xml = "<Element>Some text content</Element>"
        element = etree.fromstring(xml)
        result = _get_text(element)

        assert result == "Some text content"

    def test_get_text_empty(self):
        """Test _get_text with empty element."""
        from cve_mcp.ingest.cwe_parser import _get_text

        xml = "<Element></Element>"
        element = etree.fromstring(xml)
        result = _get_text(element)

        assert result is None

    def test_get_text_none(self):
        """Test _get_text with None."""
        from cve_mcp.ingest.cwe_parser import _get_text

        result = _get_text(None)
        assert result is None

    def test_get_all_text_nested(self):
        """Test _get_all_text with nested elements."""
        from cve_mcp.ingest.cwe_parser import _get_all_text

        xml = "<Element>Start <Nested>middle</Nested> end</Element>"
        element = etree.fromstring(xml)
        result = _get_all_text(element)

        assert result is not None
        assert "Start" in result
        assert "middle" in result
        assert "end" in result

    def test_get_all_text_none(self):
        """Test _get_all_text with None."""
        from cve_mcp.ingest.cwe_parser import _get_all_text

        result = _get_all_text(None)
        assert result is None
