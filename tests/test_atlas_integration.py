"""Tests for ATLAS MCP tool integration.

These tests verify that:
1. ATLAS MCP tools are properly defined
2. Tool schemas are valid
3. Request validators work correctly
4. Handler functions exist
5. Badge URLs are correctly formatted
"""

import inspect

import pytest


class TestATLASMCPTools:
    """Test ATLAS MCP tool definitions."""

    def test_atlas_tools_defined(self):
        """All 5 ATLAS MCP tools are defined."""
        from cve_mcp.api.tools import MCP_TOOLS

        atlas_tools = [t for t in MCP_TOOLS if "atlas" in t.name.lower()]
        assert len(atlas_tools) == 5

        tool_names = {t.name for t in atlas_tools}
        expected = {
            "search_atlas_techniques",
            "find_similar_atlas_techniques",
            "get_atlas_technique_details",
            "search_atlas_case_studies",
            "find_similar_atlas_case_studies",
        }
        assert tool_names == expected

    def test_semantic_tools_mention_ai(self):
        """Semantic search tools mention AI-powered functionality."""
        from cve_mcp.api.tools import MCP_TOOLS

        semantic_tools = [
            t for t in MCP_TOOLS
            if t.name in {"find_similar_atlas_techniques", "find_similar_atlas_case_studies"}
        ]
        for tool in semantic_tools:
            assert "ai" in tool.description.lower() or "semantic" in tool.description.lower()

    def test_search_atlas_techniques_schema(self):
        """search_atlas_techniques has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "search_atlas_techniques")
        props = tool.inputSchema["properties"]

        # Check required properties exist
        assert "query" in props
        assert "tactics" in props
        assert "ml_lifecycle_stage" in props
        assert "ai_system_type" in props
        assert "active_only" in props
        assert "limit" in props

        # Check ATLAS-specific filter descriptions
        assert "lifecycle" in props["ml_lifecycle_stage"]["description"].lower()
        assert "ai system" in props["ai_system_type"]["description"].lower()

    def test_find_similar_atlas_techniques_schema(self):
        """find_similar_atlas_techniques has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "find_similar_atlas_techniques")

        # description is required
        assert "description" in tool.inputSchema.get("required", [])

        props = tool.inputSchema["properties"]
        assert "description" in props
        assert "min_similarity" in props
        assert "tactics" in props
        assert "ml_lifecycle_stage" in props
        assert "ai_system_type" in props

        # Check min_similarity constraints
        sim_prop = props["min_similarity"]
        assert sim_prop.get("minimum") == 0.0
        assert sim_prop.get("maximum") == 1.0

    def test_get_atlas_technique_details_schema(self):
        """get_atlas_technique_details has correct schema with ATLAS ID pattern."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "get_atlas_technique_details")

        # technique_id is required
        assert "technique_id" in tool.inputSchema.get("required", [])

        props = tool.inputSchema["properties"]
        assert "technique_id" in props

        # ATLAS technique ID pattern: AML.T####
        assert "pattern" in props["technique_id"]
        assert "AML" in props["technique_id"]["pattern"]

    def test_search_atlas_case_studies_schema(self):
        """search_atlas_case_studies has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "search_atlas_case_studies")
        props = tool.inputSchema["properties"]

        assert "query" in props
        assert "techniques" in props
        assert "limit" in props

    def test_find_similar_atlas_case_studies_schema(self):
        """find_similar_atlas_case_studies has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "find_similar_atlas_case_studies")

        # description is required
        assert "description" in tool.inputSchema.get("required", [])

        props = tool.inputSchema["properties"]
        assert "description" in props
        assert "min_similarity" in props
        assert "limit" in props


class TestATLASSchemas:
    """Test ATLAS Pydantic request schemas."""

    def test_search_atlas_techniques_request_validation(self):
        """SearchATLASTechniquesRequest validates correctly."""
        from cve_mcp.api.schemas import SearchATLASTechniquesRequest

        # Valid request with all fields
        request = SearchATLASTechniquesRequest(
            query="model inversion",
            tactics=["reconnaissance", "ml-attack-staging"],
            ml_lifecycle_stage="deployment",
            ai_system_type=["computer-vision"],
            active_only=True,
            limit=25,
        )
        assert request.query == "model inversion"
        assert request.tactics == ["reconnaissance", "ml-attack-staging"]
        assert request.ml_lifecycle_stage == "deployment"
        assert request.ai_system_type == ["computer-vision"]
        assert request.active_only is True
        assert request.limit == 25

        # Default values
        default_request = SearchATLASTechniquesRequest()
        assert default_request.query is None
        assert default_request.active_only is True
        assert default_request.limit == 50

    def test_find_similar_atlas_techniques_description_validation(self):
        """FindSimilarATLASTechniquesRequest validates description length."""
        from cve_mcp.api.schemas import FindSimilarATLASTechniquesRequest
        from pydantic import ValidationError

        # Valid description
        request = FindSimilarATLASTechniquesRequest(
            description="Attacker poisoned training data to create backdoor in ML model"
        )
        assert len(request.description) >= 10

        # Too short description
        with pytest.raises(ValidationError):
            FindSimilarATLASTechniquesRequest(description="short")

    def test_find_similar_atlas_techniques_similarity_validation(self):
        """FindSimilarATLASTechniquesRequest validates similarity range."""
        from cve_mcp.api.schemas import FindSimilarATLASTechniquesRequest
        from pydantic import ValidationError

        # Valid similarity
        request = FindSimilarATLASTechniquesRequest(
            description="Test description for ML attack",
            min_similarity=0.8,
        )
        assert request.min_similarity == 0.8

        # Invalid similarity > 1.0
        with pytest.raises(ValidationError):
            FindSimilarATLASTechniquesRequest(
                description="Test description for ML attack",
                min_similarity=1.5,
            )

        # Invalid similarity < 0.0
        with pytest.raises(ValidationError):
            FindSimilarATLASTechniquesRequest(
                description="Test description for ML attack",
                min_similarity=-0.1,
            )

    def test_get_atlas_technique_details_request(self):
        """GetATLASTechniqueDetailsRequest validates ATLAS technique ID."""
        from cve_mcp.api.schemas import GetATLASTechniqueDetailsRequest
        from pydantic import ValidationError

        # Valid ATLAS technique ID
        request = GetATLASTechniqueDetailsRequest(technique_id="AML.T0001")
        assert request.technique_id == "AML.T0001"

        # Invalid format (ATT&CK format)
        with pytest.raises(ValidationError):
            GetATLASTechniqueDetailsRequest(technique_id="T1566")

        # Invalid format (missing AML prefix)
        with pytest.raises(ValidationError):
            GetATLASTechniqueDetailsRequest(technique_id="T0001")

    def test_search_atlas_case_studies_request(self):
        """SearchATLASCaseStudiesRequest validates correctly."""
        from cve_mcp.api.schemas import SearchATLASCaseStudiesRequest

        request = SearchATLASCaseStudiesRequest(
            query="autonomous vehicle",
            techniques=["AML.T0001", "AML.T0002"],
            limit=20,
        )
        assert request.query == "autonomous vehicle"
        assert request.techniques == ["AML.T0001", "AML.T0002"]
        assert request.limit == 20

    def test_find_similar_atlas_case_studies_request(self):
        """FindSimilarATLASCaseStudiesRequest validates correctly."""
        from cve_mcp.api.schemas import FindSimilarATLASCaseStudiesRequest
        from pydantic import ValidationError

        # Valid request
        request = FindSimilarATLASCaseStudiesRequest(
            description="Adversarial attack on autonomous driving system",
            min_similarity=0.6,
            limit=5,
        )
        assert request.description == "Adversarial attack on autonomous driving system"
        assert request.min_similarity == 0.6
        assert request.limit == 5

        # Description too short
        with pytest.raises(ValidationError):
            FindSimilarATLASCaseStudiesRequest(description="too short")


class TestATLASToolHandlers:
    """Test ATLAS tool handlers are properly registered."""

    def test_all_handlers_registered(self):
        """All 5 ATLAS handlers are registered in TOOL_HANDLERS."""
        from cve_mcp.api.tools import TOOL_HANDLERS

        atlas_handlers = [h for h in TOOL_HANDLERS.keys() if "atlas" in h.lower()]
        assert len(atlas_handlers) == 5

        expected = {
            "search_atlas_techniques",
            "find_similar_atlas_techniques",
            "get_atlas_technique_details",
            "search_atlas_case_studies",
            "find_similar_atlas_case_studies",
        }
        assert set(atlas_handlers) == expected

    def test_handlers_are_async_functions(self):
        """All ATLAS handlers are async functions."""
        from cve_mcp.api.tools import TOOL_HANDLERS

        atlas_handlers = {
            k: v for k, v in TOOL_HANDLERS.items()
            if "atlas" in k.lower()
        }
        for name, handler in atlas_handlers.items():
            assert inspect.iscoroutinefunction(handler), \
                f"Handler {name} should be async"


class TestATLASQueryService:
    """Test ATLAS query service functions exist."""

    def test_search_techniques_exists(self):
        """search_techniques function exists."""
        from cve_mcp.services import atlas_queries

        assert hasattr(atlas_queries, "search_techniques")
        assert inspect.iscoroutinefunction(atlas_queries.search_techniques)

    def test_find_similar_techniques_exists(self):
        """find_similar_techniques function exists."""
        from cve_mcp.services import atlas_queries

        assert hasattr(atlas_queries, "find_similar_techniques")
        assert inspect.iscoroutinefunction(atlas_queries.find_similar_techniques)

    def test_get_technique_details_exists(self):
        """get_technique_details function exists."""
        from cve_mcp.services import atlas_queries

        assert hasattr(atlas_queries, "get_technique_details")
        assert inspect.iscoroutinefunction(atlas_queries.get_technique_details)

    def test_search_case_studies_exists(self):
        """search_case_studies function exists."""
        from cve_mcp.services import atlas_queries

        assert hasattr(atlas_queries, "search_case_studies")
        assert inspect.iscoroutinefunction(atlas_queries.search_case_studies)

    def test_find_similar_case_studies_exists(self):
        """find_similar_case_studies function exists."""
        from cve_mcp.services import atlas_queries

        assert hasattr(atlas_queries, "find_similar_case_studies")
        assert inspect.iscoroutinefunction(atlas_queries.find_similar_case_studies)


class TestATLASBadgeURL:
    """Test ATLAS badge URL generation."""

    def test_badge_url_format(self):
        """ATLAS badge URL uses atlas.mitre.org."""
        from cve_mcp.models.atlas import ATLASTechnique

        # Create a mock technique
        tech = ATLASTechnique(
            technique_id="AML.T0001",
            stix_id="attack-pattern--00000000-0000-0000-0000-000000000001",
            name="Test Technique",
            description="Test description",
        )

        badge_url = tech.badge_url
        assert badge_url == "https://atlas.mitre.org/techniques/AML.T0001"
        assert "atlas.mitre.org" in badge_url
        assert "attack.mitre.org" not in badge_url

    def test_badge_url_uses_technique_id(self):
        """Badge URL correctly includes the technique ID."""
        from cve_mcp.models.atlas import ATLASTechnique

        tech = ATLASTechnique(
            technique_id="AML.T0042",
            stix_id="attack-pattern--00000000-0000-0000-0000-000000000042",
            name="Another Technique",
            description="Another description",
        )

        assert "AML.T0042" in tech.badge_url
