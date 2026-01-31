"""Integration tests for MITRE ATT&CK MCP tools.

Tests MCP tool definitions, schemas, and semantic search functionality.
Follows TDD approach - these tests are written BEFORE implementation.
"""

import pytest


class TestAttackMCPTools:
    """Test ATT&CK MCP tool definitions are properly configured."""

    def test_attack_tools_defined(self):
        """All 7 ATT&CK MCP tools are defined."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool_names = {tool.name for tool in MCP_TOOLS}
        expected_attack_tools = {
            "search_techniques",
            "find_similar_techniques",
            "get_technique_details",
            "get_technique_badges",
            "search_threat_actors",
            "find_similar_threat_actors",
            "get_group_profile",
        }

        # Check all ATT&CK tools are present
        assert expected_attack_tools.issubset(tool_names)

    def test_semantic_tools_mention_ai(self):
        """Semantic search tools mention AI/embeddings in description."""
        from cve_mcp.api.tools import MCP_TOOLS

        semantic_tools = [
            tool for tool in MCP_TOOLS
            if tool.name in ["find_similar_techniques", "find_similar_threat_actors"]
        ]

        assert len(semantic_tools) == 2

        for tool in semantic_tools:
            desc = tool.description.lower()
            # Should mention AI/semantic/embeddings/similarity
            assert any(
                keyword in desc
                for keyword in ["ai", "semantic", "embedding", "similarity"]
            )

    def test_search_techniques_schema(self):
        """search_techniques tool has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "search_techniques")
        props = tool.inputSchema["properties"]

        # Check key parameters
        assert "query" in props
        assert "tactics" in props
        assert "platforms" in props
        assert "include_subtechniques" in props
        assert "active_only" in props
        assert "limit" in props

    def test_find_similar_techniques_schema(self):
        """find_similar_techniques tool has semantic search schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "find_similar_techniques")
        props = tool.inputSchema["properties"]

        # Check semantic search parameters
        assert "description" in props
        assert "min_similarity" in props
        assert "tactics" in props
        assert "platforms" in props
        assert "active_only" in props
        assert "limit" in props

        # Verify required fields
        required = tool.inputSchema.get("required", [])
        assert "description" in required

    def test_get_group_profile_schema(self):
        """get_group_profile tool has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool = next(t for t in MCP_TOOLS if t.name == "get_group_profile")
        props = tool.inputSchema["properties"]

        # Check parameters
        assert "group_id" in props

        # Verify required fields
        required = tool.inputSchema.get("required", [])
        assert "group_id" in required


class TestAttackSchemas:
    """Test ATT&CK Pydantic schemas validate correctly."""

    def test_search_techniques_request_validation(self):
        """SearchTechniquesRequest validates parameters correctly."""
        from cve_mcp.api.schemas import SearchTechniquesRequest

        # Valid request
        request = SearchTechniquesRequest(
            query="phishing",
            tactics=["initial-access"],
            platforms=["windows"],
            limit=10
        )
        assert request.query == "phishing"
        assert request.tactics == ["initial-access"]
        assert request.limit == 10

    def test_find_similar_techniques_description_validation(self):
        """FindSimilarTechniquesRequest validates description length."""
        from cve_mcp.api.schemas import FindSimilarTechniquesRequest
        from pydantic import ValidationError

        # Valid request
        request = FindSimilarTechniquesRequest(
            description="Attacker sent phishing email with malicious attachment"
        )
        assert len(request.description) >= 10

        # Invalid: description too short
        with pytest.raises(ValidationError):
            FindSimilarTechniquesRequest(description="short")

        # Invalid: description too long
        with pytest.raises(ValidationError):
            FindSimilarTechniquesRequest(description="x" * 6000)

    def test_find_similar_techniques_similarity_validation(self):
        """min_similarity must be between 0 and 1."""
        from cve_mcp.api.schemas import FindSimilarTechniquesRequest
        from pydantic import ValidationError

        # Valid similarity values
        request1 = FindSimilarTechniquesRequest(
            description="Test attack scenario",
            min_similarity=0.7
        )
        assert request1.min_similarity == 0.7

        request2 = FindSimilarTechniquesRequest(
            description="Test attack scenario",
            min_similarity=0.0
        )
        assert request2.min_similarity == 0.0

        # Invalid: similarity > 1
        with pytest.raises(ValidationError):
            FindSimilarTechniquesRequest(
                description="Test attack scenario",
                min_similarity=1.5
            )

        # Invalid: similarity < 0
        with pytest.raises(ValidationError):
            FindSimilarTechniquesRequest(
                description="Test attack scenario",
                min_similarity=-0.1
            )

    def test_get_technique_details_request(self):
        """GetTechniqueDetailsRequest validates technique_id format."""
        from cve_mcp.api.schemas import GetTechniqueDetailsRequest

        # Valid technique IDs
        request1 = GetTechniqueDetailsRequest(technique_id="T1566")
        assert request1.technique_id == "T1566"

        request2 = GetTechniqueDetailsRequest(technique_id="T1566.001")
        assert request2.technique_id == "T1566.001"

    def test_get_technique_badges_request(self):
        """GetTechniqueBadgesRequest accepts list of technique IDs."""
        from cve_mcp.api.schemas import GetTechniqueBadgesRequest

        request = GetTechniqueBadgesRequest(
            technique_ids=["T1566", "T1566.001", "T1059.001"]
        )
        assert len(request.technique_ids) == 3

    def test_search_threat_actors_request(self):
        """SearchThreatActorsRequest validates correctly."""
        from cve_mcp.api.schemas import SearchThreatActorsRequest

        request = SearchThreatActorsRequest(
            query="apt",
            techniques=["T1566.001"],
            limit=20
        )
        assert request.query == "apt"
        assert request.techniques == ["T1566.001"]
        assert request.limit == 20

    def test_find_similar_threat_actors_request(self):
        """FindSimilarThreatActorsRequest validates description length."""
        from cve_mcp.api.schemas import FindSimilarThreatActorsRequest
        from pydantic import ValidationError

        # Valid request
        request = FindSimilarThreatActorsRequest(
            description="Advanced persistent threat targeting financial institutions"
        )
        assert len(request.description) >= 10

        # Invalid: too short
        with pytest.raises(ValidationError):
            FindSimilarThreatActorsRequest(description="apt")

    def test_get_group_profile_request(self):
        """GetGroupProfileRequest validates group_id format."""
        from cve_mcp.api.schemas import GetGroupProfileRequest

        request = GetGroupProfileRequest(group_id="G0001")
        assert request.group_id == "G0001"


class TestAttackToolHandlers:
    """Test ATT&CK tool handlers are registered."""

    def test_all_handlers_registered(self):
        """All 7 ATT&CK tool handlers are in TOOL_HANDLERS mapping."""
        from cve_mcp.api.tools import TOOL_HANDLERS

        expected_handlers = {
            "search_techniques",
            "find_similar_techniques",
            "get_technique_details",
            "get_technique_badges",
            "search_threat_actors",
            "find_similar_threat_actors",
            "get_group_profile",
        }

        assert expected_handlers.issubset(TOOL_HANDLERS.keys())

    def test_handlers_are_async_functions(self):
        """All ATT&CK handlers are async functions."""
        import inspect

        from cve_mcp.api.tools import TOOL_HANDLERS

        attack_handlers = [
            "search_techniques",
            "find_similar_techniques",
            "get_technique_details",
            "get_technique_badges",
            "search_threat_actors",
            "find_similar_threat_actors",
            "get_group_profile",
        ]

        for handler_name in attack_handlers:
            handler = TOOL_HANDLERS.get(handler_name)
            assert handler is not None
            assert inspect.iscoroutinefunction(handler)


@pytest.mark.asyncio
class TestAttackQueryService:
    """Test ATT&CK query service functions exist."""

    async def test_search_techniques_exists(self):
        """search_techniques function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "search_techniques")
        assert callable(attack_queries.search_techniques)

    async def test_find_similar_techniques_exists(self):
        """find_similar_techniques function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "find_similar_techniques")
        assert callable(attack_queries.find_similar_techniques)

    async def test_get_technique_details_exists(self):
        """get_technique_details function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "get_technique_details")
        assert callable(attack_queries.get_technique_details)

    async def test_get_technique_badges_exists(self):
        """get_technique_badges function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "get_technique_badges")
        assert callable(attack_queries.get_technique_badges)

    async def test_search_threat_actors_exists(self):
        """search_threat_actors function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "search_threat_actors")
        assert callable(attack_queries.search_threat_actors)

    async def test_find_similar_threat_actors_exists(self):
        """find_similar_threat_actors function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "find_similar_threat_actors")
        assert callable(attack_queries.find_similar_threat_actors)

    async def test_get_group_profile_exists(self):
        """get_group_profile function exists."""
        from cve_mcp.services import attack_queries

        assert hasattr(attack_queries, "get_group_profile")
        assert callable(attack_queries.get_group_profile)


@pytest.mark.asyncio
class TestAttackBadgeURL:
    """Test ATT&CK technique badge URL generation."""

    async def test_badge_url_format_parent_technique(self):
        """Badge URL format correct for parent technique."""
        from cve_mcp.models.attack import AttackTechnique

        technique = AttackTechnique(
            technique_id="T1566",
            stix_id="attack-pattern--test",
            name="Phishing",
            description="Test description",
            created="2024-01-01T00:00:00Z",
            modified="2024-01-01T00:00:00Z"
        )

        assert technique.badge_url == "https://attack.mitre.org/techniques/T1566/"

    async def test_badge_url_format_subtechnique(self):
        """Badge URL format correct for subtechnique with / separator."""
        from cve_mcp.models.attack import AttackTechnique

        technique = AttackTechnique(
            technique_id="T1566.001",
            stix_id="attack-pattern--test",
            name="Spearphishing Attachment",
            description="Test description",
            is_subtechnique=True,
            created="2024-01-01T00:00:00Z",
            modified="2024-01-01T00:00:00Z"
        )

        # Should replace . with /
        assert technique.badge_url == "https://attack.mitre.org/techniques/T1566/001/"
