"""Tests for D3FEND query services.

TDD: Tests written before implementation.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cve_mcp.models.d3fend import D3FENDRelationshipType


class TestTechniqueToDict:
    """Test _technique_to_dict helper function."""

    def test_technique_to_dict_summary(self):
        """_technique_to_dict returns summary dict by default."""
        from cve_mcp.services.d3fend_queries import _technique_to_dict

        # Create mock technique
        technique = MagicMock()
        technique.technique_id = "D3-AL"
        technique.name = "Application Lockdown"
        technique.description = "A" * 250  # Long description
        technique.tactic_id = "D3-HARDEN"
        technique.deprecated = False
        technique.badge_url = "https://d3fend.mitre.org/technique/D3-AL/"

        result = _technique_to_dict(technique)

        assert result["technique_id"] == "D3-AL"
        assert result["name"] == "Application Lockdown"
        assert len(result["description"]) <= 203  # 200 + "..."
        assert result["tactic_id"] == "D3-HARDEN"
        assert result["deprecated"] is False
        assert result["badge_url"] == "https://d3fend.mitre.org/technique/D3-AL/"

    def test_technique_to_dict_full(self):
        """_technique_to_dict returns full dict when include_full=True."""
        from cve_mcp.services.d3fend_queries import _technique_to_dict

        # Create mock technique with all fields
        technique = MagicMock()
        technique.technique_id = "D3-AL"
        technique.name = "Application Lockdown"
        technique.description = "Full description here"
        technique.tactic_id = "D3-HARDEN"
        technique.parent_id = None
        technique.synonyms = ["App Lock", "AppLocker"]
        technique.references = [{"title": "Ref1", "url": "http://example.com"}]
        technique.kb_article_url = "https://d3fend.mitre.org/kb/D3-AL"
        technique.d3fend_version = "0.15.0"
        technique.deprecated = False
        technique.created = datetime(2023, 1, 1)
        technique.modified = datetime(2023, 6, 1)
        technique.embedding = [0.1] * 1536
        technique.badge_url = "https://d3fend.mitre.org/technique/D3-AL/"

        result = _technique_to_dict(technique, include_full=True)

        assert result["technique_id"] == "D3-AL"
        assert result["description"] == "Full description here"  # Not truncated
        assert result["synonyms"] == ["App Lock", "AppLocker"]
        assert result["references"] == [{"title": "Ref1", "url": "http://example.com"}]
        assert result["kb_article_url"] == "https://d3fend.mitre.org/kb/D3-AL"
        assert result["embedding_generated"] is True


@pytest.mark.asyncio
class TestSearchDefenses:
    """Test search_defenses query function."""

    async def test_search_defenses_basic(self):
        """search_defenses returns techniques matching keyword with total count."""
        from cve_mcp.services.d3fend_queries import search_defenses

        # Mock session
        session = AsyncMock()
        mock_technique = MagicMock()
        mock_technique.technique_id = "D3-AL"
        mock_technique.name = "Application Lockdown"
        mock_technique.description = "Restricting execution of applications"
        mock_technique.tactic_id = "D3-HARDEN"
        mock_technique.deprecated = False
        mock_technique.badge_url = "https://d3fend.mitre.org/technique/D3-AL/"

        # Setup mock execute - first call for count, second for results
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 1
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_technique]
        session.execute.side_effect = [mock_count_result, mock_result]

        results, total_count = await search_defenses(session, query="application")

        assert isinstance(results, list)
        assert isinstance(total_count, int)
        assert total_count == 1
        session.execute.assert_called()

    async def test_search_defenses_with_tactic_filter(self):
        """search_defenses filters by tactic and returns total count."""
        from cve_mcp.services.d3fend_queries import search_defenses

        session = AsyncMock()
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.side_effect = [mock_count_result, mock_result]

        results, total_count = await search_defenses(
            session, query="hardening", tactic=["Harden", "Detect"]
        )

        assert isinstance(results, list)
        assert isinstance(total_count, int)
        session.execute.assert_called()

    async def test_search_defenses_with_children(self):
        """search_defenses includes children when requested and returns total count."""
        from cve_mcp.services.d3fend_queries import search_defenses

        session = AsyncMock()

        # Parent technique with children
        parent = MagicMock()
        parent.technique_id = "D3-AL"
        parent.name = "Application Lockdown"
        parent.description = "Parent technique"
        parent.tactic_id = "D3-HARDEN"
        parent.deprecated = False
        parent.badge_url = "https://d3fend.mitre.org/technique/D3-AL/"
        parent.children = []

        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 1
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [parent]
        session.execute.side_effect = [mock_count_result, mock_result]

        results, total_count = await search_defenses(
            session, query="application", include_children=True
        )

        assert isinstance(results, list)
        assert isinstance(total_count, int)


@pytest.mark.asyncio
class TestFindSimilarDefenses:
    """Test find_similar_defenses semantic search function."""

    @patch("cve_mcp.services.d3fend_queries.generate_embedding")
    async def test_find_similar_defenses_basic(self, mock_embed):
        """find_similar_defenses returns similar techniques with scores."""
        from cve_mcp.services.d3fend_queries import find_similar_defenses

        # Mock embedding generation
        mock_embed.return_value = [0.1] * 1536

        session = AsyncMock()

        # Mock technique with similarity score
        mock_technique = MagicMock()
        mock_technique.technique_id = "D3-NI"
        mock_technique.name = "Network Isolation"
        mock_technique.description = "Isolating network segments"
        mock_technique.tactic_id = "D3-ISOLATE"
        mock_technique.deprecated = False
        mock_technique.badge_url = "https://d3fend.mitre.org/technique/D3-NI/"

        mock_result = MagicMock()
        mock_result.all.return_value = [(mock_technique, 0.85)]
        session.execute.return_value = mock_result

        results = await find_similar_defenses(
            session, description="network segmentation for defense"
        )

        assert isinstance(results, list)
        mock_embed.assert_called_once_with("network segmentation for defense")

    @patch("cve_mcp.services.d3fend_queries.generate_embedding")
    async def test_find_similar_defenses_with_min_similarity(self, mock_embed):
        """find_similar_defenses respects min_similarity threshold."""
        from cve_mcp.services.d3fend_queries import find_similar_defenses

        mock_embed.return_value = [0.1] * 1536

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        session.execute.return_value = mock_result

        results = await find_similar_defenses(
            session,
            description="test description",
            min_similarity=0.9,  # High threshold
        )

        assert isinstance(results, list)


@pytest.mark.asyncio
class TestGetDefenseDetails:
    """Test get_defense_details query function."""

    async def test_get_defense_details_found(self):
        """get_defense_details returns full technique with ATT&CK mappings."""
        from cve_mcp.services.d3fend_queries import get_defense_details

        session = AsyncMock()

        # Mock technique
        mock_technique = MagicMock()
        mock_technique.technique_id = "D3-AL"
        mock_technique.name = "Application Lockdown"
        mock_technique.description = "Full technique description"
        mock_technique.tactic_id = "D3-HARDEN"
        mock_technique.parent_id = None
        mock_technique.synonyms = ["AppLocker"]
        mock_technique.references = []
        mock_technique.kb_article_url = "https://d3fend.mitre.org/kb/D3-AL"
        mock_technique.d3fend_version = "0.15.0"
        mock_technique.deprecated = False
        mock_technique.created = datetime(2023, 1, 1)
        mock_technique.modified = datetime(2023, 6, 1)
        mock_technique.embedding = [0.1] * 1536
        mock_technique.badge_url = "https://d3fend.mitre.org/technique/D3-AL/"

        # Mock tactic
        mock_tactic = MagicMock()
        mock_tactic.name = "Harden"
        mock_technique.tactic = mock_tactic

        # Mock attack mappings
        mock_mapping = MagicMock()
        mock_mapping.attack_technique_id = "T1059"
        mock_mapping.relationship_type = D3FENDRelationshipType.COUNTERS
        mock_technique.attack_mappings = [mock_mapping]

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_technique
        session.execute.return_value = mock_result

        result = await get_defense_details(session, technique_id="D3-AL")

        assert result is not None
        assert result["technique_id"] == "D3-AL"
        assert "attack_mappings" in result

    async def test_get_defense_details_not_found(self):
        """get_defense_details returns None for unknown technique."""
        from cve_mcp.services.d3fend_queries import get_defense_details

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        result = await get_defense_details(session, technique_id="D3-UNKNOWN")

        assert result is None


@pytest.mark.asyncio
class TestGetDefensesForAttack:
    """Test get_defenses_for_attack query function."""

    async def test_get_defenses_for_attack_basic(self):
        """get_defenses_for_attack finds defenses for ATT&CK technique."""
        from cve_mcp.services.d3fend_queries import get_defenses_for_attack

        session = AsyncMock()

        # Mock defense technique
        mock_technique = MagicMock()
        mock_technique.technique_id = "D3-AL"
        mock_technique.name = "Application Lockdown"
        mock_technique.description = "Restricting execution"
        mock_technique.tactic_id = "D3-HARDEN"
        mock_technique.deprecated = False
        mock_technique.badge_url = "https://d3fend.mitre.org/technique/D3-AL/"

        # Mock mapping
        mock_mapping = MagicMock()
        mock_mapping.d3fend_technique = mock_technique
        mock_mapping.relationship_type = D3FENDRelationshipType.COUNTERS

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_mapping]
        session.execute.return_value = mock_result

        results = await get_defenses_for_attack(session, attack_technique_id="T1059")

        assert isinstance(results, list)

    async def test_get_defenses_for_attack_with_subtechniques(self):
        """get_defenses_for_attack includes subtechniques when requested."""
        from cve_mcp.services.d3fend_queries import get_defenses_for_attack

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.return_value = mock_result

        results = await get_defenses_for_attack(
            session,
            attack_technique_id="T1059",
            include_subtechniques=True,  # Should also check T1059.001, T1059.002, etc.
        )

        assert isinstance(results, list)

    async def test_get_defenses_for_attack_filter_relationship(self):
        """get_defenses_for_attack filters by relationship type."""
        from cve_mcp.services.d3fend_queries import get_defenses_for_attack

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.return_value = mock_result

        results = await get_defenses_for_attack(
            session,
            attack_technique_id="T1059",
            relationship_type=["counters"],
        )

        assert isinstance(results, list)


@pytest.mark.asyncio
class TestGetAttackCoverage:
    """Test get_attack_coverage query function."""

    async def test_get_attack_coverage_basic(self):
        """get_attack_coverage returns coverage analysis."""
        from cve_mcp.services.d3fend_queries import get_attack_coverage

        session = AsyncMock()

        # Mock technique with attack mappings
        mock_technique = MagicMock()
        mock_technique.technique_id = "D3-AL"
        mock_technique.attack_mappings = []

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_technique]
        session.execute.return_value = mock_result

        result = await get_attack_coverage(session, technique_ids=["D3-AL", "D3-NI"])

        assert "covered_techniques" in result
        assert "coverage_details" in result
        assert "total_covered" in result
        assert "coverage_percentage" in result

    async def test_get_attack_coverage_with_gaps(self):
        """get_attack_coverage shows gaps when requested."""
        from cve_mcp.services.d3fend_queries import get_attack_coverage

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.return_value = mock_result

        result = await get_attack_coverage(session, technique_ids=["D3-AL"], show_gaps=True)

        assert "gaps" in result
        assert "total_gaps" in result

    async def test_get_attack_coverage_empty_input(self):
        """get_attack_coverage handles empty input gracefully."""
        from cve_mcp.services.d3fend_queries import get_attack_coverage

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.return_value = mock_result

        result = await get_attack_coverage(session, technique_ids=[])

        assert result["total_covered"] == 0
        assert result["coverage_percentage"] == 0.0
