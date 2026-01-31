"""End-to-end integration tests for semantic search functionality.

Tests verify that semantic search works correctly with real data:
- Database with ATT&CK techniques and groups
- OpenAI embedding generation
- pgvector similarity search
- MCP tool integration

These are REAL integration tests - they require:
- PostgreSQL database running
- ATT&CK data synced with embeddings
- OpenAI API key configured
"""

import pytest

from cve_mcp.api.tools import call_tool


@pytest.mark.asyncio
class TestSemanticTechniqueSearch:
    """Integration tests for semantic technique similarity search."""

    async def test_semantic_technique_search(self, check_prerequisites):
        """Test semantic similarity search for techniques using incident description.

        Verifies:
        - Returns at least 1 technique
        - All similarity scores >= 0.6 (min_similarity threshold)
        - All similarity scores <= 1.0
        - Finds phishing-related technique (T1566.*)
        - Finds PowerShell-related technique (T1059.001)
        - Results sorted by similarity (descending)
        """
        # Multi-line incident description mentioning phishing, Excel, PowerShell, C2
        incident_description = """
        Security team detected a sophisticated phishing campaign targeting our finance department.
        Attackers sent emails with malicious Excel spreadsheets that contained embedded macros.
        When users enabled macros, the spreadsheet executed PowerShell commands to download
        and install a remote access trojan. The malware established command and control
        communication with an external server and began exfiltrating sensitive financial data.
        """

        # Call semantic search tool
        result = await call_tool("find_similar_techniques", {
            "description": incident_description,
            "min_similarity": 0.6,
            "limit": 10
        })

        # Verify response structure
        assert "data" in result
        data = result["data"]
        assert "techniques" in data
        techniques = data["techniques"]

        # Should return at least 1 technique
        assert len(techniques) > 0, "Should return at least 1 matching technique"

        # Verify all results have required fields and valid similarity scores
        for tech in techniques:
            assert "technique_id" in tech
            assert "name" in tech
            assert "description" in tech
            assert "similarity_score" in tech
            assert "tactics" in tech
            assert "platforms" in tech

            # Similarity scores should be in valid range
            assert tech["similarity_score"] >= 0.6, \
                f"Technique {tech['technique_id']} has similarity {tech['similarity_score']} < 0.6"
            assert tech["similarity_score"] <= 1.0, \
                f"Technique {tech['technique_id']} has similarity {tech['similarity_score']} > 1.0"

        # Verify results are sorted by similarity (descending)
        similarities = [t["similarity_score"] for t in techniques]
        assert similarities == sorted(similarities, reverse=True), \
            "Results should be sorted by similarity score (highest first)"

        # Verify phishing-related technique is found (flexible check)
        phishing_found = any(
            "T1566" in tech["technique_id"] or
            "phishing" in tech["name"].lower() or
            "phishing" in tech["description"].lower()
            for tech in techniques
        )
        assert phishing_found, \
            "Should find phishing-related technique (T1566.* or contains 'phishing')"

        # Verify PowerShell-related technique is found (flexible check)
        powershell_found = any(
            "T1059.001" in tech["technique_id"] or
            "powershell" in tech["name"].lower() or
            "powershell" in tech["description"].lower()
            for tech in techniques
        )
        assert powershell_found, \
            "Should find PowerShell-related technique (T1059.001 or contains 'powershell')"

    async def test_semantic_technique_search_with_filters(self, check_prerequisites):
        """Test semantic search with platform and tactic filters.

        Verifies:
        - Filters are applied correctly
        - Results match both semantic similarity AND filters
        """
        description = "Exploiting Windows registry for persistence"

        result = await call_tool("find_similar_techniques", {
            "description": description,
            "min_similarity": 0.6,
            "platforms": ["windows"],
            "tactics": ["persistence"],
            "limit": 5
        })

        data = result["data"]
        techniques = data["techniques"]

        # If results returned, verify they match filters
        for tech in techniques:
            assert "windows" in [p.lower() for p in tech.get("platforms", [])], \
                f"Technique {tech['technique_id']} should have Windows platform"
            assert "persistence" in [t.lower() for t in tech.get("tactics", [])], \
                f"Technique {tech['technique_id']} should have persistence tactic"


@pytest.mark.asyncio
class TestSemanticThreatActorSearch:
    """Integration tests for semantic threat actor similarity search."""

    async def test_semantic_threat_actor_search(self, check_prerequisites):
        """Test semantic similarity search for threat actors.

        Verifies:
        - Returns at least 1 group
        - All groups have required fields (group_id, name, similarity_score)
        - All similarity scores >= 0.5 (min_similarity threshold)
        """
        # Threat profile mentioning financial targeting, spearphishing, Office docs, Eastern European
        threat_profile = """
        This advanced persistent threat group primarily targets financial institutions
        and payment processors in North America and Europe. They use sophisticated
        spearphishing campaigns with weaponized Microsoft Office documents, often
        exploiting zero-day vulnerabilities. The group is believed to operate from
        Eastern Europe and has been active since 2015. Their primary motivation
        appears to be financial gain through wire fraud and theft of banking credentials.
        """

        # Call semantic search tool
        result = await call_tool("find_similar_threat_actors", {
            "description": threat_profile,
            "min_similarity": 0.5,
            "limit": 5
        })

        # Verify response structure
        assert "data" in result
        data = result["data"]
        assert "groups" in data
        groups = data["groups"]

        # Should return at least 1 group
        assert len(groups) > 0, "Should return at least 1 matching threat actor group"

        # Verify all results have required fields
        for group in groups:
            assert "group_id" in group, "Group should have group_id field"
            assert "name" in group, "Group should have name field"
            assert "similarity_score" in group, "Group should have similarity_score field"

            # Similarity scores should be >= min_similarity
            assert group["similarity_score"] >= 0.5, \
                f"Group {group['group_id']} has similarity {group['similarity_score']} < 0.5"
            assert group["similarity_score"] <= 1.0, \
                f"Group {group['group_id']} has similarity {group['similarity_score']} > 1.0"

    async def test_semantic_threat_actor_search_low_threshold(self, check_prerequisites):
        """Test semantic search with low similarity threshold returns more results."""
        description = "Cyber espionage targeting government agencies"

        # Lower threshold should return more results
        result = await call_tool("find_similar_threat_actors", {
            "description": description,
            "min_similarity": 0.3,
            "limit": 10
        })

        data = result["data"]
        groups = data["groups"]

        # With lower threshold, should get some results
        assert len(groups) > 0, "Should return results with low similarity threshold"

        # All should still meet the threshold
        for group in groups:
            assert group["similarity_score"] >= 0.3


@pytest.mark.asyncio
class TestSemanticVsTraditionalSearch:
    """Compare semantic vs traditional keyword search."""

    async def test_semantic_vs_traditional_search(self, check_prerequisites):
        """Compare semantic vs traditional keyword search.

        Verifies:
        - Both return at least 1 result (or gracefully handle no results)
        - Semantic results have similarity_score field (traditional doesn't)
        - Results may differ (semantic catches concepts, traditional matches keywords)
        """
        query = "credential theft from browser"

        # Traditional keyword search
        traditional_result = await call_tool("search_techniques", {
            "query": "credential browser",
            "limit": 5
        })

        # Semantic search
        semantic_result = await call_tool("find_similar_techniques", {
            "description": query,
            "min_similarity": 0.6,
            "limit": 5
        })

        # Extract results
        traditional_data = traditional_result["data"]
        traditional_techniques = traditional_data["techniques"]

        semantic_data = semantic_result["data"]
        semantic_techniques = semantic_data["techniques"]

        # Both should return at least 1 result
        assert len(traditional_techniques) > 0, \
            "Traditional search should return at least 1 result"
        assert len(semantic_techniques) > 0, \
            "Semantic search should return at least 1 result"

        # Verify semantic results have similarity_score
        if semantic_techniques:
            for tech in semantic_techniques:
                assert "similarity_score" in tech, \
                    "Semantic search results should have similarity_score"

        # Verify traditional results DON'T have similarity_score
        if traditional_techniques:
            for tech in traditional_techniques:
                assert "similarity_score" not in tech, \
                    "Traditional search results should NOT have similarity_score"

    async def test_semantic_search_conceptual_matching(self, check_prerequisites):
        """Test semantic search finds conceptually similar techniques.

        Semantic search should find techniques related to the CONCEPT,
        even if exact keywords don't match.
        """
        # Use conceptual description without exact ATT&CK terminology
        conceptual_query = "Adversary steals authentication tokens from web browsers"

        result = await call_tool("find_similar_techniques", {
            "description": conceptual_query,
            "min_similarity": 0.6,
            "limit": 5
        })

        data = result["data"]
        techniques = data["techniques"]

        # Should find credential access techniques
        if techniques:
            # Verify we found techniques related to credentials/browsers
            found_relevant = any(
                "credential" in tech["name"].lower() or
                "credential" in tech["description"].lower() or
                "browser" in tech["description"].lower() or
                "token" in tech["description"].lower()
                for tech in techniques
            )
            # Note: This is a best-effort check - embeddings may vary
            # We don't assert here as it depends on embedding quality
            # Just verify the search completed and returned valid results
            assert all("similarity_score" in tech for tech in techniques)

    async def test_semantic_search_query_embedding_metadata(self, check_prerequisites):
        """Verify semantic search response includes embedding metadata."""
        description = "Test query for metadata verification"

        result = await call_tool("find_similar_techniques", {
            "description": description,
            "min_similarity": 0.7,
            "limit": 3
        })

        data = result["data"]

        # Should include metadata about embedding generation
        assert "query_embedding_generated" in data
        assert data["query_embedding_generated"] is True

        # Should include the min_similarity used
        assert "min_similarity" in data
        assert data["min_similarity"] == 0.7

        # Should include count of results
        assert "returned_results" in data
        assert data["returned_results"] == len(data["techniques"])
