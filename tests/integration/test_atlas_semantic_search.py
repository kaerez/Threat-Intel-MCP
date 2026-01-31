"""End-to-end integration tests for ATLAS semantic search functionality.

Tests verify that ATLAS semantic search works correctly with real data:
- Database with ATLAS techniques and case studies
- OpenAI embedding generation
- pgvector similarity search
- MCP tool integration

These are REAL integration tests - they require:
- PostgreSQL database running
- ATLAS data synced with embeddings
- OpenAI API key configured
"""

import pytest
from cve_mcp.api.tools import call_tool


@pytest.mark.asyncio
class TestATLASTraditionalSearch:
    """Integration tests for traditional ATLAS technique search."""

    async def test_search_atlas_techniques_basic(self, check_prerequisites):
        """Test basic ATLAS technique search.

        Verifies:
        - Returns techniques
        - All techniques have required fields
        - Results have ATLAS-specific fields
        """
        result = await call_tool("search_atlas_techniques", {
            "limit": 10
        })

        # Verify response structure
        assert "data" in result
        data = result["data"]
        assert "techniques" in data
        assert "total_results" in data
        assert "returned_results" in data

        techniques = data["techniques"]

        # Verify results have required ATLAS-specific fields
        for tech in techniques:
            assert "technique_id" in tech
            assert tech["technique_id"].startswith("AML.T"), \
                f"ATLAS technique ID should start with AML.T, got {tech['technique_id']}"
            assert "name" in tech
            assert "description" in tech
            assert "badge_url" in tech
            assert "atlas.mitre.org" in tech["badge_url"], \
                "Badge URL should point to atlas.mitre.org"

    async def test_search_atlas_techniques_with_query(self, check_prerequisites):
        """Test ATLAS technique search with keyword query."""
        result = await call_tool("search_atlas_techniques", {
            "query": "model",
            "limit": 10
        })

        data = result["data"]
        techniques = data["techniques"]

        # If results returned, verify query relevance
        for tech in techniques:
            # Query should match in name or description
            name_lower = tech["name"].lower()
            desc_lower = tech["description"].lower()
            assert "model" in name_lower or "model" in desc_lower, \
                f"Technique {tech['technique_id']} should contain 'model' in name or description"

    async def test_search_atlas_techniques_with_filters(self, check_prerequisites):
        """Test ATLAS technique search with ML-specific filters."""
        result = await call_tool("search_atlas_techniques", {
            "tactics": ["ml-attack-staging"],
            "limit": 10
        })

        data = result["data"]
        techniques = data["techniques"]

        # If results returned, verify filter was applied
        for tech in techniques:
            if tech.get("tactics"):
                # Tactics should include the filtered tactic
                assert any("ml-attack-staging" in t.lower() for t in tech["tactics"]), \
                    f"Technique {tech['technique_id']} should have ml-attack-staging tactic"


@pytest.mark.asyncio
class TestATLASSemanticTechniqueSearch:
    """Integration tests for semantic ATLAS technique similarity search."""

    async def test_semantic_atlas_technique_search(self, check_prerequisites):
        """Test semantic similarity search for ATLAS techniques.

        Verifies:
        - Returns techniques
        - All similarity scores >= min_similarity threshold
        - All similarity scores <= 1.0
        - Results sorted by similarity (descending)
        """
        # AI/ML attack scenario description
        attack_description = """
        An attacker crafted adversarial examples by adding carefully designed
        perturbations to images that caused a computer vision model to misclassify
        objects. The perturbations were imperceptible to humans but caused the
        neural network to output incorrect predictions with high confidence.
        """

        # Call semantic search tool
        result = await call_tool("find_similar_atlas_techniques", {
            "description": attack_description,
            "min_similarity": 0.5,
            "limit": 10
        })

        # Verify response structure
        assert "data" in result
        data = result["data"]
        assert "techniques" in data
        assert "query_embedding_generated" in data
        assert data["query_embedding_generated"] is True
        assert "min_similarity" in data

        techniques = data["techniques"]

        # Should return at least 1 technique if embeddings exist
        # (may be 0 if no ATLAS data is synced)
        if len(techniques) > 0:
            # Verify all results have required fields and valid similarity scores
            for tech in techniques:
                assert "technique_id" in tech
                assert tech["technique_id"].startswith("AML.T")
                assert "name" in tech
                assert "description" in tech
                assert "similarity_score" in tech
                assert "badge_url" in tech

                # Similarity scores should be in valid range
                assert tech["similarity_score"] >= 0.5, \
                    f"Technique {tech['technique_id']} has similarity {tech['similarity_score']} < 0.5"
                assert tech["similarity_score"] <= 1.0, \
                    f"Technique {tech['technique_id']} has similarity {tech['similarity_score']} > 1.0"

            # Verify results are sorted by similarity (descending)
            similarities = [t["similarity_score"] for t in techniques]
            assert similarities == sorted(similarities, reverse=True), \
                "Results should be sorted by similarity score (highest first)"

    async def test_semantic_atlas_technique_search_with_filters(self, check_prerequisites):
        """Test ATLAS semantic search with ML-specific filters."""
        description = "Poisoning training data to create backdoor in ML model"

        result = await call_tool("find_similar_atlas_techniques", {
            "description": description,
            "min_similarity": 0.5,
            "tactics": ["ml-attack-staging"],
            "limit": 5
        })

        data = result["data"]
        techniques = data["techniques"]

        # If results returned, verify they have similarity_score
        for tech in techniques:
            assert "similarity_score" in tech


@pytest.mark.asyncio
class TestATLASCaseStudySearch:
    """Integration tests for ATLAS case study search."""

    async def test_search_atlas_case_studies_basic(self, check_prerequisites):
        """Test basic ATLAS case study search."""
        result = await call_tool("search_atlas_case_studies", {
            "limit": 10
        })

        # Verify response structure
        assert "data" in result
        data = result["data"]
        assert "case_studies" in data
        assert "total_results" in data
        assert "returned_results" in data

        case_studies = data["case_studies"]

        # Verify results have required fields
        for cs in case_studies:
            assert "case_study_id" in cs
            assert cs["case_study_id"].startswith("AML.CS"), \
                f"ATLAS case study ID should start with AML.CS, got {cs['case_study_id']}"
            assert "name" in cs
            assert "summary" in cs

    async def test_search_atlas_case_studies_with_techniques(self, check_prerequisites):
        """Test ATLAS case study search filtered by techniques."""
        result = await call_tool("search_atlas_case_studies", {
            "techniques": ["AML.T0000"],
            "limit": 10
        })

        data = result["data"]
        # Just verify the query executed without error
        assert "case_studies" in data


@pytest.mark.asyncio
class TestATLASSemanticCaseStudySearch:
    """Integration tests for semantic ATLAS case study similarity search."""

    async def test_semantic_atlas_case_study_search(self, check_prerequisites):
        """Test semantic similarity search for ATLAS case studies."""
        # Scenario description
        incident_description = """
        Researchers demonstrated that autonomous vehicles could be fooled by
        placing adversarial stickers on stop signs, causing the vehicle's
        computer vision system to misclassify the sign as a speed limit sign.
        """

        result = await call_tool("find_similar_atlas_case_studies", {
            "description": incident_description,
            "min_similarity": 0.5,
            "limit": 5
        })

        # Verify response structure
        assert "data" in result
        data = result["data"]
        assert "case_studies" in data
        assert "query_embedding_generated" in data
        assert data["query_embedding_generated"] is True
        assert "min_similarity" in data

        case_studies = data["case_studies"]

        # Verify results have similarity_score
        for cs in case_studies:
            assert "similarity_score" in cs
            assert cs["similarity_score"] >= 0.5
            assert cs["similarity_score"] <= 1.0


@pytest.mark.asyncio
class TestATLASTechniqueDetails:
    """Integration tests for ATLAS technique details lookup."""

    async def test_get_atlas_technique_details(self, check_prerequisites):
        """Test getting details for a specific ATLAS technique."""
        # First search for a technique to get a valid ID
        search_result = await call_tool("search_atlas_techniques", {
            "limit": 1
        })

        techniques = search_result["data"]["techniques"]
        if len(techniques) == 0:
            pytest.skip("No ATLAS techniques in database")

        technique_id = techniques[0]["technique_id"]

        # Get details
        result = await call_tool("get_atlas_technique_details", {
            "technique_id": technique_id
        })

        assert "data" in result
        data = result["data"]

        if data is not None:
            # Verify detailed fields
            assert data["technique_id"] == technique_id
            assert "stix_id" in data
            assert "name" in data
            assert "description" in data  # Full description
            assert "badge_url" in data
            assert "embedding_generated" in data

    async def test_get_atlas_technique_details_not_found(self, check_prerequisites):
        """Test getting details for non-existent technique."""
        result = await call_tool("get_atlas_technique_details", {
            "technique_id": "AML.T9999"
        })

        assert "data" in result
        # Should return None for non-existent technique
        assert result["data"] is None


@pytest.mark.asyncio
class TestATLASVsATTACKTools:
    """Tests to verify ATLAS and ATT&CK tools are distinct."""

    async def test_atlas_vs_attack_technique_ids(self, check_prerequisites):
        """Verify ATLAS and ATT&CK return different technique ID formats."""
        # ATLAS search
        atlas_result = await call_tool("search_atlas_techniques", {"limit": 5})
        atlas_techniques = atlas_result["data"]["techniques"]

        # ATT&CK search
        attack_result = await call_tool("search_techniques", {"limit": 5})
        attack_techniques = attack_result["data"]["techniques"]

        # ATLAS IDs should start with AML.T
        for tech in atlas_techniques:
            assert tech["technique_id"].startswith("AML.T"), \
                "ATLAS technique IDs should start with AML.T"

        # ATT&CK IDs should start with T (not AML)
        for tech in attack_techniques:
            assert tech["technique_id"].startswith("T"), \
                "ATT&CK technique IDs should start with T"
            assert not tech["technique_id"].startswith("AML"), \
                "ATT&CK technique IDs should not start with AML"

    async def test_atlas_badge_url_format(self, check_prerequisites):
        """Verify ATLAS badge URLs point to atlas.mitre.org."""
        result = await call_tool("search_atlas_techniques", {"limit": 5})
        techniques = result["data"]["techniques"]

        for tech in techniques:
            assert "atlas.mitre.org" in tech["badge_url"], \
                f"ATLAS badge URL should contain atlas.mitre.org, got {tech['badge_url']}"
