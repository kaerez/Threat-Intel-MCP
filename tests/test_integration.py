"""Integration tests for CVE MCP server.

Tests actual MCP protocol, database queries, and end-to-end flows.
Focuses on useful integration points, not trivial schema validation.
"""

import pytest
from httpx import AsyncClient

from cve_mcp.api.app import create_app
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.models.cve import CVE
from cve_mcp.services.database import DatabaseService


@pytest.fixture
def app():
    """Create FastAPI test app."""
    return create_app()


@pytest.fixture
async def client(app):
    """Create async HTTP test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


class TestMCPProtocol:
    """Test MCP protocol compliance."""

    async def test_health_endpoint(self, client):
        """Health check returns valid response."""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert "database" in data
        assert "cache" in data

    async def test_tools_list(self, client):
        """MCP tools list returns all 8 tools."""
        response = await client.get("/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data
        tools = data["tools"]
        assert len(tools) == 8

        tool_names = {tool["name"] for tool in tools}
        expected_tools = {
            "search_cve",
            "get_cve_details",
            "check_kev_status",
            "get_epss_score",
            "search_by_product",
            "get_exploits",
            "get_cwe_details",
            "batch_search",
        }
        assert tool_names == expected_tools

        # Verify each tool has required MCP fields
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool
            assert tool["inputSchema"]["type"] == "object"

    async def test_tool_call_search_cve(self, client):
        """MCP tool call executes and returns valid response."""
        response = await client.post(
            "/call",
            json={
                "name": "search_cve",
                "arguments": {"keyword": "apache", "cvss_min": 7.0, "limit": 5},
            },
        )
        assert response.status_code == 200
        data = response.json()

        # MCP protocol fields
        assert "content" in data
        assert isinstance(data["content"], list)
        assert "isError" in data
        assert data["isError"] is False

    async def test_tool_call_invalid_tool(self, client):
        """Invalid tool name returns error."""
        response = await client.post("/call", json={"name": "nonexistent_tool", "arguments": {}})
        assert response.status_code == 400

    async def test_tool_call_invalid_arguments(self, client):
        """Invalid arguments return validation error."""
        response = await client.post(
            "/call",
            json={
                "name": "search_cve",
                "arguments": {
                    "cvss_min": 15.0,  # Invalid: max is 10
                },
            },
        )
        assert response.status_code in [400, 422]


class TestDatabaseIntegration:
    """Test database queries work end-to-end."""

    async def test_database_connection(self):
        """Database connection works."""
        async with AsyncSessionLocal() as session:
            # Simple query to verify connection
            from sqlalchemy import text

            result = await session.execute(text("SELECT 1"))
            assert result.scalar() == 1

    async def test_search_cve_database_query(self):
        """Search CVE executes database query."""
        db_service = DatabaseService()
        async with AsyncSessionLocal() as session:
            # Search for CVEs (may return 0 if no data synced yet)
            cves, total = await db_service.search_cve(
                session, keyword="test", cvss_min=0.0, limit=10
            )
            assert isinstance(cves, list)
            assert isinstance(total, int)
            assert total >= 0

    async def test_get_cve_details_not_found(self):
        """Get CVE details handles non-existent CVE."""
        db_service = DatabaseService()
        async with AsyncSessionLocal() as session:
            cve = await db_service.get_cve_details(session, "CVE-9999-99999")
            assert cve is None

    async def test_search_by_product_database_query(self):
        """Search by product executes database query."""
        db_service = DatabaseService()
        async with AsyncSessionLocal() as session:
            cves, total = await db_service.search_by_product(
                session, product_name="test_product", limit=10
            )
            assert isinstance(cves, list)
            assert isinstance(total, int)
            assert total >= 0


class TestVersionComparison:
    """Test critical version comparison logic."""

    def test_version_eq(self):
        """Equal version comparison works."""
        db_service = DatabaseService()
        assert db_service._compare_versions("2.4.49", "2.4.49", "eq") is True
        assert db_service._compare_versions("2.4.48", "2.4.49", "eq") is False

    def test_version_lt(self):
        """Less than version comparison works."""
        db_service = DatabaseService()
        assert db_service._compare_versions("2.4.48", "2.4.49", "lt") is True
        assert db_service._compare_versions("2.4.49", "2.4.49", "lt") is False
        assert db_service._compare_versions("2.4.50", "2.4.49", "lt") is False

    def test_version_lte(self):
        """Less than or equal version comparison works."""
        db_service = DatabaseService()
        assert db_service._compare_versions("2.4.48", "2.4.49", "lte") is True
        assert db_service._compare_versions("2.4.49", "2.4.49", "lte") is True
        assert db_service._compare_versions("2.4.50", "2.4.49", "lte") is False

    def test_version_gt(self):
        """Greater than version comparison works."""
        db_service = DatabaseService()
        assert db_service._compare_versions("2.4.50", "2.4.49", "gt") is True
        assert db_service._compare_versions("2.4.49", "2.4.49", "gt") is False
        assert db_service._compare_versions("2.4.48", "2.4.49", "gt") is False

    def test_version_gte(self):
        """Greater than or equal version comparison works."""
        db_service = DatabaseService()
        assert db_service._compare_versions("2.4.50", "2.4.49", "gte") is True
        assert db_service._compare_versions("2.4.49", "2.4.49", "gte") is True
        assert db_service._compare_versions("2.4.48", "2.4.49", "gte") is False

    def test_version_semantic_ordering(self):
        """Semantic version ordering works correctly."""
        db_service = DatabaseService()
        # 2.4.9 < 2.4.10 (semantic, not string comparison)
        assert db_service._compare_versions("2.4.9", "2.4.10", "lt") is True
        assert db_service._compare_versions("2.4.10", "2.4.9", "gt") is True

    def test_version_none_handling(self):
        """None/empty versions handled correctly."""
        db_service = DatabaseService()
        assert db_service._compare_versions(None, "2.4.49", "eq") is False
        assert db_service._compare_versions("", "2.4.49", "eq") is False

    def test_version_invalid_format_fallback(self):
        """Invalid version formats fall back to string comparison."""
        db_service = DatabaseService()
        # Non-semantic versions should still work with eq
        assert db_service._compare_versions("custom-v1", "custom-v1", "eq") is True
        assert db_service._compare_versions("custom-v1", "custom-v2", "eq") is False


class TestCacheIntegration:
    """Test Redis cache integration."""

    async def test_cache_connection(self):
        """Redis cache connects."""
        from cve_mcp.services.cache import cache_service

        # Cache service should be connected by app lifespan
        assert cache_service.redis is not None

    async def test_cache_set_get(self):
        """Cache set and get work."""
        from cve_mcp.services.cache import cache_service

        test_data = {"test": "value", "number": 123}
        await cache_service.set_cve("TEST-CVE-001", test_data)
        cached = await cache_service.get_cve("TEST-CVE-001")
        assert cached is not None
        assert cached["test"] == "value"
        assert cached["number"] == 123


class TestEndToEndFlows:
    """Test complete user workflows."""

    async def test_search_workflow(self, client):
        """Complete search workflow executes."""
        # 1. Search for CVEs
        response = await client.post(
            "/call",
            json={
                "name": "search_cve",
                "arguments": {"keyword": "authentication", "limit": 3},
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["isError"] is False

    async def test_product_search_workflow(self, client):
        """Product vulnerability search workflow."""
        response = await client.post(
            "/call",
            json={
                "name": "search_by_product",
                "arguments": {
                    "product_name": "apache",
                    "vendor": "apache",
                    "version": "2.4.49",
                    "version_operator": "eq",
                    "limit": 5,
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["isError"] is False

    async def test_batch_search_workflow(self, client):
        """Batch CVE lookup workflow."""
        response = await client.post(
            "/call",
            json={
                "name": "batch_search",
                "arguments": {
                    "cve_ids": ["CVE-2021-44228", "CVE-2024-1234"],
                    "include_kev": True,
                    "include_epss": True,
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["isError"] is False


class TestPerformance:
    """Test performance requirements."""

    async def test_search_query_latency(self, client):
        """Search queries complete within performance target."""
        import time

        start = time.time()
        response = await client.post(
            "/call",
            json={"name": "search_cve", "arguments": {"keyword": "apache", "limit": 10}},
        )
        elapsed_ms = (time.time() - start) * 1000

        assert response.status_code == 200
        # Target: < 100ms for search queries
        # Allow higher in test environment (no optimizations)
        assert elapsed_ms < 1000  # 1 second max in test

    async def test_batch_query_latency(self, client):
        """Batch queries complete within performance target."""
        import time

        start = time.time()
        response = await client.post(
            "/call",
            json={
                "name": "batch_search",
                "arguments": {
                    "cve_ids": [f"CVE-2024-{i:05d}" for i in range(50)],
                },
            },
        )
        elapsed_ms = (time.time() - start) * 1000

        assert response.status_code == 200
        # Target: < 500ms for 100 CVEs
        # 50 CVEs should be faster
        assert elapsed_ms < 2000  # 2 seconds max in test
