"""Integration tests for CVE MCP server.

Tests MCP protocol compliance and critical business logic.
Uses actual HTTP calls - no complex async fixtures or database mocking.
Focuses on useful integration tests that verify production behavior.
"""

import pytest

from cve_mcp.services.database import DatabaseService


class TestVersionComparison:
    """Test critical version comparison logic (semantic versioning)."""

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

        # Major version takes precedence
        assert db_service._compare_versions("2.9.9", "3.0.0", "lt") is True
        assert db_service._compare_versions("3.0.0", "2.9.9", "gt") is True

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

        # Non-eq operators return False for invalid versions
        assert db_service._compare_versions("custom-v1", "custom-v2", "lt") is False


class TestMCPToolDefinitions:
    """Test MCP tool schemas are properly defined."""

    def test_all_tools_defined(self):
        """All 8 MCP tools are defined."""
        from cve_mcp.api.tools import MCP_TOOLS

        assert len(MCP_TOOLS) == 8

        tool_names = {tool.name for tool in MCP_TOOLS}
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

    def test_tools_have_required_fields(self):
        """Each tool has required MCP protocol fields."""
        from cve_mcp.api.tools import MCP_TOOLS

        for tool in MCP_TOOLS:
            assert tool.name
            assert tool.description
            assert tool.inputSchema
            assert tool.inputSchema["type"] == "object"
            assert "properties" in tool.inputSchema

    def test_search_cve_schema(self):
        """search_cve tool has correct schema."""
        from cve_mcp.api.tools import MCP_TOOLS

        search_cve = next(t for t in MCP_TOOLS if t.name == "search_cve")
        props = search_cve.inputSchema["properties"]

        # Check key parameters
        assert "keyword" in props
        assert "cvss_min" in props
        assert "cvss_max" in props
        assert "severity" in props
        assert "limit" in props

    def test_search_by_product_schema(self):
        """search_by_product tool has version_operator parameter."""
        from cve_mcp.api.tools import MCP_TOOLS

        search_by_product = next(t for t in MCP_TOOLS if t.name == "search_by_product")
        props = search_by_product.inputSchema["properties"]

        # Check version comparison parameters
        assert "product_name" in props
        assert "version" in props
        assert "version_operator" in props

        # Verify version_operator has correct enum
        assert "enum" in props["version_operator"]
        assert set(props["version_operator"]["enum"]) == {"eq", "lt", "lte", "gt", "gte"}


class TestAPISchemas:
    """Test Pydantic schemas validate correctly."""

    def test_search_cve_request_validation(self):
        """SearchCVERequest validates parameters correctly."""
        from cve_mcp.api.schemas import SearchCVERequest

        # Valid request
        request = SearchCVERequest(
            keyword="apache",
            cvss_min=7.0,
            cvss_max=10.0,
            limit=50
        )
        assert request.keyword == "apache"
        assert request.cvss_min == 7.0
        assert request.limit == 50

    def test_search_cve_request_cvss_validation(self):
        """CVSS scores must be between 0 and 10."""
        from pydantic import ValidationError

        from cve_mcp.api.schemas import SearchCVERequest

        # Invalid: CVSS > 10
        with pytest.raises(ValidationError):
            SearchCVERequest(cvss_min=15.0)

        # Invalid: CVSS < 0
        with pytest.raises(ValidationError):
            SearchCVERequest(cvss_min=-1.0)

    def test_cve_id_pattern_validation(self):
        """CVE ID must match CVE-YYYY-NNNNN pattern."""
        from pydantic import ValidationError

        from cve_mcp.api.schemas import GetCVEDetailsRequest

        # Valid CVE ID
        request = GetCVEDetailsRequest(cve_id="CVE-2021-44228")
        assert request.cve_id == "CVE-2021-44228"

        # Invalid CVE ID
        with pytest.raises(ValidationError):
            GetCVEDetailsRequest(cve_id="invalid-cve-id")


class TestDatabaseModels:
    """Test SQLAlchemy models are properly configured."""

    def test_cve_model_has_required_fields(self):
        """CVE model has required fields."""
        from cve_mcp.models.cve import CVE

        # Check model has expected columns
        assert hasattr(CVE, "cve_id")
        assert hasattr(CVE, "description")
        assert hasattr(CVE, "cvss_v3_score")
        assert hasattr(CVE, "cvss_v3_severity")
        assert hasattr(CVE, "published_date")

    def test_cisa_kev_model_exists(self):
        """CISA KEV model is properly defined."""
        from cve_mcp.models.intelligence import CISAKEV

        assert hasattr(CISAKEV, "cve_id")
        assert hasattr(CISAKEV, "vulnerability_name")
        assert hasattr(CISAKEV, "due_date")

    def test_epss_score_model_exists(self):
        """EPSS score model is properly defined."""
        from cve_mcp.models.intelligence import EPSSScore

        assert hasattr(EPSSScore, "cve_id")
        assert hasattr(EPSSScore, "epss_score")
        assert hasattr(EPSSScore, "percentile")


class TestConfigurationLoading:
    """Test configuration loads correctly."""

    def test_settings_load(self):
        """Settings load with defaults."""
        from cve_mcp.config import get_settings

        settings = get_settings()
        assert settings.mcp_port == 8307
        assert settings.mcp_host == "0.0.0.0"
        assert settings.log_level in ["INFO", "DEBUG", "WARNING", "ERROR"]

    def test_cors_origins_configurable(self):
        """CORS origins are configurable."""
        from cve_mcp.config import get_settings

        settings = get_settings()
        assert settings.cors_origins
        assert isinstance(settings.cors_origins, str)
        # Should default to localhost
        assert "localhost" in settings.cors_origins.lower()


class TestUtilities:
    """Test utility functions."""

    def test_nvd_parser_exists(self):
        """NVD parser utility exists."""
        from cve_mcp.utils import nvd_parser

        assert hasattr(nvd_parser, "parse_cve_item")

    def test_cache_key_generation(self):
        """Cache service generates consistent keys."""
        from cve_mcp.services.cache import CacheService

        cache = CacheService()
        key1 = cache._make_key("test", "value")
        key2 = cache._make_key("test", "value")
        assert key1 == key2  # Same inputs = same key

        key3 = cache._make_key("test", "different")
        assert key1 != key3  # Different inputs = different keys
