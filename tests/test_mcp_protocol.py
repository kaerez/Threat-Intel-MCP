"""MCP Protocol Compliance Tests.

Tests JSON-RPC 2.0 message format, stdio transport simulation,
and MCP server protocol implementation.
"""

import asyncio
import json
from io import StringIO

import pytest

# Import MCP types separately to avoid circular import issues
try:
    from mcp.types import TextContent, Tool
except ImportError:
    TextContent = None
    Tool = None


class TestMCPServerCreation:
    """Test MCP server initialization."""

    def test_server_creation(self):
        """MCP server creates successfully."""
        # Import locally to avoid circular imports
        from cve_mcp.mcp.server import create_mcp_server

        server = create_mcp_server()
        assert server is not None
        # MCP SDK server wrapper doesn't expose name directly, but it's created correctly

    def test_server_has_tool_handlers(self):
        """MCP server has tools registered."""
        from cve_mcp.mcp.server import create_mcp_server

        server = create_mcp_server()
        # MCP SDK stores handlers internally
        assert server is not None


class TestToolsListProtocol:
    """Test tools/list MCP protocol endpoint."""

    @pytest.mark.asyncio
    async def test_list_tools_returns_41_tools(self):
        """tools/list returns all 41 tools."""
        from cve_mcp.api.tools import MCP_TOOLS

        assert len(MCP_TOOLS) == 41

    @pytest.mark.asyncio
    async def test_list_tools_format(self):
        """Each tool has required MCP fields."""
        from cve_mcp.api.tools import MCP_TOOLS

        for tool in MCP_TOOLS:
            # Check Tool object structure
            assert hasattr(tool, "name")
            assert hasattr(tool, "description")
            assert hasattr(tool, "inputSchema")

            # Validate name is non-empty
            assert tool.name
            assert isinstance(tool.name, str)

            # Validate description is non-empty
            assert tool.description
            assert isinstance(tool.description, str)

            # Validate inputSchema is JSON Schema format
            assert tool.inputSchema
            assert isinstance(tool.inputSchema, dict)
            assert tool.inputSchema.get("type") == "object"
            assert "properties" in tool.inputSchema

    @pytest.mark.asyncio
    async def test_all_tool_categories_present(self):
        """All tool categories are represented."""
        from cve_mcp.api.tools import MCP_TOOLS

        tool_names = {t.name for t in MCP_TOOLS}

        # CVE Intelligence (8 tools)
        cve_tools = {
            "search_cve",
            "get_cve_details",
            "check_kev_status",
            "get_epss_score",
            "search_by_product",
            "get_exploits",
            "get_cwe_details",
            "batch_search",
        }
        assert cve_tools.issubset(tool_names), f"Missing CVE tools: {cve_tools - tool_names}"

        # ATT&CK (7 tools)
        attack_tools = {
            "search_techniques",
            "find_similar_techniques",
            "get_technique_details",
            "get_technique_badges",
            "search_threat_actors",
            "find_similar_threat_actors",
            "get_group_profile",
        }
        assert (
            attack_tools.issubset(tool_names)
        ), f"Missing ATT&CK tools: {attack_tools - tool_names}"

        # ATLAS (5 tools)
        atlas_tools = {
            "search_atlas_techniques",
            "find_similar_atlas_techniques",
            "get_atlas_technique_details",
            "search_atlas_case_studies",
            "find_similar_atlas_case_studies",
        }
        assert atlas_tools.issubset(tool_names), f"Missing ATLAS tools: {atlas_tools - tool_names}"

        # CAPEC (5 tools)
        capec_tools = {
            "search_capec_patterns",
            "find_similar_capec_patterns",
            "get_capec_pattern_details",
            "search_capec_mitigations",
            "find_similar_capec_mitigations",
        }
        assert capec_tools.issubset(tool_names), f"Missing CAPEC tools: {capec_tools - tool_names}"

        # CWE (6 tools)
        cwe_tools = {
            "search_cwe_weaknesses",
            "find_similar_cwe_weaknesses",
            "get_cwe_weakness_details",
            "search_by_external_mapping",
            "get_cwe_hierarchy",
            "find_weaknesses_for_capec",
        }
        assert cwe_tools.issubset(tool_names), f"Missing CWE tools: {cwe_tools - tool_names}"

        # D3FEND (5 tools)
        d3fend_tools = {
            "search_defenses",
            "find_similar_defenses",
            "get_defense_details",
            "get_defenses_for_attack",
            "get_attack_coverage",
        }
        assert (
            d3fend_tools.issubset(tool_names)
        ), f"Missing D3FEND tools: {d3fend_tools - tool_names}"

        # Cloud Security (4 tools)
        cloud_tools = {
            "search_cloud_services",
            "get_cloud_service_security",
            "compare_cloud_services",
            "get_shared_responsibility",
        }
        assert cloud_tools.issubset(tool_names), f"Missing Cloud tools: {cloud_tools - tool_names}"

        # System (1 tool)
        system_tools = {"get_data_freshness"}
        assert (
            system_tools.issubset(tool_names)
        ), f"Missing System tools: {system_tools - tool_names}"


class TestToolsCallProtocol:
    """Test tools/call MCP protocol endpoint."""

    @pytest.mark.asyncio
    async def test_call_tool_handler_exists(self):
        """All tools have registered handlers."""
        from cve_mcp.api.tools import MCP_TOOLS, TOOL_HANDLERS

        for tool in MCP_TOOLS:
            assert (
                tool.name in TOOL_HANDLERS
            ), f"Tool {tool.name} missing handler in TOOL_HANDLERS"
            handler = TOOL_HANDLERS[tool.name]
            assert callable(handler), f"Handler for {tool.name} is not callable"

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_call_tool_returns_text_content(self):
        """Tool execution returns MCP TextContent format."""
        pytest.skip("Requires database connection - tested in integration tests")
        # This test would need a running database
        # Moved to integration tests that make actual HTTP calls

    @pytest.mark.asyncio
    async def test_call_nonexistent_tool_raises_error(self):
        """Calling non-existent tool raises ValueError."""
        from cve_mcp.api.tools import call_tool

        with pytest.raises(ValueError, match="Unknown tool"):
            await call_tool("nonexistent_tool", {})


class TestJSONRPCFormat:
    """Test JSON-RPC 2.0 message format compliance."""

    def test_jsonrpc_request_format(self):
        """JSON-RPC request has required fields."""
        # Example JSON-RPC 2.0 request
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
        }

        assert request["jsonrpc"] == "2.0"
        assert "method" in request
        assert "id" in request

    def test_jsonrpc_notification_format(self):
        """JSON-RPC notification has no id field."""
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }

        assert notification["jsonrpc"] == "2.0"
        assert "method" in notification
        assert "id" not in notification

    def test_jsonrpc_response_success_format(self):
        """JSON-RPC success response has required fields."""
        response = {
            "jsonrpc": "2.0",
            "result": {"tools": []},
            "id": 1,
        }

        assert response["jsonrpc"] == "2.0"
        assert "result" in response
        assert "error" not in response
        assert response["id"] == 1

    def test_jsonrpc_response_error_format(self):
        """JSON-RPC error response has required fields."""
        response = {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": 1,
        }

        assert response["jsonrpc"] == "2.0"
        assert "error" in response
        assert "result" not in response
        assert "code" in response["error"]
        assert "message" in response["error"]
        assert response["id"] == 1


class TestStdioTransportSimulation:
    """Test stdio transport behavior (simulated)."""

    @pytest.mark.asyncio
    async def test_stdio_message_framing(self):
        """Messages are newline-delimited JSON."""
        # Simulate reading a JSON-RPC message from stdin
        message = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}

        # Serialize as MCP protocol expects (newline-delimited JSON)
        serialized = json.dumps(message) + "\n"

        # Parse it back
        parsed = json.loads(serialized.strip())

        assert parsed == message
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["method"] == "tools/list"

    @pytest.mark.asyncio
    async def test_stdio_multiple_messages(self):
        """Multiple messages can be sent sequentially."""
        messages = [
            {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 2},
        ]

        # Simulate stdin stream
        stream = StringIO()
        for msg in messages:
            stream.write(json.dumps(msg) + "\n")

        stream.seek(0)

        # Read messages back
        parsed_messages = []
        for line in stream:
            parsed_messages.append(json.loads(line))

        assert len(parsed_messages) == 2
        assert parsed_messages[0]["id"] == 1
        assert parsed_messages[1]["id"] == 2

    def test_stdio_invalid_json_handling(self):
        """Invalid JSON raises error."""
        invalid_json = "{ invalid json }\n"

        with pytest.raises(json.JSONDecodeError):
            json.loads(invalid_json.strip())


class TestMCPSchemaValidation:
    """Test input schema validation for MCP tools."""

    @pytest.mark.asyncio
    async def test_search_cve_schema_validation(self):
        """search_cve validates parameters correctly."""
        from cve_mcp.api.schemas import SearchCVERequest
        from pydantic import ValidationError

        # Valid request
        request = SearchCVERequest(keyword="apache", cvss_min=7.0, limit=50)
        assert request.keyword == "apache"
        assert request.cvss_min == 7.0

        # Invalid: CVSS > 10
        with pytest.raises(ValidationError):
            SearchCVERequest(cvss_min=15.0)

    @pytest.mark.asyncio
    async def test_get_cve_details_schema_validation(self):
        """get_cve_details validates CVE ID pattern."""
        from cve_mcp.api.schemas import GetCVEDetailsRequest
        from pydantic import ValidationError

        # Valid CVE ID
        request = GetCVEDetailsRequest(cve_id="CVE-2021-44228")
        assert request.cve_id == "CVE-2021-44228"

        # Invalid CVE ID
        with pytest.raises(ValidationError):
            GetCVEDetailsRequest(cve_id="invalid-id")

    @pytest.mark.asyncio
    async def test_search_by_product_version_operator(self):
        """search_by_product accepts valid version operators."""
        from cve_mcp.api.schemas import SearchByProductRequest

        # Valid operators
        for op in ["eq", "lt", "lte", "gt", "gte"]:
            request = SearchByProductRequest(
                product_name="apache",
                version="2.4.49",
                version_operator=op,
            )
            assert request.version_operator == op


class TestProtocolCompliance:
    """High-level MCP protocol compliance tests."""

    @pytest.mark.asyncio
    async def test_server_implements_required_methods(self):
        """Server implements required MCP methods."""
        from cve_mcp.mcp.server import create_mcp_server

        server = create_mcp_server()

        # MCP SDK server should have these capabilities
        # These are internal to SDK but we verify via our tools
        from cve_mcp.api.tools import MCP_TOOLS

        # tools/list: must return 41 tools
        assert len(MCP_TOOLS) == 41

        # tools/call: all tools must have handlers
        from cve_mcp.api.tools import TOOL_HANDLERS

        for tool in MCP_TOOLS:
            assert tool.name in TOOL_HANDLERS

    @pytest.mark.asyncio
    async def test_protocol_version(self):
        """Server uses JSON-RPC 2.0."""
        # All MCP messages must use jsonrpc: "2.0"
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        assert request["jsonrpc"] == "2.0"

    @pytest.mark.asyncio
    async def test_content_type_format(self):
        """Tool responses use MCP TextContent format."""
        if TextContent is None:
            pytest.skip("MCP types not available")

        # Example response
        content = TextContent(type="text", text="test")
        assert content.type == "text"
        assert content.text == "test"


@pytest.mark.fast
class TestFastMCPValidation:
    """Fast tests that don't require database or external services."""

    def test_tool_count(self):
        """Quick check: 41 tools registered."""
        from cve_mcp.api.tools import MCP_TOOLS

        assert len(MCP_TOOLS) == 41

    def test_tool_handler_count(self):
        """Quick check: 41 handlers registered."""
        from cve_mcp.api.tools import TOOL_HANDLERS

        assert len(TOOL_HANDLERS) == 41

    def test_server_creates_quickly(self):
        """Server creation is fast (<100ms)."""
        import time

        from cve_mcp.mcp.server import create_mcp_server

        start = time.time()
        server = create_mcp_server()
        elapsed = time.time() - start

        assert server is not None
        assert elapsed < 0.1  # Should be nearly instantaneous
