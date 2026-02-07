"""MCP server implementation using official Python SDK."""

from typing import Any

import structlog
from mcp.server import Server
from mcp.types import TextContent, Tool

from cve_mcp.api.tools import MCP_TOOLS, TOOL_HANDLERS
from cve_mcp.config import PROJECT_NAME

logger = structlog.get_logger(__name__)


class MCPServerWrapper:
    """Wrapper around MCP Server with direct handler access.

    This wrapper provides both the standard MCP Server interface (for stdio transport)
    and direct access to handlers (for HTTP wrapper). This ensures both modes use
    identical business logic.
    """

    def __init__(self, server: Server):
        self.server = server
        self._call_tool_func = None
        self._list_tools_func = None

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Call a tool directly (for HTTP wrapper)."""
        if self._call_tool_func is None:
            raise RuntimeError("call_tool handler not registered")
        return await self._call_tool_func(name, arguments)

    async def list_tools(self) -> list[Tool]:
        """List tools directly (for HTTP wrapper)."""
        if self._list_tools_func is None:
            raise RuntimeError("list_tools handler not registered")
        return await self._list_tools_func()


def create_mcp_server() -> MCPServerWrapper:
    """
    Create and configure an MCP server instance.

    This function creates an MCP server using the official Python SDK and
    registers all 41 tool handlers. The tools are defined in cve_mcp.api.tools
    and this function acts as a thin adapter layer.

    Returns:
        Configured MCP server wrapper with direct handler access
    """
    # Create server with project metadata
    server = Server(PROJECT_NAME)

    # Create wrapper
    wrapper = MCPServerWrapper(server)

    # Register all tools from MCP_TOOLS list
    logger.info(f"Registering {len(MCP_TOOLS)} tools with MCP server")

    # Convert tool definitions to MCP SDK format and store them
    tools_map: dict[str, Tool] = {}
    for tool_def in MCP_TOOLS:
        tool = Tool(
            name=tool_def.name,
            description=tool_def.description,
            inputSchema=tool_def.inputSchema,
        )
        tools_map[tool_def.name] = tool

    @server.list_tools()
    async def list_tools_handler() -> list[Tool]:
        """
        List all available tools.

        This handler responds to the MCP tools/list request.
        """
        logger.debug("Listing tools", count=len(tools_map))
        return list(tools_map.values())

    # Store handler for direct access
    wrapper._list_tools_func = list_tools_handler

    @server.call_tool()
    async def call_tool_handler(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """
        Call a tool by name with the provided arguments.

        This handler responds to the MCP tools/call request and delegates
        to the existing tool handlers in cve_mcp.api.tools without modification.

        Args:
            name: Tool name
            arguments: Tool arguments from MCP client

        Returns:
            List of text content items (MCP protocol format)

        Raises:
            ValueError: If tool name is not found
        """
        logger.info("Tool call", tool=name, args_keys=list(arguments.keys()))

        # Get the handler for this tool
        handler = TOOL_HANDLERS.get(name)
        if not handler:
            logger.error("Tool not found", tool=name)
            raise ValueError(f"Tool not found: {name}")

        # Validate tool exists in our tools map
        if name not in tools_map:
            logger.error("Tool not registered", tool=name)
            raise ValueError(f"Tool not registered: {name}")

        try:
            # Call the existing handler (unchanged business logic)
            result = await handler(arguments)

            # Convert result to MCP TextContent format
            # The existing handlers return dict[str, Any] which we serialize as JSON
            import json

            result_text = json.dumps(result, indent=2, default=str)

            logger.debug("Tool call succeeded", tool=name, result_size=len(result_text))

            return [TextContent(type="text", text=result_text)]

        except Exception as e:
            logger.error("Tool call failed", tool=name, error=str(e), exc_info=True)
            # Return error as text content (MCP protocol)
            error_msg = f"Error calling tool {name}: {str(e)}"
            return [TextContent(type="text", text=error_msg)]

    # Store handler for direct access
    wrapper._call_tool_func = call_tool_handler

    logger.info(
        "MCP server created",
        project=PROJECT_NAME,
        tools_count=len(tools_map),
        protocol="JSON-RPC 2.0",
    )

    return wrapper
