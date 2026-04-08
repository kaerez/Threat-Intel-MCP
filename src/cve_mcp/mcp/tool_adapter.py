"""Adapter to convert existing tool handlers to MCP tool definitions."""

from typing import Any

from mcp.server import Server
from mcp.types import Tool

from cve_mcp.api.tools import MCP_TOOLS, TOOL_HANDLERS


def register_tools(server: Server) -> None:
    """
    Register all existing tool handlers with the MCP server.

    This adapter converts the existing MCPToolDefinition objects and handler
    functions into MCP SDK tool registrations without modifying the original
    business logic.

    Args:
        server: MCP server instance to register tools with
    """
    for tool_def in MCP_TOOLS:
        # Convert MCPToolDefinition to MCP SDK Tool
        tool = Tool(
            name=tool_def.name,
            description=tool_def.description,
            inputSchema=tool_def.inputSchema,
        )

        # Get the corresponding handler
        handler = TOOL_HANDLERS.get(tool_def.name)
        if not handler:
            raise ValueError(f"No handler found for tool: {tool_def.name}")

        # Register the tool with the server
        # The @server.call_tool decorator expects a function that takes
        # (name: str, arguments: dict) and returns the result
        async def tool_handler(name: str, arguments: dict[str, Any]) -> list[Any]:
            """
            MCP tool handler wrapper.

            Args:
                name: Tool name
                arguments: Tool arguments from MCP client

            Returns:
                List of content items (MCP protocol requires list format)
            """
            # Get the actual handler for this tool
            handler_func = TOOL_HANDLERS.get(name)
            if not handler_func:
                raise ValueError(f"No handler found for tool: {name}")

            # Call the existing handler (unchanged business logic)
            result = await handler_func(arguments)

            # MCP protocol expects results as a list of content items
            # For JSON responses, we return a single text content item
            return [{"type": "text", "text": str(result)}]

        # Store the tool definition for later use
        # Note: The actual registration happens in server.py using @server.call_tool
        server.add_tool(tool)


def get_tool_list() -> list[Tool]:
    """
    Get list of all tools in MCP SDK format.

    Returns:
        List of Tool objects compatible with MCP SDK
    """
    tools = []
    for tool_def in MCP_TOOLS:
        tool = Tool(
            name=tool_def.name,
            description=tool_def.description,
            inputSchema=tool_def.inputSchema,
        )
        tools.append(tool)
    return tools


async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Call a tool handler by name with the provided arguments.

    This function provides a clean interface for calling tool handlers
    without directly accessing TOOL_HANDLERS dict.

    Args:
        name: Tool name
        arguments: Tool arguments

    Returns:
        Tool execution result

    Raises:
        ValueError: If tool name is not found
    """
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        raise ValueError(f"Tool not found: {name}")

    return await handler(arguments)
