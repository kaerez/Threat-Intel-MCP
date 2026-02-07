# MCP Protocol Implementation

**Date:** 2026-02-07
**Status:** ✅ Complete (Phase 1)
**Version:** 1.3.0-dev

## Overview

This document describes the MCP protocol implementation for the Threat Intel MCP server using the official Python SDK. The implementation provides JSON-RPC 2.0 protocol compliance with stdio transport while maintaining 100% backward compatibility with the existing HTTP wrapper for Ansvar platform.

## Architecture

### Layered Design

```
┌─────────────────────────────────────────────────────┐
│  MCP Clients (Claude Desktop, Cursor, etc.)         │
│  via stdio transport (JSON-RPC 2.0)                 │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│  MCP Protocol Layer (NEW)                           │
│  src/cve_mcp/mcp/                                   │
│  - server.py: MCP server with JSON-RPC 2.0          │
│  - tool_adapter.py: Converts handlers to MCP tools  │
│  - transports.py: stdio transport implementation    │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│  Core Business Logic Layer (UNCHANGED)              │
│  src/cve_mcp/api/tools.py                           │
│  - 41 tool handlers (unchanged)                     │
│  - Query services (CVE, ATT&CK, etc.)               │
│  - Database & cache services                        │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│  HTTP Wrapper (UNCHANGED - for Ansvar platform)     │
│  src/cve_mcp/api/app.py                             │
│  - FastAPI endpoints (/mcp/tools, /mcp/tools/call)  │
│  - CORS & health checks                             │
│  - Calls into Core Business Logic                   │
└─────────────────────────────────────────────────────┘
```

**Key Principle:** The 41 existing tool handlers in `src/cve_mcp/api/tools.py` remain completely unchanged. Both the MCP protocol layer and HTTP wrapper call the same business logic.

## Files Created

### New Files

1. **`src/cve_mcp/mcp/__init__.py`**
   - Package initialization
   - Exports `create_mcp_server` function

2. **`src/cve_mcp/mcp/server.py`** (Core MCP Server)
   - Creates MCP server using official Python SDK
   - Registers all 41 tools from `MCP_TOOLS` list
   - Implements `list_tools()` handler for tool discovery
   - Implements `call_tool()` handler for tool execution
   - Delegates to existing tool handlers without modification
   - Returns results in MCP TextContent format

3. **`src/cve_mcp/mcp/tool_adapter.py`** (Tool Adapter)
   - Converts `MCPToolDefinition` objects to MCP SDK `Tool` objects
   - Provides `get_tool_list()` for tool discovery
   - Provides `call_tool()` for clean handler invocation
   - Bridge between existing tool definitions and MCP protocol

4. **`src/cve_mcp/mcp/transports.py`** (Transport Layer)
   - `run_stdio_transport()`: stdio transport using MCP SDK
   - Reads JSON-RPC 2.0 messages from stdin
   - Writes responses to stdout
   - Uses stderr for logging (compatible with Claude Desktop)
   - `run_http_sse_transport()`: placeholder for future HTTP/SSE transport

5. **`src/cve_mcp/__main__.py`**
   - Entry point for `python -m cve_mcp`
   - Delegates to `main.py`

### Modified Files

1. **`src/cve_mcp/main.py`** (Entry Point)
   - Added `--mode` flag support (stdio, http, both)
   - Added `--host` and `--port` flags
   - `run_stdio_mode()`: Runs MCP server with stdio transport
   - `run_http_mode()`: Runs existing FastAPI HTTP server (unchanged)
   - `run_both_modes()`: Runs both simultaneously for dev/test
   - Falls back to `mcp_mode` config setting if `--mode` not provided

2. **`src/cve_mcp/config.py`** (Configuration)
   - Added `mcp_mode: str = "http"` setting
   - Supports 'stdio', 'http', or 'both' modes
   - Default remains 'http' for backward compatibility

3. **`pyproject.toml`** (Dependencies)
   - Added `mcp>=1.26.0` to dependencies
   - Official MCP Python SDK for JSON-RPC 2.0 protocol

## Usage

### Mode 1: stdio (MCP Clients)

For Claude Desktop, Cursor, and other MCP-compatible clients:

```bash
python -m cve_mcp --mode stdio
```

Or using the CLI command:

```bash
cve-mcp --mode stdio
```

**Claude Desktop Configuration:**

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "python3",
      "args": ["-m", "cve_mcp", "--mode", "stdio"],
      "env": {
        "DATABASE_URL": "postgresql+asyncpg://...",
        "REDIS_URL": "redis://...",
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

Or using installed command:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "cve-mcp",
      "args": ["--mode", "stdio"]
    }
  }
}
```

### Mode 2: http (Ansvar Platform)

For the existing Ansvar platform integration (no changes):

```bash
python -m cve_mcp --mode http
```

Or with custom host/port:

```bash
python -m cve_mcp --mode http --host 0.0.0.0 --port 8307
```

**Docker Compose (Ansvar Platform):**

```yaml
# docker-compose.mcp.yml - only change is adding --mode flag
services:
  cve-mcp-server:
    command: python -m cve_mcp --mode http
    ports:
      - "8307:8307"
```

### Mode 3: both (Development/Testing)

Run both stdio and HTTP simultaneously:

```bash
python -m cve_mcp --mode both
```

This allows:
- Testing with Claude Desktop via stdio
- Running integration tests via HTTP endpoints
- Debugging both transports simultaneously

## Protocol Details

### JSON-RPC 2.0 Compliance

The MCP server implements JSON-RPC 2.0 protocol using the official MCP Python SDK:

1. **Tool Discovery** (tools/list)
   - Returns list of all 41 tools
   - Each tool includes name, description, and inputSchema
   - Schema uses JSON Schema format

2. **Tool Execution** (tools/call)
   - Accepts tool name and arguments
   - Validates tool exists
   - Calls existing handler from `TOOL_HANDLERS` dict
   - Returns result as TextContent with JSON-serialized data

3. **Error Handling**
   - Unknown tools return ValueError
   - Handler errors caught and returned as TextContent with error message
   - All errors logged via structlog

### Stdio Transport

The stdio transport implementation:
- Uses MCP SDK's `stdio_server()` context manager
- Reads JSON-RPC 2.0 messages from stdin
- Writes responses to stdout
- Logs to stderr (compatible with Claude Desktop)
- Fully async using asyncio

## Testing

### Basic Import Test

```python
from cve_mcp.mcp import create_mcp_server

server = create_mcp_server()
print(f"Server: {server.name}")
# Output: Server: Threat Intel MCP
```

### Tool Registration Test

```python
from cve_mcp.mcp.server import create_mcp_server

server = create_mcp_server()
# Logs: Registering 41 tools with MCP server
# Logs: MCP server created (protocol=JSON-RPC 2.0, tools_count=41)
```

### Command-Line Test

```bash
# Test help
python -m cve_mcp --help

# Test stdio mode (requires stdin input - use with MCP client)
python -m cve_mcp --mode stdio

# Test http mode (starts FastAPI server)
python -m cve_mcp --mode http
```

### Full stdio Test

Use the included test script:

```bash
python test_mcp_stdio.py
```

## Tool Coverage

All 41 tools from `src/cve_mcp/api/tools.py` are available via MCP protocol:

### CVE Intelligence (8 tools)
- search_cve
- get_cve_details
- check_kev_status
- get_epss_score
- search_by_product
- get_exploits
- get_cwe_details
- batch_search

### ATT&CK (7 tools)
- search_techniques
- find_similar_techniques
- get_technique_details
- get_technique_badges
- search_threat_actors
- find_similar_threat_actors
- get_group_profile

### ATLAS (5 tools)
- search_atlas_techniques
- find_similar_atlas_techniques
- get_atlas_technique_details
- search_atlas_case_studies
- find_similar_atlas_case_studies

### CAPEC (5 tools)
- search_capec_patterns
- find_similar_capec_patterns
- get_capec_pattern_details
- search_capec_mitigations
- find_similar_capec_mitigations

### CWE (6 tools)
- search_cwe_weaknesses
- find_similar_cwe_weaknesses
- get_cwe_weakness_details
- search_by_external_mapping
- get_cwe_hierarchy
- find_weaknesses_for_capec

### D3FEND (5 tools)
- search_defenses
- find_similar_defenses
- get_defense_details
- get_defenses_for_attack
- get_attack_coverage

### Cloud Security (4 tools)
- search_cloud_services
- get_cloud_service_security
- compare_cloud_services
- get_shared_responsibility

### System (1 tool)
- get_data_freshness

## Backward Compatibility

### HTTP Wrapper (Ansvar Platform)

The existing HTTP endpoints remain completely unchanged:

- `GET /health` - Health check
- `GET /mcp/tools` - List tools
- `POST /mcp/tools/call` - Call tool

The FastAPI app in `src/cve_mcp/api/app.py` continues to work identically. All 25 agent-facing tools in the Ansvar platform integration are unaffected.

### Tool Handlers

All 41 tool handlers in `src/cve_mcp/api/tools.py` remain completely unchanged. They continue to:
- Accept `params: dict[str, Any]`
- Return `dict[str, Any]`
- Use existing query services
- Use existing Pydantic schemas for validation

The MCP protocol layer acts as a thin adapter that:
1. Receives JSON-RPC 2.0 messages
2. Extracts tool name and arguments
3. Calls existing handler
4. Wraps result in MCP TextContent format

## Dependencies

New dependency added:

```toml
"mcp>=1.26.0"  # Official MCP Python SDK for JSON-RPC 2.0 protocol
```

All existing dependencies remain unchanged.

## Success Criteria

### ✅ Completed

1. **MCP SDK Integration**
   - Official MCP Python SDK installed
   - MCP server created successfully
   - All 41 tools registered

2. **stdio Transport**
   - stdio transport implementation using MCP SDK
   - JSON-RPC 2.0 message handling
   - Compatible with Claude Desktop

3. **CLI Support**
   - `--mode` flag implemented (stdio, http, both)
   - `--host` and `--port` flags for HTTP mode
   - Help text and examples

4. **Configuration**
   - `mcp_mode` setting added to config
   - Falls back to config if `--mode` not provided
   - Default remains 'http' for backward compatibility

5. **Testing**
   - Import tests pass
   - Server creation works
   - CLI help works
   - Basic protocol test passes

### 🔄 Next Steps (Future Phases)

1. **Integration Tests** (Phase 2)
   - Add MCP protocol integration tests
   - Test with actual Claude Desktop
   - Test dual-mode operation
   - Validate all 41 tools via stdio

2. **HTTP Wrapper Refactoring** (Phase 2)
   - Refactor `api/app.py` to call MCP server internally
   - Ensure Ansvar platform compatibility
   - Add middleware tests

3. **Documentation** (Phase 2)
   - Update README with MCP usage examples
   - Add troubleshooting guide
   - Document Claude Desktop setup

## Known Limitations

1. **HTTP/SSE Transport**: Not yet implemented. The MCP SDK supports HTTP with Server-Sent Events, but the Ansvar platform uses a custom HTTP wrapper instead. This may be implemented in a future phase.

2. **Full stdio Testing**: Requires actual stdin/stdout streams, which is best tested with a real MCP client like Claude Desktop.

3. **Error Handling**: Currently returns errors as text content. May need enhanced error formatting for better client experience.

## References

- MCP Specification: https://modelcontextprotocol.io/
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- Design Document: `docs/plans/2026-02-07-mcp-protocol-compliance-design.md`
- Project Memory: `.claude/projects/.../memory/MEMORY.md`

## Version History

- **1.2.1**: Pre-MCP baseline (HTTP-only, custom REST endpoints)
- **1.3.0-dev**: MCP protocol core implementation (this release)
  - Official MCP SDK integration
  - stdio transport for Claude Desktop
  - Dual-mode support (stdio + http)
  - All 41 tools available via JSON-RPC 2.0
