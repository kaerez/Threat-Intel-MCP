# MCP Protocol Compliance Design

**Date:** 2026-02-07
**Status:** Approved
**Scope:** P0 (MCP Protocol) + P1 (Docs/Security) + P2 (Tests/Cloud Module)

## Problem Statement

The threat-intel-mcp server claims to implement the MCP protocol but has critical gaps:

- **[P0] Protocol Mismatch**: Docs claim JSON-RPC 2.0 over HTTP/SSE and stdio, but only custom REST endpoints exist
- **[P1] Documentation Errors**: README uses wrong endpoints, SETUP.md references non-existent tasks
- **[P1] Security Overstatement**: SECURITY.md claims rate limiting but no middleware exists
- **[P2] Test Drift**: Integration tests don't make HTTP calls, expect 36 tools but system has 41
- **[P2] Cloud Module Incomplete**: GCP constraints are placeholders, agent integration pending

## Goals

1. Implement proper MCP protocol compliance (JSON-RPC 2.0 with stdio transport)
2. Maintain 100% backward compatibility with Ansvar platform HTTP wrapper
3. Fix all documentation to match implementation
4. Complete GCP cloud module with real API integration
5. Update test suite to validate both MCP and HTTP modes

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
│  MCP Protocol Layer (official Python SDK)           │
│  - Tool registration & discovery                    │
│  - JSON-RPC 2.0 message handling                    │
│  - stdio transport implementation                   │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│  Core Business Logic Layer (shared)                 │
│  - 41 tool handlers (unchanged)                     │
│  - Query services (CVE, ATT&CK, etc.)               │
│  - Database & cache services                        │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│  HTTP Wrapper (for Ansvar platform)                 │
│  - FastAPI endpoints (/mcp/tools, /mcp/tools/call)  │
│  - CORS & health checks                             │
│  - Calls into Core Business Logic                   │
└─────────────────────────────────────────────────────┘
```

**Key Principle:** The 41 existing tool handlers remain unchanged. Both MCP layer and HTTP wrapper call the same business logic.

### File Structure

**New Files:**
```
src/cve_mcp/
├── mcp/
│   ├── __init__.py
│   ├── server.py          # MCP server using official SDK
│   ├── transports.py      # stdio transport implementation
│   └── tool_adapter.py    # Converts tool handlers → MCP tool definitions
├── api/
│   └── middleware.py      # CORS, logging (NO rate limiting - internal only)
```

**Refactored Files:**
```
src/cve_mcp/api/app.py     # HTTP wrapper calls MCP server internally
src/cve_mcp/api/tools.py   # Add MCP metadata to tool definitions
src/cve_mcp/config.py      # Add mcp_mode: "stdio" | "http" | "both"
src/cve_mcp/main.py        # Support multiple modes
```

### Deployment Modes

```bash
# Mode 1: stdio (for MCP clients like Claude Desktop)
python -m cve_mcp --mode stdio

# Mode 2: http (for Ansvar platform)
python -m cve_mcp --mode http

# Mode 3: both (for development/testing)
python -m cve_mcp --mode both
```

**Ansvar Platform (No Breaking Changes):**
```yaml
# docker-compose.mcp.yml - only change is adding --mode flag
services:
  cve-mcp-server:
    command: python -m cve_mcp --mode http
    ports:
      - "8307:8307"
```

## Implementation Plan

### Phase 1: Parallel Workstreams (Independent)

**Agent 1: MCP Protocol Core**
- Install official MCP Python SDK
- Implement `src/cve_mcp/mcp/server.py` with JSON-RPC 2.0 handler
- Implement `src/cve_mcp/mcp/tool_adapter.py` to wrap existing tool handlers
- Add stdio transport in `src/cve_mcp/mcp/transports.py`
- Update `main.py` to support `--mode` flag
- Test with Claude Desktop

**Agent 2: GCP Cloud Module Completion**
- Replace placeholder constraints in `src/cve_mcp/cloud/gcp_api_client.py`
- Integrate GCP Security Command Center API for real constraint data
- Add end-to-end test validating agent queries work
- Update `docs/CLOUD_SECURITY_HANDOVER.md` to mark complete
- Ensure parity with AWS/Azure modules

**Agent 3: Documentation Fixes (Draft)**
- Fix README.md: `/call` → `/mcp/tools/call`
- Fix SETUP.md: Update task names to match Celery tasks
- Update SECURITY.md: Remove rate limiting claim
- Draft MCP usage section for README
- Update architecture diagrams

### Phase 2: Integration & Validation (After Phase 1)

**Agent 4: HTTP Wrapper Refactoring**
- Refactor `src/cve_mcp/api/app.py` to call MCP server internally
- Add `src/cve_mcp/api/middleware.py` (CORS, logging only)
- Ensure all 25 Ansvar platform tools work identically
- Validate against ThreatIntelClient contract
- Test with actual Ansvar platform containers

**Agent 5: Test Suite Overhaul**
- Add MCP protocol tests (`tests/test_mcp_protocol.py`)
- Add HTTP integration tests with actual HTTP calls
- Update tool count expectations (36 → 41)
- Add dual-mode test (stdio + HTTP simultaneously)
- Ensure version comparison tests still pass

**Agent 3 (continued): Documentation Finalization**
- Update docs based on actual implementation
- Add working examples for both MCP and HTTP modes
- Verify all SETUP.md commands execute successfully
- Update version to 1.3.0

## Success Criteria

### MCP Protocol Compliance
- ✅ Server works with Claude Desktop via stdio
- ✅ JSON-RPC 2.0 message format validated
- ✅ All 41 tools discoverable via `tools/list`
- ✅ All 41 tools callable via `tools/call`

### Ansvar Platform Compatibility
- ✅ All existing ThreatIntelClient calls work unchanged
- ✅ All 25 agent-facing tools return identical responses
- ✅ HTTP endpoints `/mcp/tools` and `/mcp/tools/call` work
- ✅ Container startup unchanged except `--mode http` flag

### Documentation Accuracy
- ✅ README examples execute successfully
- ✅ SETUP.md task names match actual Celery tasks
- ✅ SECURITY.md reflects actual features (no false claims)
- ✅ Architecture diagrams match implementation

### Cloud Module Complete
- ✅ GCP constraints use real API data (no placeholders)
- ✅ End-to-end agent integration test passes
- ✅ All 3 providers (AWS, Azure, GCP) work identically

### Test Coverage
- ✅ MCP stdio mode integration tests pass
- ✅ HTTP wrapper tests make actual HTTP calls
- ✅ Tool count assertions updated to 41
- ✅ Both modes tested simultaneously

## Risks & Mitigations

**Risk:** Breaking Ansvar platform integration
**Mitigation:** Agent 4 validates ThreatIntelClient contract, runs integration tests

**Risk:** MCP SDK compatibility issues
**Mitigation:** Use official SDK, follow reference implementations

**Risk:** GCP API quota/costs
**Mitigation:** Use free tier, cache aggressively like AWS module

**Risk:** Test suite takes too long
**Mitigation:** Use pytest markers for fast/slow tests, run in parallel

## Version Bump

Current: 1.2.1 → Target: **1.3.0**

Major feature: Full MCP protocol compliance with backward-compatible HTTP wrapper.
