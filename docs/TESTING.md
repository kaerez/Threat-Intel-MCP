# Testing Guide for Threat Intel MCP

This document describes the test suite for the Threat Intelligence MCP server, including test organization, execution strategies, and coverage details.

## Test Suite Overview

The test suite validates:
1. **MCP Protocol Compliance** - JSON-RPC 2.0, stdio transport, tool registration
2. **HTTP Wrapper Integration** - FastAPI endpoints for Ansvar platform
3. **Dual-Mode Operation** - Both stdio and HTTP modes running simultaneously
4. **Business Logic** - CVE, ATT&CK, ATLAS, CAPEC, CWE, D3FEND, Cloud Security modules
5. **Data Parsing** - NVD, CISA KEV, MITRE frameworks, cloud provider APIs
6. **Version Comparison** - Semantic versioning for CVE product matching

## Test Organization

```
tests/
├── test_mcp_protocol.py      # MCP protocol compliance (23 tests)
├── test_integration.py        # Integration tests + HTTP endpoints (30 tests)
├── test_dual_mode.py          # Dual-mode server tests (19 tests)
├── ingest/                    # Data ingestion parsers (100+ tests)
├── integration/               # Integration with DB (20+ tests)
├── models/                    # SQLAlchemy models (50+ tests)
├── services/                  # Query services (80+ tests)
└── tasks/                     # Celery sync tasks (40+ tests)
```

## Test Markers

Tests are categorized using pytest markers for selective execution:

### Speed Markers
- **`@pytest.mark.fast`** - Unit tests < 1 second, no external dependencies
- **`@pytest.mark.slow`** - Tests taking several seconds (e.g., server startup)

### Dependency Markers
- **`@pytest.mark.integration`** - Requires running database/Redis/server
- **`@pytest.mark.aws`** - Requires AWS credentials (Security Hub API)
- **`@pytest.mark.azure`** - Requires Azure credentials (Policy API)
- **`@pytest.mark.gcp`** - Requires GCP credentials (Organization Policy API)

## Running Tests

### Fast Unit Tests (Default)
```bash
# Run all fast tests (< 5 seconds total)
pytest tests/ -m "not integration and not slow"

# Expected: ~250 tests pass in < 5 seconds
```

### MCP Protocol Tests
```bash
# Test MCP JSON-RPC 2.0 compliance
pytest tests/test_mcp_protocol.py -v

# Test only fast MCP tests
pytest tests/test_mcp_protocol.py -m fast
```

### Integration Tests (Requires Running Server)
```bash
# Start server in separate terminal
python -m cve_mcp --mode http

# Run HTTP integration tests
pytest tests/test_integration.py::TestHTTPIntegration -v

# Expected: Server must be running on localhost:8307
```

### Dual-Mode Tests
```bash
# Test both stdio and HTTP modes simultaneously
pytest tests/test_dual_mode.py -m "not slow"

# Integration tests (starts server automatically)
pytest tests/test_dual_mode.py::TestDualModeServer -v
```

### All Tests (Slow, Requires Services)
```bash
# Run complete test suite
pytest tests/ -v

# Expected: ~370 tests, requires PostgreSQL + Redis + optional API keys
```

## Test Coverage by Module

### MCP Protocol (test_mcp_protocol.py) - 23 tests
- **Server Creation**: Initialization, tool registration
- **Tools List**: Validates all 41 tools are discoverable via `tools/list`
- **Tools Call**: Handler execution via `tools/call`
- **JSON-RPC Format**: Message format validation (request/response/error)
- **Stdio Transport**: Message framing, newline-delimited JSON
- **Schema Validation**: Pydantic request/response schemas
- **Protocol Compliance**: JSON-RPC 2.0 version, content types

**Key Tests:**
- `test_list_tools_returns_41_tools()` - Validates tool count
- `test_all_tool_categories_present()` - Ensures all 8 modules represented
- `test_jsonrpc_request_format()` - JSON-RPC 2.0 message structure
- `test_stdio_message_framing()` - Newline-delimited JSON parsing

### HTTP Integration (test_integration.py) - 30 tests
- **Version Comparison** (8 tests): Semantic versioning logic (eq/lt/lte/gt/gte)
- **MCP Tool Definitions** (4 tests): Tool schemas, required fields
- **API Schemas** (3 tests): Pydantic validation (CVSS scores, CVE ID patterns)
- **Database Models** (3 tests): SQLAlchemy model structure
- **Configuration** (2 tests): Settings loading, CORS configuration
- **Utilities** (2 tests): NVD parser, cache key generation
- **HTTP Endpoints** (8 tests): `/health`, `/mcp/tools`, `/mcp/tools/call`

**Key Tests:**
- `test_version_semantic_ordering()` - Critical for CVE product matching
- `test_all_tools_defined()` - Updated to validate 41 tools
- `test_mcp_tools_list_endpoint()` - HTTP wrapper returns all tools
- `test_mcp_tools_call_search_cve()` - End-to-end HTTP tool execution

### Dual-Mode (test_dual_mode.py) - 19 tests
- **Mode Configuration** (3 tests): Valid modes (stdio/http/both)
- **Mode Selection** (3 tests): Startup logic for each mode
- **Server Startup** (3 tests): Fast creation, coexistence validation
- **HTTP in Dual Mode** (4 tests): HTTP endpoints work when stdio also active
- **Transport Implementation** (3 tests): Module existence validation
- **Environment Variables** (2 tests): Mode selection via env vars
- **Dual-Mode Server** (1 test): Both modes running simultaneously

**Key Tests:**
- `test_both_components_can_coexist()` - MCP server + FastAPI app together
- `test_http_mode_works_in_dual_mode()` - No interference between modes
- `test_server_creation_fast()` - Performance validation

## Expected Test Results

### Fast Tests (No External Dependencies)
```
pytest tests/ -m "not integration and not slow" -k "not azure and not aws and not gcp"

Expected: ~250 passed, 3 skipped (OpenAI embeddings), 0 failed
Time: < 5 seconds
```

### With Running Server (HTTP Integration)
```
# Terminal 1
python -m cve_mcp --mode http

# Terminal 2
pytest tests/test_integration.py::TestHTTPIntegration -v

Expected: 8 passed, 0 failed
Time: < 10 seconds
```

### With Database + Redis (Full Integration)
```
# Requires docker-compose up postgres redis
pytest tests/integration/ -v

Expected: ~20 passed (DB queries work)
Failures: Database connection errors if services not running
```

## Known Test Patterns

### Database-Dependent Tests
These tests are marked `@pytest.mark.integration` and require PostgreSQL:
- `tests/integration/test_atlas_semantic_search.py` (12 tests)
- `tests/integration/test_semantic_search.py` (7 tests)
- Tests expecting `asyncpg.exceptions.InvalidPasswordError` when DB unavailable

### Cloud-Specific Tests
Require cloud provider credentials:
- `@pytest.mark.aws` - AWS Security Hub API tests
- `@pytest.mark.azure` - Azure Policy API tests (some use public GitHub data)
- `@pytest.mark.gcp` - GCP Organization Policy API tests

### Embedding Tests
Require `OPENAI_API_KEY`:
- `tests/services/test_embeddings.py` - Skipped if key not set
- All `find_similar_*` tools - Return error if key not configured

## Test Maintenance

### Adding New Tools
When adding a new MCP tool:

1. **Update tool count**:
   ```python
   # test_mcp_protocol.py
   assert len(MCP_TOOLS) == 42  # Increment from 41

   # test_integration.py
   assert len(MCP_TOOLS) == 42  # Keep in sync
   ```

2. **Add to category test**:
   ```python
   # test_mcp_protocol.py::TestToolsListProtocol::test_all_tool_categories_present
   expected_new_module_tools = {
       "new_tool_name",
   }
   ```

3. **Add schema test**:
   ```python
   # test_mcp_protocol.py::TestMCPSchemaValidation
   def test_new_tool_schema_validation(self):
       from cve_mcp.api.schemas import NewToolRequest
       # Validation logic
   ```

### Updating Integration Tests
For HTTP endpoint changes:

1. Update expected response format in `TestHTTPIntegration`
2. Add new endpoint tests if adding routes
3. Validate CORS headers if changing middleware

### Performance Benchmarks
- Server creation: < 100ms
- Fast test suite: < 5 seconds
- Full integration suite: < 60 seconds

## Troubleshooting

### "ModuleNotFoundError: No module named 'cve_mcp'"
```bash
pip install -e ".[dev]"
```

### "password authentication failed for user 'cve_user'"
Database not running or wrong credentials. Skip integration tests:
```bash
pytest -m "not integration"
```

### "Server already running" (dual-mode tests)
```bash
# Stop existing server first
pkill -f "python -m cve_mcp"

# Then run dual-mode tests
pytest tests/test_dual_mode.py::TestDualModeServer
```

### "Unknown tool: ..." errors
Tool handler registration issue. Check:
1. Tool defined in `MCP_TOOLS` list
2. Handler registered in `TOOL_HANDLERS` dict
3. Handler function signature matches `async def handler(args: dict) -> dict`

## CI/CD Recommendations

### GitHub Actions Workflow
```yaml
- name: Run fast tests
  run: pytest tests/ -m "not integration and not slow" --cov=cve_mcp

- name: Run integration tests
  run: |
    docker-compose up -d postgres redis
    sleep 10
    pytest tests/integration/ -v
  env:
    DATABASE_URL: postgresql+asyncpg://cve_user:test@localhost:5432/cve_mcp
```

### Pre-commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
pytest tests/ -m fast --maxfail=1 -q
```

## Test Coverage Goals

- **Unit Tests**: > 80% code coverage
- **Integration Tests**: All 41 tools callable via HTTP
- **MCP Protocol**: 100% JSON-RPC 2.0 compliance
- **Version Comparison**: All operators (eq/lt/lte/gt/gte) tested
- **Error Handling**: Validation errors return clear messages

## Version History

- **v1.3.0**: Added MCP protocol tests, HTTP integration tests, dual-mode tests
- **v1.2.0**: Added Cloud Security module tests (AWS/Azure/GCP)
- **v1.1.0**: Added D3FEND, CWE, CAPEC integration tests
- **v1.0.0**: Initial test suite with CVE, ATT&CK, ATLAS coverage
