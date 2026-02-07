# Quick Test Guide

Fast reference for running the threat-intel-mcp test suite.

## Run All Fast Tests (< 1 second)
```bash
pytest tests/test_mcp_protocol.py tests/test_integration.py tests/test_dual_mode.py \
  -m "not integration and not slow"
```
**Expected:** 57 passed in ~0.8s

## Run MCP Protocol Tests Only
```bash
pytest tests/test_mcp_protocol.py -v
```
**Expected:** 23 passed in ~0.6s

## Run HTTP Integration Tests (Requires Server)
```bash
# Terminal 1: Start server
python -m cve_mcp --mode http

# Terminal 2: Run tests
pytest tests/test_integration.py::TestHTTPIntegration -v
```
**Expected:** 8 passed in ~10s

## Run Dual-Mode Tests (Fast)
```bash
pytest tests/test_dual_mode.py -m "not integration and not slow"
```
**Expected:** 12 passed in ~0.6s

## Run All Tests (Requires Database + Redis)
```bash
pytest tests/ -v
```
**Expected:** ~370 tests (some may fail/skip without database)

## Run Only Fast Tests Across Entire Suite
```bash
pytest tests/ -m "not integration and not slow" -k "not azure and not aws and not gcp"
```
**Expected:** ~250 passed in < 5s

## Test Markers

- `fast` - Unit tests < 1 second, no external deps
- `slow` - Tests taking several seconds
- `integration` - Requires running database/Redis/server
- `aws` / `azure` / `gcp` - Requires cloud provider credentials

## Key Test Files

| File | Tests | Purpose |
|------|-------|---------|
| `test_mcp_protocol.py` | 23 | MCP JSON-RPC 2.0 compliance |
| `test_integration.py` | 30 | HTTP wrapper + version comparison |
| `test_dual_mode.py` | 19 | Dual-mode operation (stdio + HTTP) |

## Troubleshooting

**"ModuleNotFoundError"**
```bash
pip install -e ".[dev]"
```

**"Server not running"**
```bash
python -m cve_mcp --mode http  # In separate terminal
```

**"Database connection failed"**
```bash
pytest -m "not integration"  # Skip DB tests
```

## Documentation

- Full guide: `docs/TESTING.md`
- Summary: `TEST_SUITE_SUMMARY.md`
- CI/CD: See `docs/TESTING.md` for GitHub Actions example
