# MCP Quick Start Guide

## For Claude Desktop Users

### 1. Install the Package

```bash
# Clone the repository
git clone https://github.com/Ansvar-Systems/Threat-Intel-MCP.git
cd threat-intel-mcp

# Install in development mode
pip install -e .
```

### 2. Configure Claude Desktop

Add to your `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

**Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "python3",
      "args": ["-m", "cve_mcp", "--mode", "stdio"],
      "env": {
        "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost:5432/cve_mcp",
        "REDIS_URL": "redis://localhost:6379/0",
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

### 3. Start Required Services

```bash
# Using Docker Compose
docker-compose up -d cve-mcp-postgres cve-mcp-redis

# Or use existing PostgreSQL/Redis instances
```

### 4. Restart Claude Desktop

Close and reopen Claude Desktop. You should see the threat-intel MCP server connected.

### 5. Test the Tools

Ask Claude:

> "Search for recent critical CVEs affecting Apache"

> "What ATT&CK techniques are used by APT29?"

> "What are the security best practices for AWS S3?"

## For Ansvar Platform Integration

### No Changes Required

The existing HTTP mode continues to work identically:

```bash
# Start HTTP server (existing behavior)
python -m cve_mcp --mode http
```

Docker Compose:

```yaml
services:
  cve-mcp-server:
    command: python -m cve_mcp --mode http
    ports:
      - "8307:8307"
```

## For Developers

### Running Tests

```bash
# Test import
python -c "from cve_mcp.mcp import create_mcp_server; print('OK')"

# Test server creation
python test_mcp_stdio.py

# Test CLI
python -m cve_mcp --help
```

### Development Mode (Both Transports)

```bash
# Run both stdio and HTTP simultaneously
python -m cve_mcp --mode both
```

This allows:
- Testing Claude Desktop integration via stdio
- Running integration tests via HTTP
- Debugging both transports

### Adding New Tools

Tools are defined in `src/cve_mcp/api/tools.py`:

1. Add tool definition to `MCP_TOOLS` list
2. Add handler function (async)
3. Add handler to `TOOL_HANDLERS` dict

Both MCP stdio and HTTP wrapper will automatically pick up the new tool.

## Available Tools (41)

### CVE Intelligence
- search_cve, get_cve_details, check_kev_status, get_epss_score
- search_by_product, get_exploits, get_cwe_details, batch_search

### ATT&CK
- search_techniques, find_similar_techniques, get_technique_details
- get_technique_badges, search_threat_actors, find_similar_threat_actors
- get_group_profile

### ATLAS (AI/ML Threats)
- search_atlas_techniques, find_similar_atlas_techniques
- get_atlas_technique_details, search_atlas_case_studies
- find_similar_atlas_case_studies

### CAPEC (Attack Patterns)
- search_capec_patterns, find_similar_capec_patterns
- get_capec_pattern_details, search_capec_mitigations
- find_similar_capec_mitigations

### CWE (Weaknesses)
- search_cwe_weaknesses, find_similar_cwe_weaknesses
- get_cwe_weakness_details, search_by_external_mapping
- get_cwe_hierarchy, find_weaknesses_for_capec

### D3FEND (Defenses)
- search_defenses, find_similar_defenses, get_defense_details
- get_defenses_for_attack, get_attack_coverage

### Cloud Security
- search_cloud_services, get_cloud_service_security
- compare_cloud_services, get_shared_responsibility

### System
- get_data_freshness

## Troubleshooting

### Claude Desktop Not Connecting

1. Check logs in Claude Desktop's Developer Tools
2. Verify Python path: `which python3`
3. Test manually: `python3 -m cve_mcp --mode stdio`
4. Check environment variables in config

### Database Connection Issues

```bash
# Test database connection
python -c "from cve_mcp.config import get_settings; print(get_settings().database_url)"

# Check PostgreSQL is running
docker ps | grep postgres
```

### Redis Connection Issues

```bash
# Test Redis connection
python -c "from cve_mcp.config import get_settings; print(get_settings().redis_url)"

# Check Redis is running
docker ps | grep redis
```

### Import Errors

```bash
# Reinstall in development mode
pip install -e .

# Verify installation
python -c "import cve_mcp; print(cve_mcp.__file__)"
```

## Environment Variables

Required:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string

Optional:
- `OPENAI_API_KEY`: For semantic search tools (find_similar_*)
- `NVD_API_KEY`: For faster NVD sync (optional, rate limited without)
- `LOG_LEVEL`: DEBUG, INFO, WARNING, ERROR (default: INFO)

## Support

- GitHub Issues: https://github.com/Ansvar-Systems/Threat-Intel-MCP/issues
- Documentation: See `MCP_IMPLEMENTATION.md` for technical details
- Design Doc: `docs/plans/2026-02-07-mcp-protocol-compliance-design.md`
