# CVE MCP Server - Setup Guide

Complete guide for deploying and configuring the CVE + Exploit Intelligence MCP Server.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Server Deployment](#server-deployment)
3. [MCP Client Configuration](#mcp-client-configuration)
4. [Initial Data Sync](#initial-data-sync)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **RAM:** 8 GB minimum (PostgreSQL database)
- **Disk:** 10 GB free space (6 GB for database + Docker images)
- **OS:** Linux, macOS, or Windows with WSL2
- **Docker:** Version 20.10+ with Docker Compose

### Optional

- **NVD API Key:** Higher rate limits for sync operations
  - Get free key: https://nvd.nist.gov/developers/request-an-api-key
  - Without key: 5 requests/30 seconds (slow sync)
  - With key: 50 requests/30 seconds (recommended)

- **OpenAI API Key:** Required for AI-powered semantic similarity search (`find_similar_*` tools)
  - All 6 `find_similar_*` tools use OpenAI embeddings for semantic matching
  - Without key: keyword search tools still work; semantic search returns an error
  - Set via `OPENAI_API_KEY` environment variable

---

## Server Deployment

### 1. Clone Repository

```bash
git clone https://github.com/Ansvar-Systems/Threat-Intel-MCP.git
cd Threat-Intel-MCP
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set:

```bash
# Required
POSTGRES_PASSWORD=your_secure_password_here

# Optional but recommended
NVD_API_KEY=your_nvd_api_key_here

# Optional: CORS origins (defaults to localhost)
CORS_ORIGINS=http://localhost,http://localhost:*,http://127.0.0.1,http://127.0.0.1:*
```

### 3. Start Services

```bash
# Start all services (PostgreSQL, Redis, MCP server, Celery)
docker-compose up -d

# Check all containers are running
docker-compose ps
```

Expected output:
```
NAME                  STATUS              PORTS
cve-mcp-server        Up (healthy)        0.0.0.0:8307->8307/tcp
cve-mcp-postgres      Up (healthy)        0.0.0.0:5432->5432/tcp
cve-mcp-redis         Up (healthy)        0.0.0.0:6379->6379/tcp
cve-mcp-worker        Up
cve-mcp-beat          Up
```

### 4. Run Database Migrations

```bash
docker-compose exec cve-mcp-server alembic upgrade head
```

---

## Initial Data Sync

The MCP server requires local CVE data. Choose sync strategy:

### Option A: Full Initial Sync (Recommended)

Syncs entire NVD database (331,000+ CVEs) and all MITRE frameworks. Takes 6-8 hours for NVD, plus 5-15 minutes per MITRE module.

```bash
# NVD CVE data (6-8 hours)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_nvd.sync_nvd_full

# CISA KEV catalog (1-2 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_cisa_kev.sync_cisa_kev

# EPSS scores (5-10 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_epss.sync_epss_scores

# ExploitDB references (2-3 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_exploitdb.sync_exploitdb

# MITRE ATT&CK (2-3 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_attack.sync_attack

# MITRE ATLAS (1-2 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_atlas.sync_atlas

# MITRE CAPEC (2-3 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_capec.sync_capec

# MITRE CWE (3-5 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_cwe.sync_cwe

# MITRE D3FEND (2-3 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_d3fend.sync_d3fend

# Cloud Security (AWS/Azure/GCP) (3-5 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_cloud_security.sync_cloud_security
```

Monitor progress:
```bash
docker-compose logs -f celery-worker
```

### Option B: Delta Sync (Faster, Recent CVEs Only)

Syncs CVEs from last 30 days. Takes 10-15 minutes.

```bash
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_nvd.sync_nvd_recent
```

**Note:** Delta sync is suitable for testing. Production deployments should use full sync.

### Automatic Daily Sync

Celery Beat automatically runs syncs on schedule:

**Daily (02:00-04:00 UTC):**
- NVD delta updates (last 30 days)
- CISA KEV updates
- EPSS score updates
- ExploitDB updates

**Weekly (Sunday 04:00-06:00 UTC):**
- MITRE ATT&CK, ATLAS, CAPEC, CWE, D3FEND

No manual intervention needed after initial sync.

---

## MCP Client Configuration

### Claude Desktop (macOS/Windows)

#### 1. Locate Configuration File

**macOS:**
```bash
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

#### 2. Add MCP Server Configuration

**Option A: stdio mode (Official MCP Protocol - Recommended)**

Uses JSON-RPC 2.0 over stdio transport per the official MCP specification:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "docker",
      "args": ["exec", "-i", "cve-mcp-server", "python", "-m", "cve_mcp", "--mode", "stdio"],
      "env": {}
    }
  }
}
```

**Option B: HTTP mode (Custom wrapper)**

Uses HTTP REST endpoints wrapping the same MCP tools. Useful for web-based clients:

```json
{
  "mcpServers": {
    "threat-intel": {
      "url": "http://localhost:8307",
      "transport": "http"
    }
  }
}
```

**Option C: Direct execution (if not using Docker)**

If running the server locally without Docker:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "python",
      "args": ["-m", "cve_mcp", "--mode", "stdio"],
      "env": {
        "POSTGRES_HOST": "localhost",
        "REDIS_HOST": "localhost"
      }
    }
  }
}
```

**Option C: Multiple Servers**

```json
{
  "mcpServers": {
    "cve-exploit": {
      "url": "http://localhost:8307",
      "transport": "http"
    },
    "other-mcp-server": {
      "command": "npx",
      "args": ["other-server"]
    }
  }
}
```

#### 3. Restart Claude Desktop

1. Quit Claude Desktop completely
2. Reopen Claude Desktop
3. Look for 🔌 icon in bottom-right
4. Verify "cve-exploit" appears in MCP servers list

### Cursor IDE

Add to `.cursor/mcp.json` in your workspace:

```json
{
  "mcpServers": {
    "cve-exploit": {
      "url": "http://localhost:8307",
      "transport": "http"
    }
  }
}
```

### Other MCP Clients

Any MCP client supporting HTTP transport can connect to:
```
http://localhost:8307
```

---

## Verification

### 1. Check Server Health

```bash
curl http://localhost:8307/health
```

Expected response:
```json
{
  "status": "healthy",
  "data_freshness": {
    "nvd_last_sync": "2026-01-31T08:00:00Z",
    "cisa_kev_last_sync": "2026-01-31T08:00:00Z",
    "epss_last_sync": "2026-01-31T08:00:00Z",
    "exploitdb_last_sync": "2026-01-31T08:00:00Z",
    "data_age_hours": 2
  },
  "database": {
    "connected": true,
    "total_cves": 242156
  },
  "cache": {
    "connected": true,
    "cache_hit_rate": 0.85
  }
}
```

### 2. List Available Tools

```bash
curl http://localhost:8307/mcp/tools
```

Should return 41 MCP tools across 8 categories:

**CVE Intelligence (8 tools):** search_cve, get_cve_details, check_kev_status, get_epss_score, search_by_product, get_exploits, get_cwe_details, batch_search

**ATT&CK (7 tools):** search_techniques, find_similar_techniques, get_technique_details, get_technique_badges, search_threat_actors, find_similar_threat_actors, get_group_profile

**ATLAS (5 tools):** search_atlas_techniques, find_similar_atlas_techniques, get_atlas_technique_details, search_atlas_case_studies, find_similar_atlas_case_studies

**CAPEC (5 tools):** search_capec_patterns, find_similar_capec_patterns, get_capec_pattern_details, search_capec_mitigations, find_similar_capec_mitigations

**CWE (6 tools):** search_cwe_weaknesses, find_similar_cwe_weaknesses, get_cwe_weakness_details, search_by_external_mapping, get_cwe_hierarchy, find_weaknesses_for_capec

**D3FEND (5 tools):** search_defenses, find_similar_defenses, get_defense_details, get_defenses_for_attack, get_attack_coverage

**Cloud Security (4 tools):** search_cloud_services, get_cloud_service_security, compare_cloud_services, get_shared_responsibility

**System (1 tool):** get_data_freshness

### 3. Test Tool Call

```bash
curl -X POST http://localhost:8307/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_cve",
    "arguments": {
      "keyword": "apache",
      "cvss_min": 9.0,
      "limit": 5
    }
  }'
```

Should return CVE records with CVSS scores > 9.0.

### 3b. Test Data Freshness

```bash
curl -X POST http://localhost:8307/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "get_data_freshness", "arguments": {}}'
```

Should return sync status for all 9 data sources. Verify all show `"status": "current"`.

### 4. Test in Claude Desktop

Open Claude Desktop and ask:

**Example 1: Search**
```
Find critical vulnerabilities in Apache HTTP Server with CVSS > 9
```

**Example 2: Product Search**
```
What CVEs affect nginx version 1.20.0?
```

**Example 3: KEV Check**
```
Is CVE-2021-44228 (Log4Shell) in the CISA KEV catalog?
```

**Example 4: EPSS Score**
```
What's the EPSS score for CVE-2021-44228?
```

Claude should use the MCP tools to answer these questions.

---

## Troubleshooting

### Server Won't Start

**Check Docker containers:**
```bash
docker-compose ps
docker-compose logs cve-mcp-server
```

**Common issues:**
- Port 8307 already in use → Change `MCP_PORT` in `.env`
- PostgreSQL not ready → Wait for health check, check `docker-compose logs postgres`
- Redis not ready → Check `docker-compose logs redis`

### Claude Desktop Can't Connect

**Check server is accessible:**
```bash
curl http://localhost:8307/health
```

**Check Claude Desktop logs:**

**macOS:**
```bash
tail -f ~/Library/Logs/Claude/mcp*.log
```

**Windows:**
```
%LOCALAPPDATA%\Claude\logs\mcp*.log
```

**Common issues:**
- MCP server not in config → Verify `claude_desktop_config.json`
- Wrong URL → Should be `http://localhost:8307`
- Docker container stopped → Run `docker-compose up -d`

### Sync Taking Too Long

**With NVD API key:** 6-8 hours (normal)
**Without API key:** 20-30 hours (rate limited)

**Check sync progress:**
```bash
docker-compose logs -f celery-worker | grep -E "(Progress|Synced|CVE-)"
```

**Interrupt and resume:**
Sync is resumable. Press Ctrl+C and restart sync - it will continue from where it left off.

### Database Errors

**Reset database (WARNING: Deletes all data):**
```bash
docker-compose down -v
docker-compose up -d
docker-compose exec cve-mcp-server alembic upgrade head
# Re-run initial sync
```

### Out of Memory

PostgreSQL needs ~6 GB for full CVE database.

**Check Docker memory limit:**
```bash
docker stats
```

**Increase Docker Desktop memory:**
- macOS/Windows: Docker Desktop → Settings → Resources → Memory
- Allocate at least 8 GB

### CORS Errors

If accessing from non-localhost origins:

Edit `.env`:
```bash
CORS_ORIGINS=http://your-domain.com,http://localhost,http://localhost:*
```

Restart server:
```bash
docker-compose restart cve-mcp-server
```

### MCP Mode Issues

**stdio mode not working in Claude Desktop:**

Check Docker exec permissions:
```bash
# Test manually
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  docker exec -i cve-mcp-server python -m cve_mcp --mode stdio
```

Expected: JSON-RPC 2.0 response with tools list

**HTTP mode connection refused:**

Check server is running in HTTP mode:
```bash
docker-compose logs cve-mcp-server | grep "mode"
```

Should show `mode=http`. If not, update docker-compose.yml:
```yaml
services:
  cve-mcp-server:
    command: python -m cve_mcp --mode http
```

**Both modes needed (development):**

Run server in dual mode:
```bash
docker-compose exec cve-mcp-server python -m cve_mcp --mode both
```

This runs stdio and HTTP simultaneously on different threads.

---

## Advanced Configuration

### Custom Port

Edit `.env`:
```bash
MCP_PORT=9000
```

Update `docker-compose.yml` ports:
```yaml
ports:
  - "9000:9000"  # Change from 8307
```

Update Claude Desktop config:
```json
{
  "mcpServers": {
    "cve-exploit": {
      "url": "http://localhost:9000"
    }
  }
}
```

### Production Deployment

For production environments:

1. **Use secrets management:**
   - Store `POSTGRES_PASSWORD` in AWS Secrets Manager / HashiCorp Vault
   - Inject via environment variables

2. **Enable SSL:**
   - Use reverse proxy (nginx/Traefik) with Let's Encrypt
   - Configure PostgreSQL SSL connections

3. **Scale Celery workers:**
   ```yaml
   celery-worker:
     deploy:
       replicas: 4
   ```

4. **Monitor with Prometheus:**
   - Add `/metrics` endpoint
   - Track query latency, cache hit rate, sync status

5. **Backup database:**
   ```bash
   docker-compose exec postgres pg_dump -U cve_user cve_mcp > backup.sql
   ```

### Air-Gapped Deployment

For environments without internet access:

1. **Initial sync on internet-connected machine:**
   ```bash
   docker-compose up -d
   # Run full sync
   docker-compose exec postgres pg_dump -U cve_user cve_mcp > cve_data.sql
   ```

2. **Transfer to air-gapped environment:**
   - Copy `cve_data.sql`
   - Copy Docker images: `docker save > cve-mcp-images.tar`

3. **Restore on air-gapped machine:**
   ```bash
   docker load < cve-mcp-images.tar
   docker-compose up -d
   docker-compose exec postgres psql -U cve_user cve_mcp < cve_data.sql
   ```

4. **Disable external sync:**
   ```bash
   docker-compose stop celery-beat
   ```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/Ansvar-Systems/Threat-Intel-MCP/issues
- Internal Ansvar: Platform Engineering team

## Next Steps

- See [README.md](../README.md) for architecture overview
- See [DESIGN.md](../DESIGN.md) for complete technical specification
- See [.github/SECURITY-SETUP.md](../.github/SECURITY-SETUP.md) for CI/CD setup
