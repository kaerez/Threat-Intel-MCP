# Threat Intelligence MCP Server

## Overview
Python MCP server providing offline-first threat intelligence with semantic search across CVE, MITRE ATT&CK, ATLAS, CAPEC, CWE, D3FEND, OWASP LLM Top 10, and cloud security (AWS/Azure/GCP). Docker-deployed with PostgreSQL + pgvector.

## Architecture
- **Language:** Python 3.11+
- **Framework:** FastAPI (HTTP) + MCP SDK (stdio)
- **Database:** PostgreSQL 15 with pgvector extension
- **Cache:** Redis 7
- **Task Queue:** Celery with Redis broker
- **Embeddings:** OpenAI text-embedding-3-small (optional)

## Directory Structure
- `src/cve_mcp/` - Main source code (module name is `cve_mcp` for backward compat)
  - `api/` - FastAPI HTTP wrapper, tool definitions, schemas
  - `mcp/` - MCP protocol implementation (server.py, transports.py)
  - `services/` - Business logic (database.py, cache.py, embeddings.py)
  - `models/` - SQLAlchemy ORM models
  - `tasks/` - Celery background sync tasks
  - `ingest/` - Data parsers (NVD, ATT&CK, ATLAS, CAPEC, CWE, D3FEND, cloud)
- `tests/` - pytest test suite
- `alembic/` - Database migrations (13 versions)
- `scripts/` - Utility scripts for data sync
- `.github/workflows/` - CI/CD (11 workflows)

## Key Conventions
- All database queries use SQLAlchemy ORM (parameterized, no raw SQL)
- Full-text search uses PostgreSQL `plainto_tsquery()` (safe from FTS injection)
- ILIKE patterns use `escape_like()` to prevent wildcard injection
- Tool definitions live in `src/cve_mcp/api/tools.py` (MCP_TOOLS list + TOOL_HANDLERS dict)
- Pydantic schemas in `src/cve_mcp/api/schemas.py` validate all inputs
- Both stdio and HTTP modes use identical business logic via MCPServerWrapper

## Commands
- `python -m cve_mcp.main --mode stdio` - MCP protocol (Claude Desktop, Cursor)
- `python -m cve_mcp.main --mode http` - HTTP API (port 8307)
- `python -m cve_mcp.main --mode mcp-http` - Streamable HTTP (universal MCP clients)
- `docker compose up` - Full stack (Postgres, Redis, MCP server, Celery)
- `pytest tests/ -v` - Run tests
- `ruff check src/ tests/` - Lint
- `mypy src/` - Type check

## Configuration
All settings via environment variables (see `.env.example`):
- `DATABASE_URL` - PostgreSQL connection
- `REDIS_URL` - Redis connection
- `OPENAI_API_KEY` - Enables semantic search (optional)
- `MCP_MODE` - stdio/http/mcp-http/both
- `MCP_PORT` - HTTP port (default 8307)

## Data Sources (11)
See `sources.yml` for complete provenance. Key sources:
- NVD (NIST) - CVE records
- CISA KEV - Exploited vulnerabilities
- EPSS (FIRST.org) - Exploit prediction scores
- MITRE ATT&CK/ATLAS/CAPEC/CWE/D3FEND - Threat frameworks
- AWS/Azure/GCP - Cloud security properties
- OWASP LLM Top 10 - AI/LLM-specific vulnerabilities

## Testing
- `pytest tests/ -v` - All tests
- `pytest tests/ -m fast` - Fast unit tests only
- `pytest tests/ -m integration` - Integration tests (requires services)
- Golden contract tests in `fixtures/golden-tests.json`

## Security
- 6-layer scanning: CodeQL, Semgrep, Trivy, Gitleaks, Socket, OSSF Scorecard
- No raw SQL - all queries via SQLAlchemy ORM
- Input validation via Pydantic with regex patterns
- LIKE/ILIKE patterns escaped with `escape_like()` utility
- CORS restricted to localhost by default

## Git Workflow

- **Never commit directly to `main`.** Always create a feature branch and open a Pull Request.
- Branch protection requires: verified signatures, PR review, and status checks to pass.
- Use conventional commit prefixes: `feat:`, `fix:`, `chore:`, `docs:`, etc.
