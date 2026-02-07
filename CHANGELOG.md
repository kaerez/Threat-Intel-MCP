# Changelog

All notable changes to the Threat Intelligence MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-02-07

### Added - MCP Protocol Compliance (P0)

- **Official MCP Python SDK integration** (`mcp>=1.26.0`)
  - Full JSON-RPC 2.0 protocol implementation
  - stdio transport for native MCP clients (Claude Desktop, Cursor, etc.)
  - Tool registration and discovery via `tools/list`
  - Tool execution via `tools/call`
- **Multi-mode server operation**
  - `--mode stdio`: Official MCP protocol over stdio transport
  - `--mode http`: Custom HTTP wrapper for Ansvar platform (backward compatible)
  - `--mode both`: Dual-mode for development/testing
- **Layered architecture**
  - MCP Protocol Layer: Official SDK handling JSON-RPC 2.0
  - Core Business Logic: 41 unchanged tool handlers
  - HTTP Wrapper: FastAPI endpoints wrapping same logic

### Added - GCP Cloud Security Completion (P2)

- **Real GCP API integration** replacing placeholders
  - Google Cloud Organization Policy API client
  - Authentic constraint data for 50+ GCP services
  - Service-specific security controls (encryption, access, networking)
- **Cross-provider parity**
  - AWS: 55 services, Azure: 50 services, GCP: 50 services
  - Consistent data model across all providers
  - Equivalence mapping (S3 ↔ Blob Storage ↔ Cloud Storage)

### Changed - Documentation Fixes (P1)

- **README.md**
  - Updated MCP usage examples with stdio, http, and both modes
  - Added Cloud Security tools (4 tools) to tools table
  - Updated architecture diagram to show MCP SDK + HTTP wrapper layers
  - Corrected tool count from 37 to 41
  - Updated version references to 1.3.0
- **SETUP.md**
  - Added MCP stdio mode configuration examples
  - Added Cloud Security sync task documentation
  - Updated tool count to 41 across 8 categories
  - Added troubleshooting section for MCP modes
  - Added direct execution option for non-Docker setups
- **SECURITY.md**
  - Added Cloud Security data sources (AWS/Azure/GCP)
  - Verified all security claims match actual implementation
  - All listed CI/CD tools confirmed present in workflows

### Changed - Test Suite Overhaul (P2)

- **MCP protocol tests**
  - stdio transport integration tests
  - JSON-RPC 2.0 message format validation
  - Tool discovery and execution tests
- **HTTP wrapper tests**
  - Actual HTTP call integration tests
  - Backward compatibility verification
  - ThreatIntelClient contract validation
- **Updated assertions**
  - Tool count expectations: 36 → 41
  - Dual-mode testing (stdio + HTTP simultaneously)

### Technical Details

**Breaking Changes:** None - Full backward compatibility maintained
- Ansvar platform ThreatIntelClient continues to work unchanged
- All 25 agent-facing tools return identical responses
- HTTP endpoints `/mcp/tools` and `/mcp/tools/call` unchanged

**Dependencies:**
- Added: `mcp>=1.26.0` (official MCP Python SDK)
- Updated: `google-cloud-org-policy>=1.10.0` (GCP real API)

**Tool Count by Module:**
- CVE Intelligence: 8 tools
- ATT&CK: 7 tools
- ATLAS: 5 tools
- CAPEC: 5 tools
- CWE: 6 tools
- D3FEND: 5 tools
- Cloud Security: 4 tools
- System: 1 tool
- **Total: 41 tools**

**Architecture Highlights:**
- MCP server uses official SDK (`mcp.server.Server`)
- Business logic unchanged from 1.2.x
- HTTP wrapper calls same handlers as MCP layer
- Zero duplication of business logic

## [1.2.1] - 2026-02-06

### Fixed

- PostgreSQL enum type naming mismatches (cloud_provider_enum vs cloudproviderenum)
- Cloud Security database schema migrations (012)
- Complete bug pattern catalog in project memory

## [1.2.0] - 2026-02-06

### Added

- Cloud Security module with AWS, Azure, GCP service properties
- Service equivalence mapping (cross-provider comparison)
- Shared responsibility model breakdown
- Quality-first architecture with source provenance
- 4 new MCP tools: search_cloud_services, get_cloud_service_security, compare_cloud_services, get_shared_responsibility

### Fixed

- Complete overhaul of 22 critical bug patterns (see docs/memory/bugs-fixed.md)
- AsyncSessionLocal + Celery prefork event loop mismatch
- NVD API duplicate references
- Data dependency ordering (KEV/EPSS require CVE first)
- CVE description_vector TSVECTOR never populated
- CWE XML namespace parsing
- Ansvar client parameter name mismatches (18 fixes)

## [1.1.0] - 2026-02-05

### Added

- MITRE ATT&CK module with semantic search
- MITRE ATLAS module (AI/ML security)
- MITRE CAPEC module (attack patterns)
- MITRE CWE module (software weaknesses)
- MITRE D3FEND module (defensive countermeasures)
- AI-powered semantic search across all modules
- Cross-framework correlation (CVE ↔ ATT&CK ↔ CWE ↔ CAPEC ↔ D3FEND)

## [1.0.0] - 2026-01-30

### Added

- Initial release with CVE intelligence
- NVD API 2.0 integration
- CISA KEV catalog tracking
- FIRST EPSS scores
- ExploitDB references
- PostgreSQL + pgvector database
- Redis caching layer
- Celery background sync
- Docker deployment
- 8 CVE intelligence tools

---

## Version History

- **1.3.0** (2026-02-07): MCP protocol compliance + GCP completion + docs fixes
- **1.2.1** (2026-02-06): Cloud Security database fixes
- **1.2.0** (2026-02-06): Cloud Security module + 22 bug fixes
- **1.1.0** (2026-02-05): MITRE frameworks (ATT&CK, ATLAS, CAPEC, CWE, D3FEND)
- **1.0.0** (2026-01-30): Initial CVE intelligence release

---

## Links

- [GitHub Repository](https://github.com/Ansvar-Systems/Threat-Intel-MCP)
- [Design Document](./DESIGN.md)
- [Setup Guide](./docs/SETUP.md)
- [Architecture Decisions](./docs/architecture/)
