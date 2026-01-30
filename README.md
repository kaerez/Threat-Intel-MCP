# CVE + Exploit Intelligence MCP Server

A **Tier 1 (offline-first)** Model Context Protocol (MCP) server providing comprehensive CVE vulnerability data, CISA Known Exploited Vulnerabilities (KEV), EPSS exploit prediction scores, and public exploit tracking.

## 🎯 Purpose

This MCP server enables AI assistants (Claude, Cursor, etc.) to access real-time vulnerability intelligence without external API calls during queries, making it suitable for air-gapped and highly regulated environments (banking, healthcare, government).

## ✨ Key Features

- ✅ **200,000+ CVE records** with full CVSS scoring (v2, v3, v4)
- ✅ **CISA KEV integration** - Track actively exploited vulnerabilities
- ✅ **EPSS scoring** - Exploit prediction likelihood (FIRST.org)
- ✅ **CPE product mappings** - Which software versions are vulnerable
- ✅ **Exploit tracking** - Metasploit, ExploitDB, GitHub PoCs
- ✅ **Offline-first architecture** - All queries run against local PostgreSQL
- ✅ **Sub-50ms latency** - Indexed database queries
- ✅ **Air-gap compatible** - Daily background sync, no runtime internet dependency

## 📋 Quick Start

See **[DESIGN.md](./DESIGN.md)** for complete specifications including:
- Database schema (9 tables with full DDL)
- API endpoints (8 MCP tools)
- Sync services (daily NVD/KEV/EPSS updates)
- Deployment guide (Docker Compose)
- Performance targets
- Security & compliance

## 🏗️ Architecture

**Type:** Tier 1 MCP (Offline-First)
**Pattern:** Based on [Ansvar Sanctions MCP](https://github.com/Ansvar-Systems/Sanctions-MCP) architecture

```
┌─────────────────────────────────────────┐
│  MCP Client (Ansvar AI / Claude)        │
└─────────────┬───────────────────────────┘
              │ JSON-RPC 2.0
              ▼
┌─────────────────────────────────────────┐
│  HTTP/SSE Transport (Port 8307)         │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  CVE MCP Server (FastAPI)               │
│  - search_cve                           │
│  - get_cve_details                      │
│  - check_kev_status                     │
│  - get_epss_score                       │
│  - search_by_product                    │
│  - get_exploits                         │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  PostgreSQL 15 (~6 GB)                  │
│  + Redis Cache                          │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  Daily Sync (02:00-04:00 UTC)           │
│  - NVD API 2.0                          │
│  - CISA KEV                             │
│  - FIRST EPSS                           │
│  - ExploitDB                            │
└─────────────────────────────────────────┘
```

## 🚀 Deployment

```bash
# 1. Clone repository
git clone https://github.com/Ansvar-Systems/CVE-MCP.git
cd CVE-MCP

# 2. Configure environment
cp .env.example .env
# Edit .env with your NVD API key (optional but recommended)

# 3. Start services
docker-compose up -d

# 4. Run initial sync (6-8 hours)
docker-compose exec celery-worker celery -A tasks call tasks.sync_nvd_full

# 5. Verify
curl http://localhost:8307/health
```

## 📊 MCP Tools

| Tool | Description | Example |
|------|-------------|---------|
| `search_cve` | Search CVEs by keyword, CVSS score, severity | Search for "authentication bypass" with CVSS > 7 |
| `get_cve_details` | Get full CVE record with references, CPE, exploits | Get complete details for CVE-2024-1234 |
| `check_kev_status` | Check if CVE is in CISA KEV catalog | Is CVE-2024-1234 actively exploited? |
| `get_epss_score` | Get exploit prediction score (0-1) | What's the likelihood CVE-2024-1234 will be exploited? |
| `search_by_product` | Find CVEs affecting specific product/version | Find vulnerabilities in Apache 2.4.49 |
| `get_exploits` | Get public exploit code references | Show Metasploit/ExploitDB exploits for CVE-2024-1234 |
| `get_cwe_details` | Get CWE weakness information | Get details for CWE-79 (XSS) |
| `batch_search` | Bulk CVE lookup (max 100) | Get details for 50 CVEs in one query |

## 📈 Performance

| Metric | Target |
|--------|--------|
| Query latency (p95) | < 50ms |
| Full-text search | < 100ms |
| Batch queries (100 CVEs) | < 500ms |
| Daily sync duration | < 60 min |
| Availability | 99.99% |
| Database size | ~6 GB |

## 🔒 Security

- ✅ Offline queries (no external API calls)
- ✅ 7-year audit trail (query logging)
- ✅ Air-gap deployment ready
- ✅ TLS 1.3 for sync operations
- ✅ PostgreSQL SSL connections
- ✅ Rate limiting (100 req/min per client)

## 📚 Documentation

- **[DESIGN.md](./DESIGN.md)** - Complete design specification (71 pages)
- **[docs/architecture/](./docs/architecture/)** - Architecture decision records
  - Tier 1 offline-first assessment
  - Build vs. buy analysis

## 🏢 Use Cases

### STRIDE Threat Modeling (Ansvar AI)
```python
# Enrich threat scenarios with current CVE data
result = await mcp_client.call_tool(
    provider="cve-exploit",
    tool="search_cve",
    arguments={
        "keyword": "authentication bypass",
        "cvss_min": 7.0,
        "has_kev": True
    }
)
# Returns CVEs with active exploitation, EPSS scores, exploit availability
```

### CVSS Risk Scoring
```python
# Get exploit prediction score for accurate risk assessment
epss = await mcp_client.call_tool(
    provider="cve-exploit",
    tool="get_epss_score",
    arguments={"cve_id": "CVE-2024-1234"}
)
# Returns: {"epss_score": 0.92, "percentile": 0.98}
# Interpretation: Top 2% most likely to be exploited in next 30 days
```

### Product Vulnerability Assessment
```python
# Find all CVEs affecting a specific product version
vulns = await mcp_client.call_tool(
    provider="cve-exploit",
    tool="search_by_product",
    arguments={
        "product_name": "apache",
        "vendor": "apache",
        "version": "2.4.49"
    }
)
# Returns CVEs with KEV status, exploits, CVSS scores
```

## 🛠️ Development

**Technology Stack:**
- Python 3.11+
- FastAPI (async web framework)
- PostgreSQL 15 (with full-text search)
- Redis 7 (caching)
- Celery (background tasks)
- SQLAlchemy 2.0 (async ORM)
- Pydantic 2.x (validation)

**Development Roadmap:** See [DESIGN.md § Development Roadmap](./DESIGN.md#development-roadmap)

**Estimated Build Time:** 6 weeks (2 engineers)

## 📊 Data Sources

| Source | Type | Update Frequency | Records |
|--------|------|------------------|---------|
| **NVD API 2.0** | Public | Daily (delta), Monthly (full) | 240,000+ CVEs |
| **CISA KEV** | Public | Daily | 1,200+ exploited CVEs |
| **FIRST EPSS** | Public | Daily | 200,000+ scores |
| **ExploitDB** | Public | Weekly | 15,000+ exploits |

All data sources are **free and public** - no API keys required (NVD API key optional for higher rate limits).

## 🌐 Related Projects

- **[Ansvar Sanctions MCP](https://github.com/Ansvar-Systems/Sanctions-MCP)** - Tier 1 architecture reference
- **[Ansvar MCP Registry](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/mcp-server-registry.md)** - All Ansvar MCPs
- **[MCP Quality Standard](https://github.com/Ansvar-Systems/Ansvar-Architecture-Documentation/blob/main/docs/mcp-quality-standard.md)** - Development standards

## 📝 Status

**Current:** Design Complete, Ready for Implementation
**Next Steps:**
1. ✅ Repository created
2. ✅ Design specification complete
3. 🔄 Database schema implementation
4. 🔄 Sync services development
5. 🔄 MCP server implementation

## 🤝 Contributing

This is an internal Ansvar Systems project. For questions or contributions, contact the Platform Engineering team.

## 📄 License

Internal Ansvar Systems project. See [Ansvar MCP Suite License](https://github.com/Ansvar-Systems/security-controls-mcp/blob/main/LICENSE) for reference.

---

**Architecture Decision:** See [docs/architecture/2026-01-30-mcp-offline-first-assessment.md](./docs/architecture/2026-01-30-mcp-offline-first-assessment.md) for why we chose Tier 1 (offline-first) architecture over API-dependent design.

**Build vs. Buy:** See [docs/architecture/2026-01-30-mcp-build-vs-buy-analysis.md](./docs/architecture/2026-01-30-mcp-build-vs-buy-analysis.md) for analysis of existing MCP servers and decision to build custom.
