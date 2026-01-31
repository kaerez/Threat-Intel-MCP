# Threat Intelligence MCP Server

**Offline-first threat intelligence with semantic search for AI assistants.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://github.com/Ansvar-Systems/CVE-MCP/actions/workflows/test.yml/badge.svg)](https://github.com/Ansvar-Systems/CVE-MCP/actions/workflows/test.yml)
[![Security](https://github.com/Ansvar-Systems/CVE-MCP/actions/workflows/docker-security.yml/badge.svg)](https://github.com/Ansvar-Systems/CVE-MCP/actions/workflows/docker-security.yml)
[![Database](https://img.shields.io/badge/database-240K%2B%20CVEs-green)](docs/SETUP.md)

Query **240,000+ CVE records**, **700+ ATT&CK techniques**, **200+ ATLAS AI/ML techniques**, **550+ CAPEC attack patterns**, **140+ threat actors** with semantic similarity search — directly from Claude, Cursor, or any MCP-compatible client.

## Modules

This MCP server provides comprehensive threat intelligence through multiple integrated modules:

1. **CVE Intelligence** ✅ Production
   - 240,000+ CVE records with CVSS scoring
   - CISA KEV tracking (1,200+ actively exploited CVEs)
   - EPSS exploit prediction (200,000+ scores)
   - Exploit references (Metasploit, ExploitDB, GitHub PoCs)
   - **Semantic search**: "Find CVEs similar to this vulnerability description"

2. **MITRE ATT&CK** ✅ Production
   - 700+ techniques + sub-techniques with AI-powered semantic search
   - 14 tactics (kill chain phases)
   - 140+ threat actor groups with semantic attribution
   - 700+ software/tools with technique mappings
   - **Semantic search**: "Find techniques similar to this incident description"
   - **Dual search modes**: Traditional keyword (<50ms) + AI semantic (<100ms)

3. **MITRE ATLAS (AI/ML)** ✅ Production
   - 200+ AI/ML attack techniques with AI-powered semantic search
   - 14 tactics (ML attack kill chain)
   - 30+ real-world case studies with technique mappings
   - ML lifecycle filtering (data collection, training, deployment)
   - **Semantic search**: "Find techniques similar to this AI attack scenario"
   - **Dual search modes**: Traditional keyword (<50ms) + AI semantic (<100ms)

4. **MITRE CAPEC (Attack Patterns)** ✅ Production
   - 550+ attack patterns with AI-powered semantic search
   - 300+ mitigations with effectiveness ratings
   - 9 categories with hierarchical organization
   - Abstraction levels (Meta, Standard, Detailed)
   - CWE weakness mappings
   - ATT&CK technique mappings
   - **Semantic search**: "Find patterns similar to this attack description"
   - **Dual search modes**: Traditional keyword (<50ms) + AI semantic (<100ms)

5. **Threat Actors** 📋 Planned
   - APT groups
   - Ransomware gangs
   - Industry targeting
   - Attribution indicators

6. **Incident Intelligence** 📋 Planned
   - Recent breaches
   - Attack vectors
   - Lessons learned

## Key Features

- **240,000+ CVE records** — Full NVD dataset with CVSS, KEV, EPSS scoring
- **700+ ATT&CK techniques** — AI-powered semantic search for incident response
- **200+ ATLAS techniques** — AI/ML adversarial attack techniques with semantic search
- **30+ AI/ML case studies** — Real-world AI security incidents with technique mappings
- **550+ CAPEC patterns** 🆕 — Attack pattern enumeration with semantic search
- **300+ mitigations** 🆕 — Security controls mapped to attack patterns
- **140+ threat actor groups** — Semantic attribution based on observed TTPs
- **Dual search modes** — Traditional keyword (<50ms) + AI semantic (<100ms)
- **Cross-domain queries** — CVE ↔ ATT&CK ↔ ATLAS ↔ Threat Actors in single query
- **Offline-first** — All queries run against local PostgreSQL + pgvector
- **Sub-100ms latency** — Indexed database with vector similarity search
- **Monthly sync** — Automatic updates from NVD, MITRE, CISA, EPSS
- **RAG-ready** — <7 day freshness, eliminates 90-day staleness

Built by [Ansvar Systems](https://ansvar.eu) — Stockholm, Sweden

---

## Quick Start

### Installation

**Prerequisites:**
- Docker & Docker Compose
- 8 GB RAM minimum (for PostgreSQL)
- 10 GB disk space

**Step 1: Deploy Server**

```bash
git clone https://github.com/Ansvar-Systems/CVE-MCP.git
cd CVE-MCP
cp .env.example .env
docker-compose up -d

# Initial sync (6-8 hours for full NVD dataset)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call cve_mcp.tasks.sync_nvd.sync_nvd_full

# Verify server is running
curl http://localhost:8307/health
```

**Step 2: Configure Claude Desktop**

Add to your `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

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

Or use Docker exec method:

```json
{
  "mcpServers": {
    "cve-exploit": {
      "command": "docker",
      "args": ["exec", "cve-mcp-server", "python", "-m", "cve_mcp.main"],
      "env": {}
    }
  }
}
```

Restart Claude Desktop. You should see "cve-exploit" in the 🔌 menu.

**Step 3: Verify It Works**

```bash
# Check health
curl http://localhost:8307/health | jq

# Search for CVEs
curl -X POST http://localhost:8307/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_cve",
    "arguments": {"keyword": "apache", "cvss_min": 9.0, "limit": 3}
  }' | jq
```

**Detailed setup:** [docs/SETUP.md](./docs/SETUP.md)

---

## Upgrading from CVE-MCP

**Note:** This project was renamed from "CVE-MCP" to "Threat Intelligence MCP" to reflect its expanded scope. The module name remains `cve_mcp` and the CLI command remains `cve-mcp` for backward compatibility. No migration required for existing installations.

---

## Example Queries

Once connected, just ask naturally:

**CVE Intelligence:**
- *"Search for critical Apache vulnerabilities with CVSS > 9"*
- *"Is Log4Shell (CVE-2021-44228) in the CISA KEV catalog?"*
- *"What's the EPSS exploit prediction score for CVE-2021-44228?"*
- *"Find all CVEs affecting nginx version 1.20.0"*
- *"Show me public exploits for CVE-2021-44228"*

**ATT&CK Semantic Search:** 🆕
- *"Find techniques similar to: attacker sent phishing email with malicious PDF that executed PowerShell"*
- *"Which threat actors target financial institutions with supply chain attacks?"*
- *"Get detection methods for technique T1566.001 (Spearphishing Attachment)"*
- *"Find all persistence techniques for Windows platforms"*

**Cross-Domain Queries:**
- *"Get CVE-2021-44228 details and find ATT&CK techniques for remote code execution exploits"*
- *"Which threat actors are known to exploit authentication bypass CVEs?"*

**AI/ML Security (ATLAS):**
- *"Find techniques similar to: attacker poisoned training data to create backdoor in image classifier"*
- *"Search for model evasion and adversarial input techniques"*
- *"Find AI security incidents similar to autonomous vehicle sensor attacks"*
- *"What ATLAS techniques apply to LLM prompt injection attacks?"*

**Attack Patterns (CAPEC):** 🆕
- *"Find patterns similar to: SQL injection through web form to extract user credentials"*
- *"Search for injection attack patterns with high severity"*
- *"Find mitigations for buffer overflow attacks"*
- *"What CAPEC patterns relate to CWE-79 (XSS)?"*

---

## What's Included

**CVE Intelligence:**
- **240,000+ CVE Records** — Full NVD dataset with CVSS v2/v3/v4 scoring
- **1,200+ CISA KEV Entries** — Track actively exploited vulnerabilities
- **200,000+ EPSS Scores** — Exploit prediction likelihood (0-1 scale)
- **15,000+ Exploit References** — Metasploit, ExploitDB, GitHub PoCs
- **CPE Product Mappings** — Which software versions are vulnerable

**ATT&CK Intelligence:**
- **700+ ATT&CK Techniques** — Enterprise, Mobile, ICS with AI semantic search
- **140+ Threat Actor Groups** — APT groups with TTP attribution
- **14 Tactics** — Full kill chain from Initial Access to Impact
- **700+ Software/Tools** — Malware and tool mappings

**ATLAS Intelligence (AI/ML Security):**
- **200+ ATLAS Techniques** — Adversarial ML attacks with AI semantic search
- **14 ML Tactics** — ML attack kill chain from Reconnaissance to Impact
- **30+ Case Studies** — Real-world AI/ML security incidents
- **ML Lifecycle Filtering** — Data collection, training, deployment stages

**CAPEC Intelligence (Attack Patterns):** 🆕
- **550+ Attack Patterns** — Common attack patterns with AI semantic search
- **300+ Mitigations** — Security controls with effectiveness ratings
- **9 Categories** — Logical groupings (Injection, Social Engineering, etc.)
- **CWE/ATT&CK Mappings** — Cross-framework relationships

**Architecture:**
- **Offline-First** — All queries run against local PostgreSQL + pgvector
- **Sub-100ms Latency** — Indexed database with vector similarity search
- **Monthly Sync** — Background updates from NVD, MITRE, CISA, EPSS

**Detailed coverage:** [DESIGN.md](./DESIGN.md)

---

## Available Tools

### CVE Intelligence (8 tools)

| Tool | Description | Example Query |
|------|-------------|---------------|
| `search_cve` | Search CVEs by keyword, CVSS score, severity | "Find critical Apache vulnerabilities" |
| `get_cve_details` | Get full CVE record with references, CPE, exploits | "Show me details for CVE-2021-44228" |
| `check_kev_status` | Check if CVE is in CISA KEV catalog | "Is Log4Shell in the KEV catalog?" |
| `get_epss_score` | Get exploit prediction score (0-1) | "What's the EPSS score for CVE-2021-44228?" |
| `search_by_product` | Find CVEs affecting specific product/version | "Find CVEs in nginx 1.20.0" |
| `get_exploits` | Get public exploit code references | "Show exploits for CVE-2021-44228" |
| `get_cwe_details` | Get CWE weakness information | "Explain CWE-79" |
| `batch_search` | Bulk CVE lookup (max 100) | "Get details for these 10 CVEs..." |

### ATT&CK Intelligence (7 tools)

| Tool | Description | Example Query |
|------|-------------|---------------|
| `search_techniques` | Traditional keyword search for techniques | "Find all phishing techniques for Windows" |
| `find_similar_techniques` | AI semantic search for techniques | "Attacker used malicious PDF to run PowerShell" |
| `get_technique_details` | Get full technique details + detection methods | "Get details for T1566.001" |
| `get_technique_badges` | Get ATT&CK Navigator badge URLs | "Get badges for T1566, T1059.001" |
| `search_threat_actors` | Traditional keyword search for threat actors | "Find APT groups using spearphishing" |
| `find_similar_threat_actors` | AI semantic search for threat actor attribution | "APT targeting finance with custom malware" |
| `get_group_profile` | Get full threat actor profile + TTPs | "Get profile for APT32 (G0050)" |

### ATLAS Intelligence (5 tools)

| Tool | Description | Example Query |
|------|-------------|---------------|
| `search_atlas_techniques` | Traditional keyword search for AI/ML techniques | "Find data poisoning techniques for training" |
| `find_similar_atlas_techniques` | AI semantic search for AI/ML attack techniques | "Attacker injected adversarial examples into training data" |
| `get_atlas_technique_details` | Get full technique details + detection/mitigation | "Get details for AML.T0020" |
| `search_atlas_case_studies` | Search real-world AI/ML security incidents | "Find case studies about autonomous vehicles" |
| `find_similar_atlas_case_studies` | AI semantic search for similar AI incidents | "Object detection fooled by adversarial patches" |

### CAPEC Intelligence (5 tools) 🆕

| Tool | Description | Example Query |
|------|-------------|---------------|
| `search_capec_patterns` | Traditional keyword search for attack patterns | "Find SQL injection patterns with high severity" |
| `find_similar_capec_patterns` | AI semantic search for attack patterns | "Attacker manipulates input to inject SQL commands" |
| `get_capec_pattern_details` | Get full pattern details + prerequisites/mitigations | "Get details for CAPEC-66" |
| `search_capec_mitigations` | Search security controls and countermeasures | "Find mitigations for injection attacks" |
| `find_similar_capec_mitigations` | AI semantic search for mitigations | "Input validation to prevent injection" |

---

## Architecture

**Type:** Tier 1 MCP (Offline-First)
**Pattern:** Based on [Ansvar Sanctions MCP](https://github.com/Ansvar-Systems/Sanctions-MCP) architecture

```
┌─────────────────────────────────────────┐
│  MCP Client (Claude / Cursor)           │
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
│  - 25 MCP tools                         │
│  - Query routing & validation           │
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
│  - MITRE ATT&CK                         │
│  - MITRE ATLAS                          │
│  - MITRE CAPEC                          │
└─────────────────────────────────────────┘
```

### Why Offline-First?

Traditional CVE APIs have:
- **Rate limits** → NVD API: 5 requests/30 seconds
- **Latency** → 200-500ms per request
- **Internet dependency** → Incompatible with air-gapped environments
- **No correlation** → Must query multiple sources separately

This MCP server:
- **No rate limits** → Local database queries
- **<50ms latency** → Indexed PostgreSQL with Redis cache
- **Air-gap ready** → Daily background sync, no runtime internet
- **Pre-correlated** → CVE + KEV + EPSS + Exploits in single query

**Architecture decision:** [docs/architecture/2026-01-30-mcp-offline-first-assessment.md](./docs/architecture/2026-01-30-mcp-offline-first-assessment.md)

---

## Performance

| Metric | Target |
|--------|--------|
| Query latency (p95) | < 50ms |
| Full-text search | < 100ms |
| Batch queries (100 CVEs) | < 500ms |
| Daily sync duration | < 60 min |
| Availability | 99.99% |
| Database size | ~6 GB |

---

## Use Cases

### Threat Modeling Intelligence

```python
# Enrich STRIDE threat scenarios with current CVE data
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

### Risk-Based Vulnerability Prioritization

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

---

## ⚠️ Important Disclaimers

### Data Freshness

> **📅 Data Currency Warning**
>
> CVE data is synced daily from public sources (NVD, CISA, EPSS, ExploitDB). Data freshness:
> - **NVD CVEs**: Daily delta sync, monthly full refresh
> - **CISA KEV**: Daily updates
> - **EPSS scores**: Daily updates
> - **ExploitDB**: Weekly updates
>
> **This is intelligence data, not real-time vulnerability scanning.** For production security monitoring, use dedicated vulnerability scanners (Nessus, Qualys, etc.).

### Not a Vulnerability Scanner

> **🚨 NOT A SECURITY SCANNER 🚨**
>
> This MCP server provides **vulnerability intelligence**, not **vulnerability detection**. It:
> - ✅ Tells you WHAT vulnerabilities exist in the NVD database
> - ✅ Tells you WHICH CVEs have public exploits or are actively exploited
> - ✅ Helps you PRIORITIZE vulnerabilities using EPSS scores
> - ❌ Does NOT scan your systems for vulnerabilities
> - ❌ Does NOT detect if you're vulnerable to specific CVEs
> - ❌ Does NOT replace vulnerability management tools
>
> **For actual vulnerability detection, use Nessus, Qualys, OpenVAS, or similar scanners.**

### CVSS Scoring Interpretation

> **⚠️ CVSS Is Not Risk**
>
> CVSS scores measure **severity** (impact + exploitability), not **risk** (likelihood × impact).
>
> Use EPSS scores for exploit likelihood. A CVSS 9.8 vulnerability with EPSS 0.01 (1% likelihood) may be lower priority than CVSS 7.5 with EPSS 0.95 (95% likelihood).
>
> **Recommended approach:** `CVSS score × EPSS score = Risk priority`

---

## Data Sources

| Source | Type | Update Frequency | Records |
|--------|------|------------------|---------|
| **NVD API 2.0** | Public | Daily (delta), Monthly (full) | 240,000+ CVEs |
| **CISA KEV** | Public | Daily | 1,200+ exploited CVEs |
| **FIRST EPSS** | Public | Daily | 200,000+ scores |
| **ExploitDB** | Public | Weekly | 15,000+ exploits |
| **MITRE ATT&CK** | Public | Monthly | 700+ techniques, 140+ groups |
| **MITRE ATLAS** | Public | Monthly | 200+ techniques, 30+ case studies |
| **MITRE CAPEC** | Public | Monthly | 550+ patterns, 300+ mitigations |

All data sources are **free and public** — no API keys required (NVD API key optional for higher rate limits).

---

## Related Projects: Security Intelligence Suite

This server is part of **Ansvar's Security Intelligence Suite**:

### 🛡️ CVE + Exploit Intelligence MCP (This Project)
**Query 240,000+ CVE records with exploit intelligence**
- Full NVD database with CVSS scoring
- CISA KEV tracking and EPSS prediction
- Exploit references (Metasploit, ExploitDB)
- **Install:** See Quick Start above

### 🌐 [Sanctions MCP](https://github.com/Ansvar-Systems/Sanctions-MCP)
**Query global sanctions lists (OFAC, UN, EU)**
- Tier 1 offline-first architecture reference
- Same design pattern as this project
- Used by financial services and compliance teams

### 🔐 [Security Controls MCP](https://github.com/Ansvar-Systems/security-controls-mcp)
**Query 1,451 security controls across 28 frameworks**
- ISO 27001, NIST CSF, PCI DSS, SOC 2, CMMC
- Bidirectional framework mapping
- Control implementation guidance

### 🇪🇺 [EU Regulations MCP](https://github.com/Ansvar-Systems/EU_compliance_MCP)
**Query 47 EU regulations (GDPR, NIS2, DORA, AI Act)**
- Full regulatory text with article-level search
- Cross-regulation comparison
- ISO 27001/NIST CSF mappings

---

## Security Features

- ✅ **Offline queries** — No external API calls during runtime
- ✅ **7-year audit trail** — Query logging for compliance
- ✅ **Air-gap deployment** — Sync can run on separate network
- ✅ **TLS 1.3** — Encrypted sync operations
- ✅ **PostgreSQL SSL** — Encrypted database connections
- ✅ **Rate limiting** — 100 req/min per client

**Security setup guide:** [.github/SECURITY-SETUP.md](.github/SECURITY-SETUP.md)

---

## Development

**Technology Stack:**
- Python 3.11+
- FastAPI (async web framework)
- PostgreSQL 15 (with full-text search)
- Redis 7 (caching)
- Celery (background tasks)
- SQLAlchemy 2.0 (async ORM)
- Pydantic 2.x (validation)

**CI/CD:**
- CodeQL (security scanning)
- Semgrep (SAST)
- Trivy (container scanning)
- pytest (45 tests)
- mypy (strict type checking)

---

## About Ansvar Systems

We build AI-accelerated threat modeling and compliance tools for automotive, financial services, and healthcare. This MCP server started as our internal CVE intelligence tool for Ansvar AI's threat modeling workflows.

So we're open-sourcing it. Real-time vulnerability intelligence shouldn't require API keys and rate limits.

**[ansvar.eu](https://ansvar.eu)** — Stockholm, Sweden

---

## Documentation

- **[DESIGN.md](./DESIGN.md)** — Complete design specification
- **[docs/SETUP.md](./docs/SETUP.md)** — Detailed deployment guide
- **[docs/modules/](./docs/modules/)** — Module-specific documentation
  - [ATT&CK module](./docs/modules/attack.md) — Semantic search, tools, workflows
  - [ATLAS module](./docs/modules/atlas.md) — AI/ML security, case studies, workflows
  - [CAPEC module](./docs/modules/capec.md) — Attack patterns, mitigations, workflows 🆕
- **[docs/architecture/](./docs/architecture/)** — Architecture decision records
  - [Tier 1 offline-first assessment](./docs/architecture/2026-01-30-mcp-offline-first-assessment.md)
  - [Build vs. buy analysis](./docs/architecture/2026-01-30-mcp-build-vs-buy-analysis.md)
- **[.github/SECURITY-SETUP.md](./.github/SECURITY-SETUP.md)** — Security hardening guide

---

## Status

**Current:** Production Ready ✅

**Completed:**
1. ✅ Database schema (15 models, full-text search, vector embeddings)
2. ✅ MCP server (25 tools, FastAPI)
3. ✅ Sync services (NVD, KEV, EPSS, ExploitDB, ATT&CK, ATLAS, CAPEC)
4. ✅ Docker deployment (PostgreSQL, Redis, Celery)
5. ✅ CI/CD (CodeQL, Semgrep, Trivy, 45 tests)
6. ✅ Security hardened (CORS, audit logs, TLS)
7. ✅ Type-safe (strict mypy)
8. ✅ Integration tests
9. ✅ MITRE ATT&CK module (semantic search, threat actors)
10. ✅ MITRE ATLAS module (AI/ML security, case studies)
11. ✅ MITRE CAPEC module (attack patterns, mitigations, semantic search)

---

## License

Apache License 2.0. See [LICENSE](./LICENSE) for details.

---

## Contributing

This is an internal Ansvar Systems project. For questions or contributions, contact the Platform Engineering team.

---

<p align="center">
  <sub>Built with care in Stockholm, Sweden</sub>
</p>
