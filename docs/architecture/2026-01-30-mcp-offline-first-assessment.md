# MCP Offline-First Architecture Assessment

**Date:** 2026-01-30
**Status:** Analysis Complete
**Context:** Evaluating existing MCP servers for Tier 1 (offline-first) compatibility

---

## Executive Summary

**Original Assumption:** 3 existing MCP servers could replace 3 custom builds

**Reality Check:**
- ✅ **1/3 MCPs support offline-first** (MITRE ATT&CK)
- ❌ **2/3 MCPs are API-dependent** (CVE/NVD, OpenCTI)

**Revised Recommendation:**
- **Deploy MITRE ATT&CK MCP** (Tier 1 compatible)
- **Build custom CVE/Exploit MCP** (Tier 1 architecture like Sanctions MCP)
- **Build custom Threat Actor MCP** (Tier 1 architecture) OR **self-host OpenCTI** (adds infrastructure burden)

---

## Tier Architecture Review

### Tier 1: Offline-First MCPs (Bank Environment Approved)

**Architecture:**
- Local database cache (PostgreSQL/SQLite)
- Daily/weekly background synchronization
- Queries run against local data (no external API calls)
- 99.99% availability (no external dependency)
- Air-gap compatible

**Examples from Ansvar MCP Registry:**
- ✅ EU Compliance MCP (SQLite, weekly sync)
- ✅ US Compliance MCP (SQLite, weekly sync)
- ✅ OT Security MCP (SQLite, weekly sync)
- ✅ Sanctions Screening MCP (PostgreSQL, daily sync)

---

### Tier 2: API-Dependent MCPs (Requires External Connectivity)

**Architecture:**
- Direct API calls with short-term caching (5-60 min TTL)
- Requires network egress for every query
- 95-99% availability (external API dependent)
- Not air-gap compatible

**Examples from Ansvar MCP Registry:**
- 🔄 Have I Been Pwned MCP (planned)
- 🔄 Shodan MCP (planned)
- 🔄 SEC EDGAR MCP (planned)

---

## Detailed MCP Analysis

### 1. MITRE ATT&CK MCP ✅ (Tier 1 Compatible)

**Repository:** [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp)

#### Architecture Details

**Storage:**
- Local cache directory: `data/` (configurable via `MITRE_DATA_DIR`)
- Size: ~200 MB (STIX JSON bundles)
- Format: Pre-built indices for O(1) lookups

**Sync Mechanism:**
```python
# Automatic refresh logic
if cache_age > MITRE_CACHE_EXPIRY_DAYS:
    download_from_mitre_github()
else:
    use_local_cache()
```

**Data Sources (Configurable):**
```bash
# Default (internet required on first run)
MITRE_ENTERPRISE_URL=https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json
MITRE_MOBILE_URL=https://github.com/mitre-attack/attack-stix-data/raw/master/mobile-attack/mobile-attack.json
MITRE_ICS_URL=https://github.com/mitre-attack/attack-stix-data/raw/master/ics-attack/ics-attack.json

# Air-gap deployment (internal mirrors)
MITRE_ENTERPRISE_URL=https://internal-mirror.bank.local/enterprise-attack.json
MITRE_MOBILE_URL=https://internal-mirror.bank.local/mobile-attack.json
MITRE_ICS_URL=https://internal-mirror.bank.local/ics-attack.json
```

**Offline Operation:**
- ✅ Works completely offline after initial sync
- ✅ No external API calls during queries
- ✅ Manual force refresh: `--force-download` flag or delete `data/` folder

**Bank Environment Suitability:**

| Requirement | Status | Notes |
|-------------|--------|-------|
| **Air-gap compatible** | ✅ YES | Point to internal mirrors |
| **Offline queries** | ✅ YES | No external calls after cache |
| **Data freshness control** | ✅ YES | Configurable cache expiry |
| **Network isolation** | ✅ YES | Sync window: once per day |
| **Audit trail** | ⚠️ PARTIAL | No built-in query logging (add via proxy) |

**Deployment for Bank Environment:**

```yaml
# docker-compose.yml
services:
  mitre-mcp:
    image: ansvar/mitre-mcp:latest
    ports:
      - "8306:8306"
    environment:
      MITRE_DATA_DIR: /data
      MITRE_CACHE_EXPIRY_DAYS: 7  # Weekly refresh for stability
      # Point to internal mirrors (after initial download)
      MITRE_ENTERPRISE_URL: https://internal-mirror.bank.local/enterprise-attack.json
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8306/health"]
      interval: 60s
    restart: unless-stopped
```

**Verdict:** ✅ **USE AS-IS** - Fully compatible with Tier 1 requirements

---

### 2. CVE/NVD MCP ❌ (Tier 2 Only - Not Suitable)

**Repository:** [Cyreslab-AI/nist-nvd-mcp-server](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)

#### Architecture Details

**Storage:**
- ❌ No persistent database
- ⚠️ In-memory cache only (5-minute TTL)
- ❌ No offline mode

**API Dependency:**
```python
# Every query calls NVD API
async def search_cve(keyword: str):
    response = await http_client.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": keyword}
    )
    # Cache response for 5 minutes
    return response.json()
```

**Network Calls:**
- ✅ NVD API (https://services.nvd.nist.gov) - **EVERY QUERY**
- ✅ CISA KEV API - **EVERY KEV CHECK**
- ⚠️ Rate limiting: 5 requests/30 seconds (no API key), 50 requests/30 seconds (with key)

**Bank Environment Suitability:**

| Requirement | Status | Notes |
|-------------|--------|-------|
| **Air-gap compatible** | ❌ NO | Requires live NVD API |
| **Offline queries** | ❌ NO | Every query hits external API |
| **Data freshness control** | ⚠️ REAL-TIME | Always current, but no control |
| **Network isolation** | ❌ NO | Continuous egress required |
| **Audit trail** | ❌ NO | No query logging |

**Why This Is Problematic for Banks:**

1. **Regulatory Compliance:**
   - Some bank networks require **no external API calls** from production systems
   - Egress whitelisting for every query is difficult to justify

2. **Availability Risk:**
   - NVD API outages = MCP unavailable
   - Rate limiting can block queries during high-volume assessments

3. **Performance:**
   - API latency: 200-2000ms per query (vs. < 50ms for local database)
   - No bulk caching for batch assessments

**Verdict:** ❌ **BUILD CUSTOM TIER 1 MCP** - Use Sanctions MCP architecture as template

---

### 3. OpenCTI MCP ❌ (Tier 2 Proxy - Not Suitable)

**Repository:** [jhuntinfosec/mcp-opencti](https://github.com/jhuntinfosec/mcp-opencti)

#### Architecture Details

**Storage:**
- ❌ No local caching
- ❌ No persistent database
- ✅ Direct proxy to OpenCTI platform

**Dependency:**
```python
# Requires live OpenCTI connection
OPENCTI_URL = os.getenv("OPENCTI_URL")  # e.g., https://demo.opencti.io
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")

# Every query translates to OpenCTI GraphQL
async def search_threats(query: str):
    response = await opencti_client.graphql_query(
        """
        query SearchThreats($search: String!) {
          threats(search: $search) { ... }
        }
        """,
        variables={"search": query}
    )
    return response.data
```

**Network Calls:**
- ✅ OpenCTI instance (GraphQL API) - **EVERY QUERY**
- ✅ No caching layer
- ⚠️ Requires either:
  - Public OpenCTI demo (https://demo.opencti.io) - **internet required**
  - Self-hosted OpenCTI (Docker, 4GB RAM, Redis, Elasticsearch) - **adds infrastructure**

**Bank Environment Suitability:**

| Requirement | Status | Notes |
|-------------|--------|-------|
| **Air-gap compatible** | ⚠️ PARTIAL | Self-host OpenCTI, but still requires sync |
| **Offline queries** | ❌ NO | Requires live OpenCTI connection |
| **Data freshness control** | ✅ YES | OpenCTI handles data ingestion |
| **Network isolation** | ⚠️ PARTIAL | Self-hosted = internal network only |
| **Audit trail** | ✅ YES | OpenCTI has built-in audit logs |

**Self-Hosting Complexity:**

```yaml
# OpenCTI deployment (simplified)
services:
  opencti:
    image: opencti/platform:latest
    depends_on:
      - redis
      - elasticsearch
      - rabbitmq
      - minio
    environment:
      - OPENCTI_ADMIN_EMAIL=admin@bank.local
      - OPENCTI_ADMIN_PASSWORD=ChangeMePlease
    # + 15 more environment variables
    # + 4 dependent services (Redis, ES, RabbitMQ, MinIO)
    # Total resource requirements: 8GB RAM, 50GB storage
```

**Operational Burden:**
- Requires managing full OpenCTI platform (not just MCP server)
- Data ingestion from threat feeds (requires connectors)
- Elasticsearch cluster for search
- Complex upgrade procedures

**Verdict:** ❌ **BUILD CUSTOM TIER 1 MCP** - Simpler than self-hosting OpenCTI

---

## Revised Build vs. Buy Decision

### Original Plan (Assumed All Tier 1 Compatible)

| MCP Server | Decision | Rationale |
|------------|----------|-----------|
| MITRE ATT&CK | ✅ Use existing | Tier 1 compatible |
| CVE + Exploit | ✅ Use existing | **WRONG - Not Tier 1!** |
| Threat Actor Intel | ✅ Use existing | **WRONG - Not Tier 1!** |

---

### Revised Plan (Tier 1 Requirement)

| MCP Server | Decision | Rationale | Effort |
|------------|----------|-----------|--------|
| **MITRE ATT&CK** | ✅ Use existing | Tier 1 compatible, works offline | 1 hour deploy |
| **CVE + Exploit** | 🔴 Build custom | Existing is Tier 2, need offline-first | 6 weeks |
| **Threat Actor Intel** | 🔴 Build custom | Existing is Tier 2, need offline-first | 5 weeks |

**Why Build Custom for CVE/Threat Intel:**

1. **Sanctions MCP proves the pattern works:**
   - You already built a Tier 1 MCP (Sanctions)
   - Architecture: PostgreSQL + daily sync + HTTP/SSE transport
   - Can reuse this pattern for CVE and Threat Actor MCPs

2. **Bank environment requirements:**
   - Air-gap compatibility
   - No external API calls during queries
   - Audit logging
   - Data sovereignty (local storage)

3. **Performance:**
   - Local database: < 50ms latency
   - vs. NVD API: 200-2000ms latency

---

## Recommended Custom MCP Architecture

### CVE + Exploit Intelligence MCP (Tier 1)

**Based on Sanctions MCP pattern:**

```
┌─────────────────────────────────────────────────────────────┐
│  MCP Client (Ansvar AI)                                     │
└────────────────────┬────────────────────────────────────────┘
                     │ JSON-RPC 2.0
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  HTTP/SSE Transport Layer (Port 8307)                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  CVE MCP Server (Python FastAPI)                            │
│  - search_cve(keyword, cvss_min, affected_product)          │
│  - get_cve_details(cve_id)                                  │
│  - check_kev_status(cve_id)                                 │
│  - get_epss_score(cve_id)                                   │
│  - search_exploits(cve_id)                                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Redis Cache (Query Results)                                │
│  - TTL: 1 hour                                              │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  PostgreSQL Database (200k+ CVEs)                           │
│  Tables:                                                    │
│  - cves (id, description, cvss_score, published_date)       │
│  - cve_cpe_mappings (cve_id, cpe_uri, version_affected)     │
│  - cisa_kev (cve_id, date_added, required_action)           │
│  - epss_scores (cve_id, epss_score, percentile)             │
│  - exploit_references (cve_id, exploit_url, exploit_type)   │
│  - sync_metadata (source, last_sync_time, status)           │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Background Sync Service (Celery Beat)                      │
│  Schedule: Daily 02:00-04:00 UTC                            │
│  - NVD API 2.0 delta sync (CVEs from last 30 days)          │
│  - CISA KEV full refresh (daily)                            │
│  - FIRST EPSS feed (daily)                                  │
│  - ExploitDB metadata (weekly)                              │
└─────────────────────────────────────────────────────────────┘
```

**Database Schema:**

```sql
-- Core CVE table
CREATE TABLE cves (
    cve_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP,
    cvss_v2_score DECIMAL(3,1),
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),
    severity VARCHAR(10),  -- LOW, MEDIUM, HIGH, CRITICAL
    cwe_ids TEXT[],
    references JSONB,
    data_source VARCHAR(50) DEFAULT 'NVD',
    data_last_updated TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_cves_published ON cves(published_date DESC);
CREATE INDEX idx_cves_severity ON cves(severity);
CREATE INDEX idx_cves_score ON cves(cvss_v3_score DESC);
CREATE INDEX idx_cves_description_fts ON cves USING GIN(to_tsvector('english', description));

-- CPE (product) mappings
CREATE TABLE cve_cpe_mappings (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) REFERENCES cves(cve_id),
    cpe_uri VARCHAR(200),
    version_start VARCHAR(50),
    version_end VARCHAR(50),
    vulnerable BOOLEAN DEFAULT true
);
CREATE INDEX idx_cpe_cve ON cve_cpe_mappings(cve_id);
CREATE INDEX idx_cpe_uri ON cve_cpe_mappings(cpe_uri);

-- CISA KEV (Known Exploited Vulnerabilities)
CREATE TABLE cisa_kev (
    cve_id VARCHAR(20) PRIMARY KEY REFERENCES cves(cve_id),
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_use BOOLEAN,
    notes TEXT
);
CREATE INDEX idx_kev_date_added ON cisa_kev(date_added DESC);

-- EPSS (Exploit Prediction Scoring System)
CREATE TABLE epss_scores (
    cve_id VARCHAR(20) PRIMARY KEY REFERENCES cves(cve_id),
    epss_score DECIMAL(5,4),  -- 0.0000 to 1.0000
    percentile DECIMAL(5,4),
    date_scored DATE,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_epss_score ON epss_scores(epss_score DESC);

-- Exploit references (ExploitDB, Metasploit, PoC repos)
CREATE TABLE exploit_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) REFERENCES cves(cve_id),
    exploit_url VARCHAR(500),
    exploit_type VARCHAR(50),  -- metasploit, exploitdb, github_poc
    exploit_maturity VARCHAR(20),  -- functional, poc, unproven
    verified BOOLEAN DEFAULT false,
    date_added TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_exploit_cve ON exploit_references(cve_id);

-- Sync metadata (for data freshness tracking)
CREATE TABLE sync_metadata (
    source VARCHAR(50) PRIMARY KEY,
    last_sync_time TIMESTAMP,
    last_sync_status VARCHAR(20),  -- success, failed, partial
    records_synced INTEGER,
    error_message TEXT
);
```

**Sync Service (Daily Background Job):**

```python
# tasks/sync_nvd.py
from celery import shared_task
from datetime import datetime, timedelta
import httpx
from models import CVE, SyncMetadata

@shared_task
def sync_nvd_cves():
    """Daily NVD delta sync - only fetch CVEs modified in last 30 days"""
    last_sync = SyncMetadata.get(source="nvd")
    start_date = last_sync.last_sync_time if last_sync else datetime.now() - timedelta(days=30)

    async with httpx.AsyncClient() as client:
        # NVD API 2.0 with pubStartDate filter
        response = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "lastModStartDate": start_date.isoformat(),
                "lastModEndDate": datetime.now().isoformat()
            },
            headers={"apiKey": settings.NVD_API_KEY}  # From Vault
        )

        cves = response.json()["vulnerabilities"]

        # Bulk upsert to PostgreSQL
        for cve_data in cves:
            CVE.upsert(cve_data)

        SyncMetadata.update(
            source="nvd",
            last_sync_time=datetime.now(),
            records_synced=len(cves),
            status="success"
        )

@shared_task
def sync_cisa_kev():
    """Daily CISA KEV full refresh - small dataset (~1000 entries)"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        kev_data = response.json()["vulnerabilities"]

        # Clear old KEV data and insert new
        CISAKEV.truncate()
        CISAKEV.bulk_insert(kev_data)

@shared_task
def sync_epss_scores():
    """Daily EPSS score refresh from FIRST.org"""
    async with httpx.AsyncClient() as client:
        # Download full EPSS CSV (gzipped, ~50 MB)
        response = await client.get(
            "https://epss.cyentia.com/epss_scores-current.csv.gz"
        )

        # Decompress and parse CSV
        epss_data = parse_epss_csv(response.content)

        # Bulk upsert EPSS scores
        EPSSScore.bulk_upsert(epss_data)
```

**Deployment Effort:**
- Database schema design: 3 days
- Sync service implementation: 5 days
- MCP server endpoints: 4 days
- Testing & validation: 3 days
- Documentation: 1 day
- **Total:** 6 weeks (includes buffer)

**Benefits over API-dependent MCP:**
- ✅ Offline queries (< 50ms latency)
- ✅ Air-gap compatible
- ✅ No rate limiting
- ✅ Bulk assessment support
- ✅ Audit logging built-in
- ✅ Data sovereignty

---

### Threat Actor Intelligence MCP (Tier 1)

**Simpler than self-hosting OpenCTI:**

```
┌─────────────────────────────────────────────────────────────┐
│  PostgreSQL Database (APT Groups + Campaigns)               │
│  Tables:                                                    │
│  - threat_actors (id, name, aliases, motivation)            │
│  - campaigns (id, name, actor_id, date_start, date_end)     │
│  - ttps (id, actor_id, mitre_technique_id, confidence)      │
│  - iocs (id, actor_id, indicator_type, indicator_value)     │
│  - target_sectors (actor_id, sector, geography)             │
│  - sync_metadata (source, last_sync_time)                   │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Background Sync Service (Weekly)                           │
│  - MITRE ATT&CK Groups (from attack-stix-data)              │
│  - CISA Cybersecurity Advisories (RSS feed)                 │
│  - Open-source threat reports (Mandiant, CrowdStrike blogs) │
│  - ThreatFox IOCs (abuse.ch API)                            │
└─────────────────────────────────────────────────────────────┘
```

**Data Sources (All Public/Free):**
- MITRE ATT&CK Groups (GitHub JSON)
- CISA Cybersecurity Advisories (RSS/JSON feed)
- Threat actor profiles (manual curation from public reports)
- ThreatFox IOC database (abuse.ch API)

**Deployment Effort:**
- Database schema: 2 days
- Sync service: 4 days
- MCP server: 3 days
- Data curation: 5 days (initial threat actor profiles)
- Testing: 2 days
- **Total:** 5 weeks

**Benefits over OpenCTI MCP:**
- ✅ No complex infrastructure (no Elasticsearch, RabbitMQ, MinIO)
- ✅ Simpler data model (focused on threat actors, not full threat intel platform)
- ✅ Lower resource requirements (2GB RAM vs. 8GB for OpenCTI)
- ✅ Easier to maintain

---

## Cost-Benefit Analysis (Revised)

### Option A: Use Existing MCPs (API-Dependent)

| Component | Cost | Availability | Bank Compatible |
|-----------|------|--------------|-----------------|
| MITRE ATT&CK MCP | $0 | 99.99% (offline) | ✅ YES |
| CVE/NVD MCP (API) | $0 | 95% (NVD dependent) | ❌ NO |
| OpenCTI MCP + Platform | $240/year (hosting) | 97% (self-managed) | ⚠️ PARTIAL |
| **Total** | **$240/year** | **97% avg** | **1/3 compatible** |

**Risks:**
- NVD API outages block CVSS scoring
- OpenCTI operational complexity
- Cannot pass bank security review (external API calls)

---

### Option B: Build Custom Tier 1 MCPs (Recommended)

| Component | Build Cost | Infrastructure | Availability | Bank Compatible |
|-----------|------------|----------------|--------------|-----------------|
| MITRE ATT&CK MCP | $0 (use existing) | $10/month | 99.99% | ✅ YES |
| CVE + Exploit MCP | $18k (6 weeks) | $50/month | 99.99% | ✅ YES |
| Threat Actor MCP | $15k (5 weeks) | $30/month | 99.99% | ✅ YES |
| **Total** | **$33k (one-time)** | **$90/month** | **99.99% avg** | **3/3 compatible** |

**Benefits:**
- All queries run offline (no external dependencies)
- Air-gap deployment ready
- Sub-50ms query latency
- Passes bank security review
- Reuses Sanctions MCP architecture (proven pattern)

**ROI Calculation:**
- **Upfront cost:** $33k development
- **Annual infrastructure:** $1,080
- **vs. Commercial threat intel:** $50k-$200k/year (Recorded Future, ThreatConnect)
- **Break-even:** 6 months

---

## Revised Recommendation

### Phase 0: Deploy MITRE ATT&CK MCP (THIS WEEK)

**Action:** Deploy [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp)
**Time:** 1 hour
**Cost:** $0

**Why:** Tier 1 compatible, works offline, no build needed

---

### Phase 1: Build CVE + Exploit MCP (MONTH 1-2)

**Action:** Build custom Tier 1 MCP using Sanctions MCP pattern
**Time:** 6 weeks
**Cost:** $18k
**Team:** 2 engineers

**Deliverables:**
- PostgreSQL database with 200k+ CVEs
- Daily NVD sync service
- CISA KEV integration
- EPSS scoring
- Exploit reference tracking
- HTTP/SSE transport

**Why:** Existing NVD MCP is API-dependent (Tier 2), not suitable for bank environment

---

### Phase 2: Build Threat Actor Intelligence MCP (MONTH 2-3)

**Action:** Build custom Tier 1 MCP with APT group profiles
**Time:** 5 weeks
**Cost:** $15k
**Team:** 2 engineers

**Deliverables:**
- PostgreSQL database with APT groups, campaigns, TTPs
- Weekly sync from public threat reports
- MITRE ATT&CK group mappings
- IOC tracking (ThreatFox integration)
- HTTP/SSE transport

**Why:** OpenCTI MCP requires full platform deployment (complex infrastructure), custom MCP is simpler

---

## Total Revised Budget

| Phase | MCPs | Time | Cost |
|-------|------|------|------|
| Phase 0 | MITRE (deploy existing) | 1 hour | $0 |
| Phase 1 | CVE + Exploit (build custom) | 6 weeks | $18k |
| Phase 2 | Threat Actor (build custom) | 5 weeks | $15k |
| **Total** | **3 Tier 1 MCPs** | **11 weeks** | **$33k** |

**vs. Original Plan:**
- Original: Use all 3 existing MCPs ($0, 2 days)
- Revised: 1 existing + 2 custom ($33k, 11 weeks)
- **Additional cost:** $33k for Tier 1 compliance

---

## Decision Criteria

### When to Use Existing MCP

✅ Use if:
- Tier 1 compatible (offline-first)
- Production-ready (active maintenance)
- Meets security requirements
- No excessive dependencies

**Example:** Montimage/mitre-mcp ✅

---

### When to Build Custom MCP

🔴 Build if:
- Existing MCP is Tier 2 (API-dependent)
- Bank environment requires offline operation
- You already have Tier 1 MCP architecture (Sanctions pattern)
- Custom features needed (audit logging, air-gap, etc.)

**Example:** CVE + Exploit MCP, Threat Actor MCP 🔴

---

## Conclusion

**Original Assumption:** All 3 existing MCPs could be deployed immediately

**Reality:**
- ✅ **1/3 is Tier 1 compatible** (MITRE ATT&CK)
- ❌ **2/3 are Tier 2** (CVE/NVD, OpenCTI)

**Recommended Action:**
1. ✅ **Deploy MITRE ATT&CK MCP** this week ($0, 1 hour)
2. 🔴 **Build CVE + Exploit MCP** using Sanctions pattern (6 weeks, $18k)
3. 🔴 **Build Threat Actor MCP** using Sanctions pattern (5 weeks, $15k)

**Total Investment:** $33k (one-time) + $90/month (infrastructure)

**Value:** 3 Tier 1 MCPs that pass bank security review, eliminate RAG staleness, enable offline threat intelligence

---

**Document Status:** Ready for Decision
**Next Step:** Approve Phase 0 (deploy MITRE MCP) and Phase 1 budget (build CVE MCP)
**Related Documents:**
- `docs/plans/2026-01-30-deploy-existing-mcp-servers.md` (original deployment plan)
- `docs/plans/2026-01-30-mcp-build-vs-buy-analysis.md` (original cost analysis)
- `docs/mcp-server-registry.md` (Sanctions MCP architecture reference)

---

**Sources:**
- [Montimage/mitre-mcp Architecture](https://github.com/Montimage/mitre-mcp)
- [Cyreslab-AI/nist-nvd-mcp-server Architecture](https://github.com/Cyreslab-AI/nist-nvd-mcp-server)
- [jhuntinfosec/mcp-opencti Architecture](https://github.com/jhuntinfosec/mcp-opencti)
