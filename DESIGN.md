# CVE + Exploit Intelligence MCP - Complete Design Specification

**Repository:** `ansvar-cve-exploit-mcp` (to be created)
**Type:** Tier 1 MCP Server (Offline-First)
**Status:** Design Complete - Ready for Implementation
**Date:** 2026-01-30
**Version:** 1.0

---

## Executive Summary

A Model Context Protocol (MCP) server providing offline-first access to CVE vulnerability data, CISA Known Exploited Vulnerabilities (KEV), EPSS exploit prediction scores, and exploit availability tracking.

**Key Features:**
- ✅ 200,000+ CVE records with full details
- ✅ CISA KEV integration (actively exploited vulnerabilities)
- ✅ EPSS scores (exploit prediction likelihood)
- ✅ CPE product mappings (affected software versions)
- ✅ Exploit reference tracking (Metasploit, ExploitDB, GitHub PoCs)
- ✅ Offline-first architecture (daily background sync)
- ✅ Sub-50ms query latency (PostgreSQL local database)
- ✅ Air-gap deployment ready

**Architecture Pattern:** Based on Ansvar Sanctions MCP (proven Tier 1 design)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Database Schema](#database-schema)
3. [API Endpoints](#api-endpoints)
4. [Sync Services](#sync-services)
5. [Deployment Guide](#deployment-guide)
6. [Performance Targets](#performance-targets)
7. [Security & Compliance](#security--compliance)
8. [Monitoring & Maintenance](#monitoring--maintenance)

---

## Architecture Overview

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  MCP Client (Ansvar AI / Claude Desktop / Cursor)                   │
└────────────────────────────┬────────────────────────────────────────┘
                             │ JSON-RPC 2.0 (HTTP/SSE or stdio)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Transport Layer                                                     │
│  ┌─────────────────────┐  ┌─────────────────────┐                  │
│  │ HTTP/SSE (Port 8307)│  │ stdio (local mode)  │                  │
│  └─────────────────────┘  └─────────────────────┘                  │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CVE MCP Server (Python 3.11+ / FastAPI)                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ MCP Tools                                                     │  │
│  │ - search_cve(keyword, cvss_min, severity, has_kev)           │  │
│  │ - get_cve_details(cve_id)                                    │  │
│  │ - check_kev_status(cve_id)                                   │  │
│  │ - get_epss_score(cve_id)                                     │  │
│  │ - search_by_product(product_name, version)                   │  │
│  │ - get_exploits(cve_id)                                       │  │
│  │ - get_cwe_details(cwe_id)                                    │  │
│  │ - batch_search(cve_ids[])                                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Business Logic                                                │  │
│  │ - CVE query engine                                           │  │
│  │ - CVSS score calculator                                      │  │
│  │ - CPE matcher (product version resolution)                   │  │
│  │ - Exploit maturity scorer                                    │  │
│  │ - Data freshness validator                                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Redis Cache (Query Results)                                        │
│  - TTL: 1 hour (queries)                                            │
│  - TTL: 24 hours (CVE details)                                      │
│  - Eviction: LRU                                                    │
│  - Keys: cve:{cve_id}, search:{hash}, kev:list                      │
└─────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PostgreSQL 15 Database (Primary Storage)                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Core Tables                                                   │  │
│  │ - cves (200k+ records, ~8 GB)                                │  │
│  │ - cve_references (external links, advisories)                │  │
│  │ - cve_cpe_mappings (product/version mappings)                │  │
│  │ - cisa_kev (known exploited vulnerabilities)                 │  │
│  │ - epss_scores (exploit prediction scores)                    │  │
│  │ - exploit_references (Metasploit, ExploitDB, PoCs)           │  │
│  │ - cwe_data (weakness definitions)                            │  │
│  │ - sync_metadata (data freshness tracking)                    │  │
│  │ - query_audit_log (compliance audit trail)                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Indexes                                                       │  │
│  │ - GIN full-text search (cve description)                     │  │
│  │ - B-tree (cve_id, published_date, cvss_score)                │  │
│  │ - Partial index (has_kev, high severity)                     │  │
│  │ - Composite (cpe_uri, version range)                         │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Background Sync Services (Celery Beat)                             │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Daily Sync Jobs (02:00-04:00 UTC)                            │  │
│  │ - sync_nvd_recent (last 30 days delta)     → 15 min         │  │
│  │ - sync_cisa_kev (full refresh)             → 2 min          │  │
│  │ - sync_epss_scores (full refresh)          → 30 min         │  │
│  │ - sync_exploitdb_metadata (weekly)         → 10 min         │  │
│  │ - refresh_materialized_views               → 5 min          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Monthly Sync Jobs (First Sunday, 03:00 UTC)                  │  │
│  │ - sync_nvd_full (complete rebuild)         → 8 hours        │  │
│  │ - rebuild_cpe_dictionary                   → 2 hours        │  │
│  │ - vacuum_analyze_database                  → 30 min         │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  External Data Sources (Internet Access Required for Sync Only)     │
│  - NVD API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0   │
│  - CISA KEV: https://www.cisa.gov/.../known_exploited_vulns.json   │
│  - FIRST EPSS: https://epss.cyentia.com/epss_scores-current.csv.gz │
│  - ExploitDB: https://gitlab.com/exploit-database/exploitdb        │
│  - NVD CPE Dictionary: https://nvd.nist.gov/feeds/json/cpematch/   │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Offline-First:** All queries run against local PostgreSQL (no external API calls)
2. **Background Sync:** Daily syncs during maintenance window (02:00-04:00 UTC)
3. **Data Freshness:** Track sync metadata, alert if > 48 hours stale
4. **Performance:** Sub-50ms query latency via indexed PostgreSQL
5. **Audit Trail:** Log all queries for compliance (7-year retention)
6. **Graceful Degradation:** Serve stale data if sync fails (up to 7 days acceptable)

---

## Database Schema

### Core Tables

#### 1. `cves` - Main CVE Records

```sql
CREATE TABLE cves (
    -- Primary identification
    cve_id VARCHAR(20) PRIMARY KEY,  -- e.g., 'CVE-2024-1234'

    -- Temporal tracking
    published_date TIMESTAMP NOT NULL,
    last_modified_date TIMESTAMP NOT NULL,

    -- Descriptive data
    description TEXT NOT NULL,
    description_vector tsvector,  -- Full-text search index

    -- CVSS v2 scoring (legacy)
    cvss_v2_score DECIMAL(3,1),
    cvss_v2_vector VARCHAR(50),
    cvss_v2_severity VARCHAR(10),  -- LOW, MEDIUM, HIGH

    -- CVSS v3.x scoring (primary)
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),
    cvss_v3_severity VARCHAR(10),  -- NONE, LOW, MEDIUM, HIGH, CRITICAL
    cvss_v3_base_score DECIMAL(3,1),
    cvss_v3_exploitability_score DECIMAL(3,1),
    cvss_v3_impact_score DECIMAL(3,1),

    -- CVSS v4.0 scoring (future-proofing)
    cvss_v4_score DECIMAL(3,1),
    cvss_v4_vector VARCHAR(150),
    cvss_v4_severity VARCHAR(10),

    -- CWE (weakness) associations
    cwe_ids TEXT[],  -- Array of CWE-XXX identifiers
    primary_cwe_id VARCHAR(20),  -- Most relevant CWE

    -- Problem type classification
    problem_type TEXT,  -- Human-readable problem description

    -- Source tracking
    assigner VARCHAR(100),  -- Who assigned this CVE (e.g., 'cve@mitre.org')
    data_source VARCHAR(50) DEFAULT 'NVD',
    data_version VARCHAR(20),  -- NVD API version used

    -- Sync metadata
    data_last_updated TIMESTAMP DEFAULT NOW(),
    first_seen TIMESTAMP DEFAULT NOW(),

    -- Computed flags (for faster queries)
    has_exploit BOOLEAN DEFAULT false,
    has_kev_entry BOOLEAN DEFAULT false,  -- In CISA KEV list
    has_epss_score BOOLEAN DEFAULT false,
    has_public_poc BOOLEAN DEFAULT false,  -- Public proof-of-concept available

    -- Constraints
    CONSTRAINT cves_pk PRIMARY KEY (cve_id),
    CONSTRAINT cves_published_check CHECK (published_date <= last_modified_date)
);

-- Indexes for performance
CREATE INDEX idx_cves_published ON cves(published_date DESC);
CREATE INDEX idx_cves_modified ON cves(last_modified_date DESC);
CREATE INDEX idx_cves_cvss_v3_score ON cves(cvss_v3_score DESC NULLS LAST);
CREATE INDEX idx_cves_severity ON cves(cvss_v3_severity) WHERE cvss_v3_severity IN ('HIGH', 'CRITICAL');
CREATE INDEX idx_cves_has_kev ON cves(cve_id) WHERE has_kev_entry = true;
CREATE INDEX idx_cves_has_exploit ON cves(cve_id) WHERE has_exploit = true;

-- Full-text search index
CREATE INDEX idx_cves_description_fts ON cves USING GIN(to_tsvector('english', description));

-- Partial index for high-priority CVEs
CREATE INDEX idx_cves_high_priority ON cves(published_date DESC)
WHERE cvss_v3_score >= 7.0 OR has_kev_entry = true;

-- Update trigger for description_vector
CREATE TRIGGER cves_description_vector_update
BEFORE INSERT OR UPDATE ON cves
FOR EACH ROW
EXECUTE FUNCTION tsvector_update_trigger(description_vector, 'pg_catalog.english', description);

-- Statistics
COMMENT ON TABLE cves IS 'Core CVE vulnerability records from NVD API 2.0';
COMMENT ON COLUMN cves.has_kev_entry IS 'True if CVE is in CISA Known Exploited Vulnerabilities catalog';
COMMENT ON COLUMN cves.has_exploit IS 'True if exploit code is publicly available';
```

---

#### 2. `cve_references` - External Links & Advisories

```sql
CREATE TABLE cve_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,

    -- Reference details
    url TEXT NOT NULL,
    source VARCHAR(100),  -- e.g., 'vendor advisory', 'third party advisory'
    tags TEXT[],  -- e.g., ['Patch', 'Vendor Advisory', 'Exploit']

    -- Metadata
    added_date TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT cve_references_unique UNIQUE(cve_id, url)
);

CREATE INDEX idx_cve_refs_cve_id ON cve_references(cve_id);
CREATE INDEX idx_cve_refs_tags ON cve_references USING GIN(tags);
CREATE INDEX idx_cve_refs_source ON cve_references(source);

COMMENT ON TABLE cve_references IS 'External references, advisories, and patches for CVEs';
```

---

#### 3. `cve_cpe_mappings` - Product/Version Mappings

```sql
CREATE TABLE cve_cpe_mappings (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,

    -- CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    cpe_uri VARCHAR(500) NOT NULL,

    -- Parsed CPE components
    cpe_part VARCHAR(1),  -- 'a' (application), 'o' (OS), 'h' (hardware)
    cpe_vendor VARCHAR(100),
    cpe_product VARCHAR(100),
    cpe_version VARCHAR(100),
    cpe_update VARCHAR(100),

    -- Version range (for "affects versions X to Y")
    version_start_type VARCHAR(20),  -- 'including', 'excluding'
    version_start VARCHAR(100),
    version_end_type VARCHAR(20),
    version_end VARCHAR(100),

    -- Vulnerability status
    vulnerable BOOLEAN DEFAULT true,

    -- Metadata
    configuration_id VARCHAR(100),  -- NVD configuration node ID
    added_date TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT cpe_mappings_unique UNIQUE(cve_id, cpe_uri, version_start, version_end)
);

CREATE INDEX idx_cpe_cve_id ON cve_cpe_mappings(cve_id);
CREATE INDEX idx_cpe_uri ON cve_cpe_mappings(cpe_uri);
CREATE INDEX idx_cpe_vendor ON cve_cpe_mappings(cpe_vendor);
CREATE INDEX idx_cpe_product ON cve_cpe_mappings(cpe_product);
CREATE INDEX idx_cpe_vendor_product ON cve_cpe_mappings(cpe_vendor, cpe_product);

-- Composite index for version range queries
CREATE INDEX idx_cpe_version_range ON cve_cpe_mappings(cpe_vendor, cpe_product, version_start, version_end);

COMMENT ON TABLE cve_cpe_mappings IS 'CPE (Common Platform Enumeration) mappings - which products/versions are affected';
COMMENT ON COLUMN cve_cpe_mappings.cpe_uri IS 'CPE 2.3 formatted string';
```

---

#### 4. `cisa_kev` - Known Exploited Vulnerabilities

```sql
CREATE TABLE cisa_kev (
    cve_id VARCHAR(20) PRIMARY KEY REFERENCES cves(cve_id) ON DELETE CASCADE,

    -- KEV catalog data
    vulnerability_name TEXT,
    short_description TEXT,
    required_action TEXT NOT NULL,  -- What organizations must do
    due_date DATE,  -- Deadline for remediation (if specified)

    -- Threat context
    known_ransomware_use BOOLEAN DEFAULT false,

    -- Temporal data
    date_added DATE NOT NULL,  -- When added to KEV catalog
    notes TEXT,  -- Additional context from CISA

    -- Sync metadata
    data_last_updated TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_kev_date_added ON cisa_kev(date_added DESC);
CREATE INDEX idx_kev_ransomware ON cisa_kev(cve_id) WHERE known_ransomware_use = true;
CREATE INDEX idx_kev_due_date ON cisa_kev(due_date) WHERE due_date IS NOT NULL;

COMMENT ON TABLE cisa_kev IS 'CISA Known Exploited Vulnerabilities catalog - CVEs with confirmed active exploitation';
COMMENT ON COLUMN cisa_kev.required_action IS 'Mandatory remediation action from CISA';
COMMENT ON COLUMN cisa_kev.known_ransomware_use IS 'CVE used in ransomware campaigns';
```

---

#### 5. `epss_scores` - Exploit Prediction Scores

```sql
CREATE TABLE epss_scores (
    cve_id VARCHAR(20) PRIMARY KEY REFERENCES cves(cve_id) ON DELETE CASCADE,

    -- EPSS scoring (FIRST.org)
    epss_score DECIMAL(6,5) NOT NULL,  -- 0.00000 to 1.00000 (probability of exploitation in next 30 days)
    epss_percentile DECIMAL(6,5) NOT NULL,  -- Relative ranking (0-1)

    -- Temporal data
    date_scored DATE NOT NULL,  -- When EPSS score was calculated

    -- Sync metadata
    data_last_updated TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT epss_score_range CHECK (epss_score >= 0 AND epss_score <= 1),
    CONSTRAINT epss_percentile_range CHECK (epss_percentile >= 0 AND epss_percentile <= 1)
);

CREATE INDEX idx_epss_score ON epss_scores(epss_score DESC);
CREATE INDEX idx_epss_percentile ON epss_scores(epss_percentile DESC);
CREATE INDEX idx_epss_high_risk ON epss_scores(cve_id) WHERE epss_score >= 0.75;

COMMENT ON TABLE epss_scores IS 'FIRST EPSS (Exploit Prediction Scoring System) - likelihood of exploitation';
COMMENT ON COLUMN epss_scores.epss_score IS 'Probability (0-1) that CVE will be exploited in next 30 days';
COMMENT ON COLUMN epss_scores.epss_percentile IS 'Relative ranking compared to all CVEs (higher = more likely)';
```

---

#### 6. `exploit_references` - Public Exploit Code

```sql
CREATE TABLE exploit_references (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,

    -- Exploit metadata
    exploit_url TEXT NOT NULL,
    exploit_type VARCHAR(50) NOT NULL,  -- 'metasploit', 'exploitdb', 'github_poc', 'packetstorm'
    exploit_title TEXT,
    exploit_description TEXT,

    -- Maturity assessment
    exploit_maturity VARCHAR(20),  -- 'functional', 'poc', 'unproven', 'high'
    verified BOOLEAN DEFAULT false,  -- Has the exploit been verified to work

    -- Exploit characteristics
    requires_authentication BOOLEAN,
    requires_user_interaction BOOLEAN,
    exploit_complexity VARCHAR(10),  -- 'low', 'medium', 'high'

    -- Source-specific IDs
    exploitdb_id INTEGER,  -- ExploitDB EDB-ID
    metasploit_module VARCHAR(200),  -- Metasploit module path
    github_repo VARCHAR(200),  -- GitHub repository URL

    -- Temporal data
    exploit_published_date DATE,
    date_added TIMESTAMP DEFAULT NOW(),

    -- Sync metadata
    data_last_updated TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT exploit_refs_unique UNIQUE(cve_id, exploit_url)
);

CREATE INDEX idx_exploit_cve_id ON exploit_references(cve_id);
CREATE INDEX idx_exploit_type ON exploit_references(exploit_type);
CREATE INDEX idx_exploit_maturity ON exploit_references(exploit_maturity);
CREATE INDEX idx_exploit_verified ON exploit_references(cve_id) WHERE verified = true;
CREATE INDEX idx_exploit_metasploit ON exploit_references(cve_id) WHERE exploit_type = 'metasploit';

COMMENT ON TABLE exploit_references IS 'Public exploit code references (Metasploit, ExploitDB, GitHub PoCs)';
COMMENT ON COLUMN exploit_references.exploit_maturity IS 'Maturity level based on Metasploit ranking (functional = working exploit)';
```

---

#### 7. `cwe_data` - Common Weakness Enumeration

```sql
CREATE TABLE cwe_data (
    cwe_id VARCHAR(20) PRIMARY KEY,  -- e.g., 'CWE-79'

    -- CWE details
    name TEXT NOT NULL,  -- e.g., 'Cross-site Scripting (XSS)'
    description TEXT,
    extended_description TEXT,

    -- Classification
    weakness_type VARCHAR(50),  -- 'Base', 'Variant', 'Compound', 'Category'
    abstraction VARCHAR(20),  -- 'Class', 'Base', 'Variant', 'Compound'

    -- Relationships
    parent_cwe_ids TEXT[],  -- Parent weaknesses
    child_cwe_ids TEXT[],  -- Child weaknesses

    -- MITRE ATT&CK mapping
    related_attack_patterns TEXT[],  -- CAPEC IDs

    -- Sync metadata
    data_last_updated TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cwe_name ON cwe_data USING GIN(to_tsvector('english', name));
CREATE INDEX idx_cwe_type ON cwe_data(weakness_type);

COMMENT ON TABLE cwe_data IS 'CWE (Common Weakness Enumeration) definitions';
```

---

#### 8. `sync_metadata` - Data Freshness Tracking

```sql
CREATE TABLE sync_metadata (
    source VARCHAR(50) PRIMARY KEY,

    -- Sync status
    last_sync_time TIMESTAMP NOT NULL,
    last_sync_status VARCHAR(20) NOT NULL,  -- 'success', 'failed', 'partial', 'running'
    next_sync_time TIMESTAMP,

    -- Sync statistics
    records_synced INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_inserted INTEGER DEFAULT 0,
    records_deleted INTEGER DEFAULT 0,
    sync_duration_seconds INTEGER,

    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,

    -- Data version
    data_version VARCHAR(50),  -- API version or data timestamp
    data_checksum VARCHAR(64),  -- SHA256 of synced data

    -- Sync window
    sync_window_start TIME DEFAULT '02:00',
    sync_window_end TIME DEFAULT '04:00'
);

-- Seed initial metadata
INSERT INTO sync_metadata (source, last_sync_time, last_sync_status) VALUES
('nvd_recent', '1970-01-01', 'pending'),
('nvd_full', '1970-01-01', 'pending'),
('cisa_kev', '1970-01-01', 'pending'),
('epss_scores', '1970-01-01', 'pending'),
('exploitdb', '1970-01-01', 'pending'),
('cwe_data', '1970-01-01', 'pending');

COMMENT ON TABLE sync_metadata IS 'Tracks data sync status and freshness for all external sources';
```

---

#### 9. `query_audit_log` - Compliance Audit Trail

```sql
CREATE TABLE query_audit_log (
    id BIGSERIAL PRIMARY KEY,

    -- Query metadata
    timestamp TIMESTAMP DEFAULT NOW(),
    client_id VARCHAR(100),  -- MCP client identifier
    user_id VARCHAR(100),  -- If authenticated

    -- Query details
    tool_name VARCHAR(50) NOT NULL,  -- 'search_cve', 'get_cve_details', etc.
    query_params JSONB,  -- Sanitized query parameters

    -- Results
    result_count INTEGER,
    match_found BOOLEAN,
    has_kev_result BOOLEAN,  -- Did results include KEV entries

    -- Performance
    query_time_ms INTEGER,
    cache_hit BOOLEAN DEFAULT false,

    -- Context
    workflow_run_id VARCHAR(100),  -- If part of workflow execution
    request_id VARCHAR(100)  -- For tracing
);

-- Partitioning by month for 7-year retention
CREATE TABLE query_audit_log_2026_01 PARTITION OF query_audit_log
FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- (Auto-create partitions via pg_partman)

CREATE INDEX idx_audit_timestamp ON query_audit_log(timestamp DESC);
CREATE INDEX idx_audit_client ON query_audit_log(client_id);
CREATE INDEX idx_audit_tool ON query_audit_log(tool_name);

COMMENT ON TABLE query_audit_log IS '7-year audit trail of all CVE queries for compliance';
```

---

### Materialized Views (Performance Optimization)

#### `mv_high_priority_cves` - Pre-computed High-Risk CVEs

```sql
CREATE MATERIALIZED VIEW mv_high_priority_cves AS
SELECT
    c.cve_id,
    c.published_date,
    c.cvss_v3_score,
    c.cvss_v3_severity,
    c.description,
    c.has_kev_entry,
    c.has_exploit,
    k.date_added AS kev_date_added,
    k.known_ransomware_use,
    e.epss_score,
    e.epss_percentile,
    COUNT(DISTINCT ex.id) AS exploit_count
FROM cves c
LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
LEFT JOIN epss_scores e ON c.cve_id = e.cve_id
LEFT JOIN exploit_references ex ON c.cve_id = ex.cve_id
WHERE
    c.cvss_v3_score >= 7.0  -- High or Critical
    OR c.has_kev_entry = true
    OR e.epss_score >= 0.5
GROUP BY c.cve_id, k.date_added, k.known_ransomware_use, e.epss_score, e.epss_percentile;

CREATE UNIQUE INDEX idx_mv_high_priority_cve_id ON mv_high_priority_cves(cve_id);
CREATE INDEX idx_mv_high_priority_score ON mv_high_priority_cves(cvss_v3_score DESC);
CREATE INDEX idx_mv_high_priority_kev ON mv_high_priority_cves(cve_id) WHERE has_kev_entry = true;

COMMENT ON MATERIALIZED VIEW mv_high_priority_cves IS 'Pre-computed high-risk CVEs (refreshed daily after sync)';
```

---

### Database Size Estimates

| Table | Rows | Size per Row | Total Size | Notes |
|-------|------|--------------|------------|-------|
| `cves` | 240,000 | 3 KB | ~720 MB | Description text is largest field |
| `cve_references` | 960,000 | 200 bytes | ~192 MB | Avg 4 refs per CVE |
| `cve_cpe_mappings` | 1,200,000 | 300 bytes | ~360 MB | Avg 5 CPE mappings per CVE |
| `cisa_kev` | 1,200 | 500 bytes | ~600 KB | Small, high-value dataset |
| `epss_scores` | 200,000 | 50 bytes | ~10 MB | Daily scoring data |
| `exploit_references` | 15,000 | 400 bytes | ~6 MB | ~6% of CVEs have public exploits |
| `cwe_data` | 900 | 2 KB | ~1.8 MB | CWE dictionary |
| `sync_metadata` | 6 | 500 bytes | ~3 KB | Metadata only |
| `query_audit_log` | 1M/month | 200 bytes | ~200 MB/month | Partitioned, 7-year retention |
| **Indexes** | - | - | ~2 GB | GIN + B-tree indexes |
| **Total (active)** | - | - | **~4 GB** | Excludes audit log |
| **Total (with 1yr audit)** | - | - | **~6.4 GB** | Production size |

**Storage Planning:**
- Development: 10 GB volume
- Production: 25 GB volume (5-year growth headroom)
- Backup: 50 GB retention (daily snapshots, 30-day window)

---

## API Endpoints (MCP Tools)

### Tool Definitions

All tools follow MCP protocol specification. Each tool returns JSON with:
- `data`: Query results
- `metadata`: Query performance, data freshness, cache status
- `warnings`: Data staleness warnings if > 48 hours

---

### 1. `search_cve` - Primary Search Tool

**Description:** Search CVEs by keyword, severity, score range, and filters.

**Parameters:**
```typescript
{
  keyword?: string,           // Full-text search in description
  cvss_min?: number,          // Minimum CVSS v3 score (0-10)
  cvss_max?: number,          // Maximum CVSS v3 score (0-10)
  severity?: string[],        // ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
  has_kev?: boolean,          // Only CVEs in CISA KEV catalog
  has_exploit?: boolean,      // Only CVEs with public exploits
  epss_min?: number,          // Minimum EPSS score (0-1)
  published_after?: string,   // ISO date (e.g., '2024-01-01')
  published_before?: string,  // ISO date
  cwe_ids?: string[],         // Filter by CWE (e.g., ['CWE-79', 'CWE-89'])
  limit?: number,             // Max results (default 50, max 500)
  offset?: number             // Pagination offset
}
```

**Example Query:**
```json
{
  "keyword": "authentication bypass",
  "cvss_min": 7.0,
  "severity": ["CRITICAL", "HIGH"],
  "has_kev": true,
  "limit": 10
}
```

**Response:**
```json
{
  "data": {
    "cves": [
      {
        "cve_id": "CVE-2024-1234",
        "published_date": "2024-01-15T10:30:00Z",
        "cvss_v3_score": 9.8,
        "cvss_v3_severity": "CRITICAL",
        "description": "Authentication bypass vulnerability in...",
        "has_kev_entry": true,
        "kev_date_added": "2024-01-20",
        "has_exploit": true,
        "epss_score": 0.92,
        "exploit_count": 3
      }
    ],
    "total_results": 42,
    "returned_results": 10
  },
  "metadata": {
    "query_time_ms": 35,
    "cache_hit": false,
    "data_freshness": "current",
    "last_sync_time": "2026-01-30T02:15:00Z",
    "data_age_hours": 6
  }
}
```

**SQL Implementation:**
```sql
-- search_cve query
SELECT
    c.cve_id,
    c.published_date,
    c.cvss_v3_score,
    c.cvss_v3_severity,
    c.description,
    c.has_kev_entry,
    c.has_exploit,
    k.date_added AS kev_date_added,
    e.epss_score,
    (SELECT COUNT(*) FROM exploit_references WHERE cve_id = c.cve_id) AS exploit_count
FROM cves c
LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
LEFT JOIN epss_scores e ON c.cve_id = e.cve_id
WHERE
    ($1 IS NULL OR c.description_vector @@ plainto_tsquery('english', $1))  -- keyword
    AND ($2 IS NULL OR c.cvss_v3_score >= $2)  -- cvss_min
    AND ($3 IS NULL OR c.cvss_v3_score <= $3)  -- cvss_max
    AND ($4 IS NULL OR c.cvss_v3_severity = ANY($4))  -- severity
    AND ($5 IS NULL OR c.has_kev_entry = $5)  -- has_kev
    AND ($6 IS NULL OR c.has_exploit = $6)  -- has_exploit
    AND ($7 IS NULL OR e.epss_score >= $7)  -- epss_min
ORDER BY c.cvss_v3_score DESC, c.published_date DESC
LIMIT $8 OFFSET $9;
```

---

### 2. `get_cve_details` - Full CVE Record

**Description:** Get complete details for a specific CVE including references, CPE mappings, exploits.

**Parameters:**
```typescript
{
  cve_id: string,           // Required: e.g., 'CVE-2024-1234'
  include_references?: boolean,  // Include external links (default true)
  include_cpe?: boolean,         // Include CPE mappings (default true)
  include_exploits?: boolean     // Include exploit references (default true)
}
```

**Response:**
```json
{
  "data": {
    "cve_id": "CVE-2024-1234",
    "published_date": "2024-01-15T10:30:00Z",
    "last_modified_date": "2024-01-20T14:00:00Z",
    "description": "Authentication bypass...",
    "cvss_v3": {
      "score": 9.8,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "severity": "CRITICAL",
      "exploitability_score": 3.9,
      "impact_score": 5.9
    },
    "cwe_ids": ["CWE-287"],
    "kev_status": {
      "in_kev": true,
      "date_added": "2024-01-20",
      "required_action": "Apply updates per vendor instructions",
      "due_date": "2024-02-10",
      "known_ransomware_use": true
    },
    "epss": {
      "score": 0.92,
      "percentile": 0.98,
      "date_scored": "2024-01-30"
    },
    "references": [
      {
        "url": "https://vendor.com/advisory/2024-001",
        "source": "vendor advisory",
        "tags": ["Patch", "Vendor Advisory"]
      }
    ],
    "cpe_mappings": [
      {
        "cpe_uri": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
        "vendor": "vendor",
        "product": "product",
        "version_start": "1.0",
        "version_end": "1.9",
        "vulnerable": true
      }
    ],
    "exploits": [
      {
        "type": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/...",
        "title": "Vendor Product Authentication Bypass",
        "maturity": "functional",
        "verified": true,
        "published_date": "2024-01-22"
      }
    ]
  },
  "metadata": {
    "query_time_ms": 12,
    "cache_hit": true,
    "data_age_hours": 6
  }
}
```

---

### 3. `check_kev_status` - CISA KEV Lookup

**Description:** Check if CVE is in CISA Known Exploited Vulnerabilities catalog.

**Parameters:**
```typescript
{
  cve_id: string  // Required
}
```

**Response:**
```json
{
  "data": {
    "cve_id": "CVE-2024-1234",
    "in_kev": true,
    "kev_details": {
      "date_added": "2024-01-20",
      "vulnerability_name": "Vendor Product Authentication Bypass",
      "required_action": "Apply updates per vendor instructions or discontinue use",
      "due_date": "2024-02-10",
      "known_ransomware_use": true,
      "notes": "Actively exploited in ransomware campaigns targeting healthcare"
    }
  },
  "metadata": {
    "kev_last_sync": "2026-01-30T02:00:00Z"
  }
}
```

---

### 4. `get_epss_score` - Exploit Prediction Score

**Description:** Get EPSS (Exploit Prediction Scoring System) score for a CVE.

**Parameters:**
```typescript
{
  cve_id: string  // Required
}
```

**Response:**
```json
{
  "data": {
    "cve_id": "CVE-2024-1234",
    "epss_score": 0.92,
    "epss_percentile": 0.98,
    "date_scored": "2026-01-30",
    "interpretation": "Top 2% most likely to be exploited in next 30 days"
  },
  "metadata": {
    "epss_last_sync": "2026-01-30T03:00:00Z"
  }
}
```

---

### 5. `search_by_product` - Product Vulnerability Search

**Description:** Find CVEs affecting a specific product and version.

**Parameters:**
```typescript
{
  product_name: string,      // Required: e.g., 'apache'
  vendor?: string,           // Optional: e.g., 'apache'
  version?: string,          // Optional: e.g., '2.4.49'
  version_operator?: string, // 'eq', 'lt', 'lte', 'gt', 'gte'
  limit?: number
}
```

**Example:**
```json
{
  "product_name": "apache",
  "vendor": "apache",
  "version": "2.4.49",
  "version_operator": "eq"
}
```

**Response:**
```json
{
  "data": {
    "cves": [
      {
        "cve_id": "CVE-2021-41773",
        "cvss_v3_score": 7.5,
        "description": "Path traversal in Apache HTTP Server 2.4.49",
        "cpe_matches": [
          {
            "cpe_uri": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "vulnerable": true
          }
        ],
        "has_kev_entry": true,
        "has_exploit": true
      }
    ],
    "total_results": 3
  }
}
```

---

### 6. `get_exploits` - Exploit Code References

**Description:** Get public exploit code references for a CVE.

**Parameters:**
```typescript
{
  cve_id: string,
  verified_only?: boolean  // Only return verified exploits
}
```

**Response:**
```json
{
  "data": {
    "cve_id": "CVE-2024-1234",
    "exploits": [
      {
        "type": "metasploit",
        "url": "https://github.com/rapid7/metasploit-framework/modules/exploits/...",
        "title": "Vendor Product Auth Bypass",
        "maturity": "functional",
        "verified": true,
        "requires_authentication": false,
        "requires_user_interaction": false,
        "exploit_complexity": "low",
        "published_date": "2024-01-22"
      },
      {
        "type": "exploitdb",
        "url": "https://www.exploit-db.com/exploits/51234",
        "exploitdb_id": 51234,
        "title": "Vendor Product 1.x - Authentication Bypass (PoC)",
        "maturity": "poc",
        "verified": false,
        "published_date": "2024-01-25"
      }
    ],
    "total_exploits": 2,
    "functional_exploits": 1
  }
}
```

---

### 7. `get_cwe_details` - CWE Weakness Info

**Description:** Get details about a CWE (Common Weakness Enumeration).

**Parameters:**
```typescript
{
  cwe_id: string  // e.g., 'CWE-79'
}
```

**Response:**
```json
{
  "data": {
    "cwe_id": "CWE-79",
    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "description": "The software does not neutralize or incorrectly neutralizes user-controllable input...",
    "weakness_type": "Base",
    "parent_cwe_ids": ["CWE-74"],
    "related_attack_patterns": ["CAPEC-18", "CAPEC-63", "CAPEC-86"]
  }
}
```

---

### 8. `batch_search` - Bulk CVE Lookup

**Description:** Get details for multiple CVEs in one query (for batch assessment).

**Parameters:**
```typescript
{
  cve_ids: string[],  // Array of CVE IDs (max 100)
  include_kev?: boolean,
  include_epss?: boolean
}
```

**Response:**
```json
{
  "data": {
    "cves": [
      {
        "cve_id": "CVE-2024-1234",
        "cvss_v3_score": 9.8,
        "has_kev_entry": true,
        "epss_score": 0.92
      },
      {
        "cve_id": "CVE-2024-5678",
        "cvss_v3_score": 7.5,
        "has_kev_entry": false,
        "epss_score": 0.12
      }
    ],
    "requested": 2,
    "found": 2,
    "not_found": []
  }
}
```

---

## Sync Services

### Daily Sync Schedule (02:00-04:00 UTC)

```python
# celerybeat_schedule.py
from celery.schedules import crontab

CELERYBEAT_SCHEDULE = {
    # Daily syncs
    'sync-nvd-recent': {
        'task': 'tasks.sync_nvd_recent',
        'schedule': crontab(hour=2, minute=0),  # 02:00 UTC
        'options': {'expires': 7200}  # 2-hour timeout
    },
    'sync-cisa-kev': {
        'task': 'tasks.sync_cisa_kev',
        'schedule': crontab(hour=2, minute=30),  # 02:30 UTC
        'options': {'expires': 900}  # 15-min timeout
    },
    'sync-epss-scores': {
        'task': 'tasks.sync_epss_scores',
        'schedule': crontab(hour=3, minute=0),  # 03:00 UTC
        'options': {'expires': 3600}  # 1-hour timeout
    },

    # Weekly syncs
    'sync-exploitdb': {
        'task': 'tasks.sync_exploitdb',
        'schedule': crontab(hour=3, minute=30, day_of_week=1),  # Mon 03:30 UTC
        'options': {'expires': 1800}
    },

    # Post-sync tasks
    'refresh-materialized-views': {
        'task': 'tasks.refresh_materialized_views',
        'schedule': crontab(hour=3, minute=45),  # 03:45 UTC (after all syncs)
    },
    'update-computed-flags': {
        'task': 'tasks.update_computed_flags',
        'schedule': crontab(hour=3, minute=50),  # 03:50 UTC
    },

    # Monthly full rebuild
    'sync-nvd-full': {
        'task': 'tasks.sync_nvd_full',
        'schedule': crontab(hour=3, minute=0, day_of_month=1),  # 1st of month, 03:00 UTC
        'options': {'expires': 28800}  # 8-hour timeout
    }
}
```

---

### Sync Task Implementations

#### 1. `sync_nvd_recent` - Delta CVE Sync

```python
# tasks/sync_nvd.py
from celery import shared_task
from datetime import datetime, timedelta
import httpx
from sqlalchemy import select, update
from models import CVE, SyncMetadata, cve_references, cve_cpe_mappings
from utils.nvd_parser import parse_nvd_cve
import asyncio

@shared_task(bind=True, max_retries=3)
def sync_nvd_recent(self):
    """
    Daily delta sync: Fetch CVEs modified in last 30 days from NVD API 2.0
    Rationale: NVD updates existing CVEs frequently (new CPE mappings, score changes)
    """
    try:
        asyncio.run(_sync_nvd_recent())
    except Exception as exc:
        # Exponential backoff retry
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))

async def _sync_nvd_recent():
    metadata = SyncMetadata.get(source='nvd_recent')

    # Calculate time window (last 30 days or since last successful sync)
    start_date = max(
        metadata.last_sync_time if metadata.last_sync_status == 'success' else datetime.now() - timedelta(days=30),
        datetime.now() - timedelta(days=30)
    )
    end_date = datetime.now()

    # Update status to 'running'
    SyncMetadata.update(source='nvd_recent', last_sync_status='running')

    stats = {'inserted': 0, 'updated': 0, 'errors': 0}

    async with httpx.AsyncClient(timeout=60.0) as client:
        # NVD API 2.0 endpoint
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Pagination (2000 results per page max)
        start_index = 0
        results_per_page = 2000

        while True:
            try:
                response = await client.get(
                    base_url,
                    params={
                        'lastModStartDate': start_date.isoformat(),
                        'lastModEndDate': end_date.isoformat(),
                        'startIndex': start_index,
                        'resultsPerPage': results_per_page
                    },
                    headers={
                        'apiKey': settings.NVD_API_KEY  # From Vault
                    }
                )
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get('vulnerabilities', [])
                if not vulnerabilities:
                    break

                # Process each CVE
                for vuln_item in vulnerabilities:
                    try:
                        cve_data = parse_nvd_cve(vuln_item)

                        # Upsert CVE record
                        existing = CVE.get(cve_id=cve_data['cve_id'])
                        if existing:
                            CVE.update(cve_data)
                            stats['updated'] += 1
                        else:
                            CVE.create(cve_data)
                            stats['inserted'] += 1

                        # Upsert references
                        _sync_cve_references(cve_data)

                        # Upsert CPE mappings
                        _sync_cve_cpe_mappings(cve_data)

                    except Exception as e:
                        logger.error(f"Error processing {vuln_item.get('cve', {}).get('id')}: {e}")
                        stats['errors'] += 1

                # Check if more results
                if len(vulnerabilities) < results_per_page:
                    break

                start_index += results_per_page

                # Rate limiting: NVD allows 50 requests/30 seconds with API key
                await asyncio.sleep(0.6)  # ~100 req/min = well below limit

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    # Rate limited - wait and retry
                    await asyncio.sleep(30)
                    continue
                raise

    # Update sync metadata
    SyncMetadata.update(
        source='nvd_recent',
        last_sync_time=end_date,
        last_sync_status='success',
        records_synced=stats['inserted'] + stats['updated'],
        records_inserted=stats['inserted'],
        records_updated=stats['updated'],
        sync_duration_seconds=int((datetime.now() - start_date).total_seconds())
    )

    logger.info(f"NVD recent sync complete: {stats}")

def _sync_cve_references(cve_data):
    """Upsert CVE references"""
    # Delete existing
    db.execute(delete(cve_references).where(cve_references.c.cve_id == cve_data['cve_id']))

    # Insert new
    if cve_data.get('references'):
        db.execute(
            cve_references.insert(),
            [{'cve_id': cve_data['cve_id'], **ref} for ref in cve_data['references']]
        )
    db.commit()

def _sync_cve_cpe_mappings(cve_data):
    """Upsert CPE mappings"""
    # Delete existing
    db.execute(delete(cve_cpe_mappings).where(cve_cpe_mappings.c.cve_id == cve_data['cve_id']))

    # Insert new
    if cve_data.get('cpe_mappings'):
        db.execute(
            cve_cpe_mappings.insert(),
            [{'cve_id': cve_data['cve_id'], **cpe} for cpe in cve_data['cpe_mappings']]
        )
    db.commit()
```

---

#### 2. `sync_cisa_kev` - KEV Catalog Sync

```python
# tasks/sync_cisa_kev.py
from celery import shared_task
import httpx
from models import CISAKEV, SyncMetadata, CVE
from datetime import datetime

@shared_task(bind=True, max_retries=3)
def sync_cisa_kev(self):
    """
    Daily CISA KEV sync: Full refresh (small dataset ~1200 entries)
    Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """
    try:
        _sync_cisa_kev()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))

def _sync_cisa_kev():
    SyncMetadata.update(source='cisa_kev', last_sync_status='running')

    # Download KEV catalog
    response = httpx.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=30.0
    )
    response.raise_for_status()
    data = response.json()

    vulnerabilities = data.get('vulnerabilities', [])

    # Clear existing KEV data
    CISAKEV.truncate()

    # Insert new KEV data
    kev_records = []
    for vuln in vulnerabilities:
        kev_records.append({
            'cve_id': vuln['cveID'],
            'vulnerability_name': vuln.get('vulnerabilityName'),
            'short_description': vuln.get('shortDescription'),
            'required_action': vuln.get('requiredAction'),
            'due_date': vuln.get('dueDate'),
            'known_ransomware_use': vuln.get('knownRansomwareCampaignUse') == 'Known',
            'date_added': vuln.get('dateAdded'),
            'notes': vuln.get('notes')
        })

    CISAKEV.bulk_insert(kev_records)

    # Update CVE.has_kev_entry flags
    db.execute(
        update(CVE).where(CVE.cve_id.in_([r['cve_id'] for r in kev_records]))
        .values(has_kev_entry=True)
    )
    db.commit()

    # Update sync metadata
    SyncMetadata.update(
        source='cisa_kev',
        last_sync_time=datetime.now(),
        last_sync_status='success',
        records_synced=len(kev_records)
    )

    logger.info(f"CISA KEV sync complete: {len(kev_records)} entries")
```

---

#### 3. `sync_epss_scores` - EPSS Daily Sync

```python
# tasks/sync_epss.py
from celery import shared_task
import httpx
import gzip
import csv
from io import BytesIO, TextIOWrapper
from models import EPSSScore, SyncMetadata, CVE
from datetime import datetime

@shared_task(bind=True, max_retries=3)
def sync_epss_scores(self):
    """
    Daily EPSS sync: Download gzipped CSV from FIRST.org
    Source: https://epss.cyentia.com/epss_scores-current.csv.gz
    Size: ~50 MB compressed, ~200 MB uncompressed
    """
    try:
        _sync_epss_scores()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))

def _sync_epss_scores():
    SyncMetadata.update(source='epss_scores', last_sync_status='running')

    # Download EPSS CSV (gzipped)
    response = httpx.get(
        "https://epss.cyentia.com/epss_scores-current.csv.gz",
        timeout=120.0,
        follow_redirects=True
    )
    response.raise_for_status()

    # Decompress gzip
    with gzip.open(BytesIO(response.content), 'rt') as f:
        csv_reader = csv.DictReader(f)

        # Batch insert for performance
        batch_size = 10000
        batch = []
        total_records = 0

        for row in csv_reader:
            batch.append({
                'cve_id': row['cve'],
                'epss_score': float(row['epss']),
                'epss_percentile': float(row['percentile']),
                'date_scored': datetime.strptime(row.get('date', ''), '%Y-%m-%d').date()
            })

            if len(batch) >= batch_size:
                EPSSScore.bulk_upsert(batch)
                total_records += len(batch)
                batch = []

        # Insert remaining
        if batch:
            EPSSScore.bulk_upsert(batch)
            total_records += len(batch)

    # Update CVE.has_epss_score flags
    db.execute(
        update(CVE).where(CVE.cve_id.in_(
            select(EPSSScore.cve_id)
        )).values(has_epss_score=True)
    )
    db.commit()

    # Update sync metadata
    SyncMetadata.update(
        source='epss_scores',
        last_sync_time=datetime.now(),
        last_sync_status='success',
        records_synced=total_records
    )

    logger.info(f"EPSS sync complete: {total_records} scores")
```

---

#### 4. `sync_exploitdb` - ExploitDB Metadata (Weekly)

```python
# tasks/sync_exploitdb.py
from celery import shared_task
import httpx
from models import ExploitReference, SyncMetadata
import re

@shared_task
def sync_exploitdb():
    """
    Weekly ExploitDB sync: Clone/pull exploitdb repository metadata
    Source: https://gitlab.com/exploit-database/exploitdb
    Parses files_exploits.csv for CVE → ExploitDB mappings
    """
    SyncMetadata.update(source='exploitdb', last_sync_status='running')

    # Download ExploitDB CSV
    response = httpx.get(
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        timeout=60.0
    )
    response.raise_for_status()

    csv_data = response.text
    exploits = []

    for line in csv_data.split('\n')[1:]:  # Skip header
        parts = line.split(',')
        if len(parts) < 4:
            continue

        edb_id = parts[0]
        title = parts[2]

        # Extract CVE from description/title
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE)

        for cve_id in cve_matches:
            exploits.append({
                'cve_id': cve_id.upper(),
                'exploit_url': f"https://www.exploit-db.com/exploits/{edb_id}",
                'exploit_type': 'exploitdb',
                'exploit_title': title,
                'exploitdb_id': int(edb_id),
                'exploit_maturity': 'poc',  # Default to PoC for ExploitDB
                'verified': False
            })

    # Upsert exploits
    ExploitReference.bulk_upsert(exploits)

    # Update CVE.has_exploit flags
    db.execute(
        update(CVE).where(CVE.cve_id.in_([e['cve_id'] for e in exploits]))
        .values(has_exploit=True)
    )
    db.commit()

    SyncMetadata.update(
        source='exploitdb',
        last_sync_time=datetime.now(),
        last_sync_status='success',
        records_synced=len(exploits)
    )

    logger.info(f"ExploitDB sync complete: {len(exploits)} exploit references")
```

---

### Post-Sync Maintenance Tasks

#### 5. `refresh_materialized_views`

```python
@shared_task
def refresh_materialized_views():
    """Refresh materialized views after sync completion"""
    db.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_high_priority_cves")
    db.commit()
    logger.info("Materialized views refreshed")
```

#### 6. `update_computed_flags`

```python
@shared_task
def update_computed_flags():
    """Update computed boolean flags on CVE table"""
    # Update has_exploit flag
    db.execute("""
        UPDATE cves SET has_exploit = true
        WHERE cve_id IN (SELECT DISTINCT cve_id FROM exploit_references)
    """)

    # Update has_kev_entry flag
    db.execute("""
        UPDATE cves SET has_kev_entry = true
        WHERE cve_id IN (SELECT cve_id FROM cisa_kev)
    """)

    # Update has_epss_score flag
    db.execute("""
        UPDATE cves SET has_epss_score = true
        WHERE cve_id IN (SELECT cve_id FROM epss_scores)
    """)

    db.commit()
    logger.info("Computed flags updated")
```

---

## Deployment Guide

### Prerequisites

- Docker 24.0+
- PostgreSQL 15+ (with full-text search support)
- Redis 7.0+
- Python 3.11+
- 10 GB disk space (development), 25 GB (production)
- NVD API key (optional but recommended) - https://nvd.nist.gov/developers/request-an-api-key

---

### Quick Start (Docker Compose)

```yaml
# docker-compose.yml
version: '3.9'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: cve_mcp
      POSTGRES_USER: cve_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cve_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s

  cve-mcp-server:
    build: .
    ports:
      - "8307:8307"
    environment:
      DATABASE_URL: postgresql://cve_user:${POSTGRES_PASSWORD}@postgres:5432/cve_mcp
      REDIS_URL: redis://redis:6379/0
      NVD_API_KEY: ${NVD_API_KEY}
      MCP_PORT: 8307
      LOG_LEVEL: INFO
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8307/health"]
      interval: 30s

  celery-worker:
    build: .
    command: celery -A tasks worker --loglevel=info
    environment:
      DATABASE_URL: postgresql://cve_user:${POSTGRES_PASSWORD}@postgres:5432/cve_mcp
      REDIS_URL: redis://redis:6379/0
      NVD_API_KEY: ${NVD_API_KEY}
    depends_on:
      - postgres
      - redis

  celery-beat:
    build: .
    command: celery -A tasks beat --loglevel=info
    environment:
      DATABASE_URL: postgresql://cve_user:${POSTGRES_PASSWORD}@postgres:5432/cve_mcp
      REDIS_URL: redis://redis:6379/0
      NVD_API_KEY: ${NVD_API_KEY}
    depends_on:
      - postgres
      - redis

volumes:
  postgres_data:
```

---

### Environment Variables

```bash
# .env.example
# PostgreSQL
DATABASE_URL=postgresql://cve_user:changeme@localhost:5432/cve_mcp
POSTGRES_PASSWORD=changeme

# Redis
REDIS_URL=redis://localhost:6379/0

# NVD API (optional but recommended for higher rate limits)
NVD_API_KEY=your-nvd-api-key-here

# MCP Server
MCP_PORT=8307
MCP_TRANSPORT=http  # or 'stdio' for local mode
LOG_LEVEL=INFO

# Sync Configuration
SYNC_WINDOW_START=02:00
SYNC_WINDOW_END=04:00
DATA_FRESHNESS_WARNING_HOURS=48
DATA_FRESHNESS_CRITICAL_HOURS=168  # 7 days

# Performance
QUERY_CACHE_TTL_SECONDS=3600  # 1 hour
CVE_DETAILS_CACHE_TTL_SECONDS=86400  # 24 hours
MAX_QUERY_RESULTS=500
DEFAULT_QUERY_RESULTS=50

# Audit
AUDIT_LOG_RETENTION_DAYS=2555  # 7 years
```

---

### Initial Deployment Steps

```bash
# 1. Clone repository (when created)
git clone https://github.com/Ansvar-Systems/ansvar-cve-exploit-mcp.git
cd ansvar-cve-exploit-mcp

# 2. Create .env file
cp .env.example .env
# Edit .env with your credentials

# 3. Start services
docker-compose up -d

# 4. Wait for PostgreSQL to be ready
docker-compose exec postgres pg_isready -U cve_user

# 5. Run database migrations
docker-compose exec cve-mcp-server alembic upgrade head

# 6. Run initial full sync (takes 6-8 hours)
docker-compose exec celery-worker celery -A tasks call tasks.sync_nvd_full

# 7. Verify data
docker-compose exec cve-mcp-server python -c "from models import CVE; print(f'CVE count: {CVE.count()}')"

# 8. Test MCP endpoint
curl http://localhost:8307/health
```

---

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Query Latency (p50)** | < 20ms | 90% of queries |
| **Query Latency (p95)** | < 50ms | 95% of queries |
| **Query Latency (p99)** | < 200ms | 99% of queries |
| **Full-text Search** | < 100ms | Keyword searches |
| **Batch Queries (100 CVEs)** | < 500ms | Bulk lookups |
| **Daily Sync Duration** | < 60 min | NVD recent + KEV + EPSS |
| **Monthly Full Sync** | < 8 hours | Complete NVD rebuild |
| **Database Size** | < 10 GB | Active data |
| **Cache Hit Rate** | > 70% | Redis cache |
| **Availability** | 99.99% | Offline-first |

---

## Security & Compliance

### Data Classification

| Data Type | Classification | Retention | Encryption |
|-----------|----------------|-----------|------------|
| CVE records | Public | Indefinite | At rest (disk encryption) |
| CISA KEV data | Public | Indefinite | At rest |
| EPSS scores | Public | 1 year | At rest |
| Query audit logs | Confidential | 7 years | At rest + in transit (TLS) |
| Sync metadata | Internal | 1 year | At rest |

### Security Controls

1. **Input Validation:** All MCP tool parameters validated via Pydantic schemas
2. **SQL Injection Prevention:** Parameterized queries (SQLAlchemy ORM)
3. **Rate Limiting:** 100 req/min per client (Redis-based)
4. **Authentication:** Optional JWT validation for enterprise deployments
5. **Audit Logging:** All queries logged with client_id, timestamp, params
6. **Data Integrity:** Checksums tracked in `sync_metadata` table
7. **Secret Management:** NVD API key from environment (Azure Key Vault in production)

### Compliance Considerations

**GDPR:** No PII processed (public CVE data only)
**Audit Trail:** 7-year retention for query logs (compliance with financial sector requirements)
**Data Residency:** All data stored locally (no external API calls for queries)
**Availability:** 99.99% uptime (offline-first architecture)

---

## Monitoring & Maintenance

### Health Check Endpoint

```bash
GET /health

Response:
{
  "status": "healthy",
  "data_freshness": {
    "nvd_recent": {
      "last_sync": "2026-01-30T02:15:00Z",
      "age_hours": 6,
      "status": "current"
    },
    "cisa_kev": {
      "last_sync": "2026-01-30T02:30:00Z",
      "age_hours": 5,
      "status": "current"
    },
    "epss_scores": {
      "last_sync": "2026-01-30T03:00:00Z",
      "age_hours": 4,
      "status": "current"
    }
  },
  "database": {
    "cve_count": 242156,
    "kev_count": 1247,
    "epss_count": 201893
  },
  "cache": {
    "redis_connected": true,
    "cache_hit_rate": 0.73
  }
}
```

### Metrics to Monitor

```bash
# PostgreSQL
- Connection pool utilization
- Query latency (p50, p95, p99)
- Table sizes
- Index usage
- Slow queries

# Redis
- Memory usage
- Cache hit rate
- Eviction rate

# Sync Services
- Sync completion status
- Sync duration
- Records synced per job
- Error rates

# MCP Server
- Request rate (req/sec)
- Error rate (4xx, 5xx)
- Query latency
- Cache performance
```

### Alert Thresholds

| Alert | Warning | Critical | Action |
|-------|---------|----------|--------|
| **Data Staleness** | > 48 hours | > 7 days | Investigate sync failures |
| **Query Latency (p95)** | > 100ms | > 500ms | Check database performance |
| **Sync Failures** | 1 failure | 3 consecutive | Check NVD API status |
| **Database Size** | > 15 GB | > 20 GB | Plan storage expansion |
| **Cache Hit Rate** | < 60% | < 40% | Increase Redis memory |

---

## Development Roadmap

### Phase 1 (Weeks 1-2): Core Infrastructure
- [ ] Database schema implementation
- [ ] PostgreSQL setup with indexes
- [ ] Redis caching layer
- [ ] FastAPI server skeleton
- [ ] Health check endpoint

### Phase 2 (Weeks 2-3): Sync Services
- [ ] NVD API client
- [ ] CISA KEV sync
- [ ] EPSS score sync
- [ ] ExploitDB sync
- [ ] Celery worker setup

### Phase 3 (Weeks 3-4): MCP Tools
- [ ] search_cve implementation
- [ ] get_cve_details implementation
- [ ] check_kev_status implementation
- [ ] get_epss_score implementation
- [ ] search_by_product implementation

### Phase 4 (Week 5): Testing & Optimization
- [ ] Unit tests (80% coverage)
- [ ] Integration tests
- [ ] Performance testing
- [ ] Query optimization
- [ ] Cache tuning

### Phase 5 (Week 6): Documentation & Deployment
- [ ] API documentation
- [ ] Deployment guide
- [ ] Monitoring setup
- [ ] Docker images
- [ ] CI/CD pipeline

---

## Appendix: SQL Scripts

### Initial Setup Script

```sql
-- setup.sql
-- Run after Docker Compose initialization

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- Trigram similarity for fuzzy search
CREATE EXTENSION IF NOT EXISTS btree_gin;  -- GIN indexes for arrays

-- Create schema
CREATE SCHEMA IF NOT EXISTS cve_mcp;
SET search_path TO cve_mcp, public;

-- Run migrations (via Alembic)
-- alembic upgrade head

-- Create initial sync metadata
INSERT INTO sync_metadata (source, last_sync_time, last_sync_status) VALUES
('nvd_recent', '1970-01-01', 'pending'),
('nvd_full', '1970-01-01', 'pending'),
('cisa_kev', '1970-01-01', 'pending'),
('epss_scores', '1970-01-01', 'pending'),
('exploitdb', '1970-01-01', 'pending'),
('cwe_data', '1970-01-01', 'pending')
ON CONFLICT (source) DO NOTHING;

-- Grant permissions
GRANT USAGE ON SCHEMA cve_mcp TO cve_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cve_mcp TO cve_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cve_mcp TO cve_user;
```

---

**END OF DESIGN SPECIFICATION**

---

**Document Metadata:**
- **Version:** 1.0
- **Date:** 2026-01-30
- **Status:** Ready for Implementation
- **Next Steps:**
  1. Create repository: `ansvar-cve-exploit-mcp`
  2. Copy this design doc to repository root
  3. Initialize project structure
  4. Begin Phase 1 development
- **Related Documents:**
  - `docs/mcp-server-registry.md` (Sanctions MCP reference architecture)
  - `docs/mcp-quality-standard.md` (MCP development standards)
  - `docs/plans/2026-01-30-mcp-offline-first-assessment.md` (Architecture decision)
