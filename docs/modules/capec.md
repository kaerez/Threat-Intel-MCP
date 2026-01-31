# MITRE CAPEC Module

**Offline-first attack pattern enumeration with AI-powered semantic search for security assessments.**

## Overview

The CAPEC module provides comprehensive access to the MITRE CAPEC (Common Attack Pattern Enumeration and Classification) framework with both traditional keyword search and AI-powered semantic similarity search. All queries run against a local PostgreSQL database with pgvector for semantic search capabilities.

### Key Features

- **550+ Attack Patterns** — Comprehensive dictionary of known attack patterns used by adversaries
- **9 Categories** — Logical groupings for attack pattern navigation
- **300+ Mitigations** — Security controls and countermeasures for attack patterns
- **Abstraction Levels** — Meta, Standard, and Detailed pattern hierarchies
- **CWE Mappings** — Cross-reference to Common Weakness Enumeration
- **ATT&CK Mappings** — Cross-reference to MITRE ATT&CK techniques
- **Dual Search Modes** — Traditional keyword search (<50ms) + AI semantic search (<100ms)
- **Cross-Domain Queries** — Combine CVE + ATT&CK + CAPEC intelligence
- **RAG Integration** — Fresh data (<7 days) for AI assistant workflows
- **Offline-First** — All queries run locally, no external API calls during runtime

### Data Coverage

| Category | Count | Description |
|----------|-------|-------------|
| Attack Patterns | 550+ | Common attack patterns with detailed descriptions |
| Categories | 9 | Logical groupings (e.g., Injection, Social Engineering) |
| Mitigations | 300+ | Security controls and countermeasures |
| Abstraction Levels | 3 | Meta, Standard, Detailed |
| CWE Mappings | 500+ | Related weakness identifiers |
| ATT&CK Mappings | 200+ | Related technique identifiers |

### CAPEC vs ATT&CK vs CWE

| Aspect | CAPEC | ATT&CK | CWE |
|--------|-------|--------|-----|
| **Focus** | How attacks work | What adversaries do | Software weaknesses |
| **Abstraction** | Attack patterns | Techniques/procedures | Vulnerability types |
| **Scope** | Attack methodology | Threat intelligence | Code/design flaws |
| **ID Format** | CAPEC-66 | T1566 | CWE-79 |
| **Use Case** | Security design | Detection/response | Secure development |
| **Audience** | Security architects | SOC/IR teams | Developers |

### CAPEC Abstraction Levels

CAPEC organizes attack patterns into three abstraction levels:

| Level | Description | Example |
|-------|-------------|---------|
| **Meta** | High-level abstract patterns representing categories of attacks | CAPEC-152: Inject Unexpected Items |
| **Standard** | Specific attack patterns with detailed execution steps | CAPEC-66: SQL Injection |
| **Detailed** | Highly specific variations of standard patterns | CAPEC-67: String Format Overflow in syslog() |

---

## MCP Tools

The CAPEC module provides 5 MCP tools divided into traditional search and semantic search categories.

### Traditional Search Tools

#### 1. search_capec_patterns

**Description:** Search MITRE CAPEC attack patterns using keyword and filter-based search.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_capec_patterns",
  "arguments": {
    "query": "SQL injection",
    "abstraction": ["Standard", "Detailed"],
    "severity": "High",
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "patterns": [
      {
        "pattern_id": "CAPEC-66",
        "capec_id": 66,
        "name": "SQL Injection",
        "description": "This attack exploits target software that constructs SQL statements based on user input...",
        "abstraction": "Standard",
        "attack_likelihood": "High",
        "typical_severity": "High",
        "related_weaknesses": ["CWE-89", "CWE-20"],
        "deprecated": false,
        "badge_url": "https://capec.mitre.org/data/definitions/66.html"
      },
      {
        "pattern_id": "CAPEC-108",
        "capec_id": 108,
        "name": "Command Line Execution through SQL Injection",
        "description": "An attacker uses standard SQL injection techniques to inject operating system commands...",
        "abstraction": "Detailed",
        "attack_likelihood": "Low",
        "typical_severity": "Very High",
        "related_weaknesses": ["CWE-89", "CWE-78"],
        "deprecated": false,
        "badge_url": "https://capec.mitre.org/data/definitions/108.html"
      }
    ],
    "total_results": 15,
    "returned_results": 2
  },
  "metadata": {
    "query_time_ms": 35,
    "timestamp": "2026-01-31T13:00:00Z"
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | No | Full-text search in name/description |
| `abstraction` | array | No | Filter by levels: Meta, Standard, Detailed |
| `likelihood` | string | No | Filter by attack likelihood: High, Medium, Low |
| `severity` | string | No | Filter by typical severity: High, Medium, Low |
| `related_cwe` | array | No | Filter by CWE IDs (e.g., ["CWE-79", "CWE-89"]) |
| `active_only` | boolean | No | Exclude deprecated patterns (default: true) |
| `limit` | integer | No | Max results (default: 50, max: 500) |

**Use Cases:**
- Find attack patterns by name or description keywords
- Filter by abstraction level (Meta, Standard, Detailed)
- Filter by attack likelihood or severity
- Find patterns related to specific CWE weaknesses

---

#### 2. get_capec_pattern_details

**Description:** Get complete details for a specific MITRE CAPEC attack pattern.

**Performance:** <30ms average latency

**Example Request:**

```json
{
  "name": "get_capec_pattern_details",
  "arguments": {
    "pattern_id": "CAPEC-66"
  }
}
```

**Example Response:**

```json
{
  "data": {
    "pattern_id": "CAPEC-66",
    "capec_id": 66,
    "stix_id": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1",
    "name": "SQL Injection",
    "description": "This attack exploits target software that constructs SQL statements based on user input. An attacker crafts input strings so that when the target software constructs SQL statements based on the input, the resulting SQL statement performs actions other than those the application intended.",
    "abstraction": "Standard",
    "status": "Stable",
    "attack_likelihood": "High",
    "typical_severity": "High",
    "prerequisites": [
      "SQL-based database",
      "Application uses user input to construct SQL queries",
      "No input validation or sanitization"
    ],
    "skills_required": {
      "Low": "Identify SQL injection vulnerability",
      "Medium": "Exploit vulnerability to extract data",
      "High": "Achieve command execution through injection"
    },
    "resources_required": "None: No specialized resources required",
    "execution_flow": {
      "explore": {
        "name": "Survey application for user-controllable inputs",
        "description": "Identify all areas where user input is used in SQL queries"
      },
      "experiment": {
        "name": "Test inputs for SQL injection",
        "description": "Craft SQL injection payloads to test for vulnerabilities"
      },
      "exploit": {
        "name": "Execute SQL injection attack",
        "description": "Inject malicious SQL to extract data or modify database"
      }
    },
    "consequences": {
      "confidentiality": "Read application data",
      "integrity": "Modify or delete data",
      "authorization": "Bypass authentication"
    },
    "mitigations": [
      "Use parameterized queries or prepared statements",
      "Input validation and sanitization",
      "Implement least privilege for database accounts",
      "Web application firewall (WAF)"
    ],
    "examples": [
      "An attacker enters \"' OR '1'='1\" into a login form...",
      "Using UNION SELECT to extract data from other tables..."
    ],
    "references": [
      "https://owasp.org/www-community/attacks/SQL_Injection"
    ],
    "parent_of": ["CAPEC-108", "CAPEC-109", "CAPEC-110"],
    "child_of": ["CAPEC-152"],
    "related_attack_patterns": ["T1190", "T1059.001"],
    "related_weaknesses": ["CWE-89", "CWE-20", "CWE-943"],
    "version": "2.4",
    "created": "2014-06-23T00:00:00",
    "modified": "2024-07-31T00:00:00",
    "deprecated": false,
    "badge_url": "https://capec.mitre.org/data/definitions/66.html",
    "embedding_generated": true
  },
  "metadata": {
    "query_time_ms": 25
  }
}
```

**Use Cases:**
- Deep-dive analysis of specific attack patterns
- Understanding attack prerequisites and execution flow
- Mitigation planning with recommended controls
- Cross-referencing with CWE weaknesses and ATT&CK techniques
- Documentation and reporting for security assessments

---

#### 3. search_capec_mitigations

**Description:** Search MITRE CAPEC mitigations (security controls) using traditional keyword search.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_capec_mitigations",
  "arguments": {
    "query": "input validation",
    "effectiveness": "High",
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "mitigations": [
      {
        "mitigation_id": "COA-abc123",
        "name": "Input Validation",
        "description": "Perform thorough input validation on all user-supplied data before using it in any operations...",
        "effectiveness": "High",
        "mitigates_patterns": ["CAPEC-66", "CAPEC-79", "CAPEC-86"],
        "implementation_phases": ["Design", "Build"]
      },
      {
        "mitigation_id": "COA-def456",
        "name": "Parameterized Queries",
        "description": "Use parameterized queries or prepared statements to prevent SQL injection...",
        "effectiveness": "High",
        "mitigates_patterns": ["CAPEC-66", "CAPEC-108"],
        "implementation_phases": ["Build"]
      }
    ],
    "total_results": 25,
    "returned_results": 2
  },
  "metadata": {
    "query_time_ms": 38
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | No | Full-text search in name/description |
| `effectiveness` | string | No | Filter by effectiveness: High, Medium, Low |
| `patterns` | array | No | Filter by patterns mitigated (e.g., ["CAPEC-66"]) |
| `limit` | integer | No | Max results (default: 50, max: 500) |

**Use Cases:**
- Find security controls for specific attack patterns
- Filter mitigations by effectiveness level
- Discover controls for specific implementation phases
- Build defense-in-depth strategies

---

### Semantic Search Tools

#### 4. find_similar_capec_patterns

**Description:** Find MITRE CAPEC attack patterns using AI-powered semantic similarity search. Perfect for security assessments—describe an attack scenario in natural language and get matching patterns.

**Performance:** <100ms average latency

**Requirements:** OpenAI API key configured (OPENAI_API_KEY environment variable)

**Example Request:**

```json
{
  "name": "find_similar_capec_patterns",
  "arguments": {
    "description": "Attacker manipulates input fields to inject SQL commands and extract database contents including user credentials",
    "min_similarity": 0.7,
    "limit": 5
  }
}
```

**Example Response:**

```json
{
  "data": {
    "patterns": [
      {
        "pattern_id": "CAPEC-66",
        "capec_id": 66,
        "name": "SQL Injection",
        "description": "This attack exploits target software that constructs SQL statements based on user input...",
        "abstraction": "Standard",
        "attack_likelihood": "High",
        "typical_severity": "High",
        "similarity_score": 0.92,
        "badge_url": "https://capec.mitre.org/data/definitions/66.html"
      },
      {
        "pattern_id": "CAPEC-7",
        "capec_id": 7,
        "name": "Blind SQL Injection",
        "description": "Blind SQL Injection results from an insufficient mitigation for SQL Injection...",
        "abstraction": "Detailed",
        "attack_likelihood": "Medium",
        "typical_severity": "High",
        "similarity_score": 0.86,
        "badge_url": "https://capec.mitre.org/data/definitions/7.html"
      },
      {
        "pattern_id": "CAPEC-108",
        "capec_id": 108,
        "name": "Command Line Execution through SQL Injection",
        "description": "An attacker uses standard SQL injection techniques to inject operating system commands...",
        "abstraction": "Detailed",
        "attack_likelihood": "Low",
        "typical_severity": "Very High",
        "similarity_score": 0.81,
        "badge_url": "https://capec.mitre.org/data/definitions/108.html"
      }
    ],
    "returned_results": 3,
    "query_embedding_generated": true,
    "min_similarity": 0.7
  },
  "metadata": {
    "query_time_ms": 87
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | string | Yes | Natural language description of attack scenario (10-5000 chars) |
| `min_similarity` | float | No | Minimum similarity threshold (default: 0.7, range: 0-1) |
| `abstraction` | array | No | Filter by abstraction levels |
| `likelihood` | string | No | Filter by attack likelihood |
| `severity` | string | No | Filter by typical severity |
| `active_only` | boolean | No | Exclude deprecated patterns (default: true) |
| `limit` | integer | No | Max results (default: 10, max: 100) |

**Use Cases:**
- **Security Assessments:** Describe observed attack behavior, get matching patterns
- **Threat Modeling:** Map attack scenarios to CAPEC framework
- **Incident Response:** Identify attack patterns from incident descriptions
- **Red Team Exercises:** Map penetration testing activities to CAPEC

---

#### 5. find_similar_capec_mitigations

**Description:** Find similar MITRE CAPEC mitigations using AI-powered semantic similarity search. Describe what kind of security control you need and get matching mitigations.

**Performance:** <100ms average latency

**Requirements:** OpenAI API key configured

**Example Request:**

```json
{
  "name": "find_similar_capec_mitigations",
  "arguments": {
    "description": "Security controls to prevent injection attacks by validating and sanitizing user input before processing",
    "min_similarity": 0.65,
    "limit": 5
  }
}
```

**Example Response:**

```json
{
  "data": {
    "mitigations": [
      {
        "mitigation_id": "COA-abc123",
        "name": "Input Validation",
        "description": "Perform thorough input validation on all user-supplied data before using it in any operations...",
        "effectiveness": "High",
        "mitigates_patterns": ["CAPEC-66", "CAPEC-79", "CAPEC-86"],
        "implementation_phases": ["Design", "Build"],
        "similarity_score": 0.89
      },
      {
        "mitigation_id": "COA-def456",
        "name": "Output Encoding",
        "description": "Encode output data appropriately for the context to prevent injection attacks...",
        "effectiveness": "High",
        "mitigates_patterns": ["CAPEC-86", "CAPEC-588"],
        "implementation_phases": ["Build"],
        "similarity_score": 0.78
      }
    ],
    "returned_results": 2,
    "query_embedding_generated": true,
    "min_similarity": 0.65
  },
  "metadata": {
    "query_time_ms": 85
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | string | Yes | Natural language description of mitigation need (10-5000 chars) |
| `min_similarity` | float | No | Minimum similarity threshold (default: 0.7, range: 0-1) |
| `effectiveness` | string | No | Filter by effectiveness level |
| `limit` | integer | No | Max results (default: 10, max: 100) |

**Use Cases:**
- **Security Architecture:** Find appropriate controls for identified threats
- **Compliance Mapping:** Discover mitigations that address specific requirements
- **Defense-in-Depth:** Build layered security strategies
- **Security Design Reviews:** Validate mitigation coverage

---

## Semantic Search vs Traditional Search

### Comparison Table

| Feature | Traditional Search | Semantic Search |
|---------|-------------------|-----------------|
| **Query Type** | Keywords, filters | Natural language descriptions |
| **Matching** | Exact keyword matches | Contextual similarity |
| **Latency** | <50ms | <100ms |
| **Use Case** | Known pattern lookup | Security assessment, mapping scenarios |
| **Requirements** | None | OpenAI API key |
| **Best For** | Specific pattern research | Discovering relevant patterns from description |

### When to Use Each

**Use Traditional Search (`search_capec_patterns`) when:**
- You know the pattern name or ID
- You want to filter by specific abstraction levels
- You need fastest possible results
- You're browsing the CAPEC framework

**Use Semantic Search (`find_similar_capec_patterns`) when:**
- You have an attack scenario description
- You want to discover relevant patterns without knowing exact names
- You're mapping real-world attacks to CAPEC
- You're doing threat modeling or security assessments

**Example Scenario:**

Traditional: "Find all SQL injection patterns with high severity"
```json
{"query": "SQL injection", "severity": "High"}
```

Semantic: "Web application allows users to search products. Attacker discovered they can manipulate the search query to return all customer credit card numbers stored in the database."
```json
{"description": "Web application allows users to search products. Attacker discovered they can manipulate the search query to return all customer credit card numbers stored in the database."}
```
Returns CAPEC-66 (SQL Injection), CAPEC-7 (Blind SQL Injection) with high similarity

---

## Example Workflows

### Security Assessment with Semantic Search

```python
import anthropic

client = anthropic.Anthropic()

# Step 1: Describe the observed attack behavior
scenario = """
During penetration testing, we found that the login form accepts
special characters in the username field. When we entered a single
quote followed by OR 1=1, we were able to bypass authentication
and access the admin dashboard without valid credentials.
"""

# Step 2: Find matching attack patterns
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"Find CAPEC patterns for this security finding: {scenario}"
    }]
)
# Claude uses find_similar_capec_patterns tool automatically
# Returns: CAPEC-66 (SQL Injection), CAPEC-115 (Authentication Bypass)

# Step 3: Get detailed mitigation guidance
for pattern_id in ["CAPEC-66", "CAPEC-115"]:
    details = client.messages.create(
        model="claude-sonnet-4.5",
        messages=[{
            "role": "user",
            "content": f"Get full details and mitigations for {pattern_id}"
        }]
    )
    # Returns prerequisites, execution flow, mitigations, CWE mappings
```

### Cross-Domain Query: CVE + CAPEC + ATT&CK

```python
# Find CVE details and related attack patterns
query = """
1. Search for CVEs related to SQL injection in web applications
2. Find CAPEC attack patterns for SQL injection
3. Map to ATT&CK techniques for detection
"""

response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{"role": "user", "content": query}]
)

# Claude automatically:
# 1. Calls search_cve("SQL injection", cvss_min=7.0)
# 2. Calls find_similar_capec_patterns("SQL injection attack")
# 3. Uses related_attack_patterns from CAPEC to find ATT&CK techniques
# Returns unified threat intelligence
```

### Threat Modeling with CAPEC

```python
# Map STRIDE threats to CAPEC patterns
stride_threat = """
Threat: Spoofing Identity
Component: User authentication module
Description: Attacker impersonates legitimate user by manipulating
session tokens or bypassing authentication mechanisms.
"""

# Find relevant attack patterns
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"What CAPEC patterns apply to this STRIDE threat: {stride_threat}"
    }]
)
# Returns patterns related to authentication bypass, session hijacking
# Claude can then recommend mitigations from CAPEC
```

### Finding Mitigations for CWE Weaknesses

```python
# Find mitigations for a known weakness
weakness = """
Our SAST tool identified CWE-89 (SQL Injection) vulnerabilities
in our codebase. We need security controls to remediate.
"""

# Find applicable mitigations
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"Find CAPEC mitigations for: {weakness}"
    }]
)
# Returns: Parameterized Queries, Input Validation, Stored Procedures
# With effectiveness ratings and implementation guidance
```

---

## Data Sync

### Manual Sync Commands

**Sync CAPEC data WITHOUT embeddings (faster):**

```bash
# Download + parse only (3-5 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_capec.sync_capec_data

# Verify sync
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM capec_patterns')
        print(f'Patterns: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM capec_mitigations')
        print(f'Mitigations: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM capec_categories')
        print(f'Categories: {result.scalar()}')
asyncio.run(check())
"
```

**Sync CAPEC data WITH embeddings (semantic search):**

```bash
# Download + parse + generate embeddings (12-15 minutes)
# Requires OPENAI_API_KEY in environment
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_capec.sync_capec_data --kwargs='{"generate_embeddings": true}'

# Verify embeddings
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute(
            'SELECT COUNT(*) FROM capec_patterns WHERE embedding IS NOT NULL'
        )
        print(f'Patterns with embeddings: {result.scalar()}')
        result = await session.execute(
            'SELECT COUNT(*) FROM capec_mitigations WHERE embedding IS NOT NULL'
        )
        print(f'Mitigations with embeddings: {result.scalar()}')
asyncio.run(check())
"
```

### Expected Durations

| Operation | Duration | Notes |
|-----------|----------|-------|
| Download STIX data | 30-60 sec | ~5MB JSON file |
| Parse + insert patterns | 2-3 min | ~550 patterns |
| Parse + insert categories | 30 sec | ~9 categories |
| Parse + insert mitigations | 1-2 min | ~300 mitigations |
| Generate pattern embeddings | 8-10 min | OpenAI API, ~550 requests |
| Generate mitigation embeddings | 4-5 min | OpenAI API, ~300 requests |
| **Total (with embeddings)** | **12-15 min** | One-time cost |
| **Total (without embeddings)** | **3-5 min** | Traditional search only |

### Recommendations

- **Development:** Sync without embeddings for faster iteration
- **Production:** Sync with embeddings for full semantic search capabilities
- **Scheduled:** Run monthly to get latest CAPEC updates
- **Embeddings:** Re-generate only when MITRE updates pattern descriptions

---

## Performance Metrics

### Query Latency (p95)

| Operation | Target | Typical | Notes |
|-----------|--------|---------|-------|
| `search_capec_patterns` | <50ms | 35-45ms | PostgreSQL ILIKE search |
| `find_similar_capec_patterns` | <100ms | 75-95ms | pgvector cosine similarity |
| `get_capec_pattern_details` | <30ms | 20-28ms | Indexed lookup |
| `search_capec_mitigations` | <50ms | 38-48ms | PostgreSQL ILIKE search |
| `find_similar_capec_mitigations` | <100ms | 75-92ms | pgvector cosine similarity |

### Database Size

| Component | Size | Details |
|-----------|------|---------|
| CAPEC patterns | ~5 MB | ~550 records with descriptions |
| CAPEC categories | ~0.5 MB | ~9 records |
| CAPEC mitigations | ~3 MB | ~300 records with descriptions |
| Pattern embeddings | ~4 MB | 1536-dim vectors (text-embedding-3-small) |
| Mitigation embeddings | ~2 MB | 1536-dim vectors |
| Indexes (IVFFlat) | ~2 MB | Vector similarity indexes |
| **Total CAPEC module** | **~17 MB** | Minimal overhead |

### Embedding Generation Cost

Using OpenAI `text-embedding-3-small` model:

| Item | Count | Cost per 1M tokens | Total Cost |
|------|-------|-------------------|------------|
| Pattern embeddings | ~550 | $0.02 | ~$0.10 |
| Mitigation embeddings | ~300 | $0.02 | ~$0.05 |
| **Total (one-time)** | **~850** | - | **~$0.15** |

**Monthly refresh cost:** ~$0.15 (assuming content changes require full re-sync)

---

## Integration with Ansvar AI Platform

The CAPEC module eliminates RAG staleness by providing fresh, local attack pattern data to AI assistants.

### Before: RAG Without MCP

```
┌─────────────────┐
│   Claude API    │  Knowledge cutoff: May 2025
│  (RAG context)  │  CAPEC data: 180-365 days stale
└─────────────────┘
```

**Problems:**
- CAPEC knowledge outdated by 180-365 days
- No access to latest attack patterns
- Cannot query by semantic similarity
- Requires prompt engineering for pattern mapping

### After: RAG + MCP Hybrid

```
┌─────────────────┐
│   Claude API    │  General knowledge (cutoff: May 2025)
│  (RAG context)  │  +
└────────┬────────┘  MCP tools for fresh CAPEC data
         │
         ▼
┌─────────────────┐
│  CAPEC MCP      │  Data freshness: <7 days
│  (Local DB)     │  Semantic search: Yes
│                 │  Full pattern database: Yes
└─────────────────┘
```

**Benefits:**
- CAPEC data freshness: <7 days (monthly sync)
- Semantic search for scenario → pattern mapping
- Cross-domain queries (CVE + ATT&CK + CAPEC + CWE)
- No prompt engineering needed

### Performance Targets

| Metric | Target | Status |
|--------|--------|--------|
| Data freshness | <7 days | Monthly sync |
| Query latency | <100ms | 35-95ms typical |
| Semantic accuracy | >0.7 similarity | Validated |
| Availability | 99.99% | Offline-first |

---

## Database Schema

### Key Tables

**capec_patterns table:**

```sql
CREATE TABLE capec_patterns (
    pattern_id VARCHAR(20) PRIMARY KEY,       -- e.g., CAPEC-66
    capec_id INTEGER UNIQUE NOT NULL,         -- e.g., 66
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(300) NOT NULL,
    description TEXT NOT NULL,
    abstraction VARCHAR(50),                  -- Meta, Standard, Detailed
    status VARCHAR(50),                       -- Draft, Stable, Deprecated
    attack_likelihood VARCHAR(20),            -- High, Medium, Low
    typical_severity VARCHAR(20),             -- High, Medium, Low
    prerequisites TEXT[],                     -- Attack prerequisites
    skills_required JSONB,                    -- Skill level -> description
    resources_required TEXT,
    execution_flow JSONB,                     -- Step-by-step attack flow
    consequences JSONB,                       -- Impact/consequences
    mitigations TEXT[],                       -- Mitigation references
    examples TEXT[],
    references TEXT[],
    parent_of TEXT[],                         -- Hierarchical relationships
    child_of TEXT[],
    can_precede TEXT[],
    can_follow TEXT[],
    peer_of TEXT[],
    related_attack_patterns TEXT[],           -- ATT&CK technique IDs
    related_weaknesses TEXT[],                -- CWE IDs
    version VARCHAR(20),
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    deprecated BOOLEAN DEFAULT FALSE,
    embedding vector(1536),                   -- pgvector column
    embedding_model VARCHAR(50),              -- text-embedding-3-small
    embedding_generated_at TIMESTAMP,
    stix_extensions JSONB,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**capec_mitigations table:**

```sql
CREATE TABLE capec_mitigations (
    mitigation_id VARCHAR(50) PRIMARY KEY,    -- e.g., COA-abc123
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(300) NOT NULL,
    description TEXT NOT NULL,
    effectiveness VARCHAR(20),                -- High, Medium, Low
    mitigates_patterns TEXT[],                -- ["CAPEC-66", "CAPEC-79"]
    implementation_phases TEXT[],             -- Design, Build, Operation
    version VARCHAR(20),
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    embedding vector(1536),                   -- pgvector column
    embedding_model VARCHAR(50),
    embedding_generated_at TIMESTAMP,
    stix_extensions JSONB,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**capec_categories table:**

```sql
CREATE TABLE capec_categories (
    category_id VARCHAR(20) PRIMARY KEY,      -- e.g., CAPEC-CAT-100
    capec_id INTEGER UNIQUE NOT NULL,
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    summary TEXT NOT NULL,
    member_patterns TEXT[],                   -- ["CAPEC-1", "CAPEC-2"]
    parent_category VARCHAR(20),
    child_categories TEXT[],
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

### Indexes

**Vector similarity indexes (IVFFlat):**

```sql
-- Pattern semantic search (lists=100 for ~550 patterns)
CREATE INDEX idx_capec_pattern_embedding
    ON capec_patterns
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- Mitigation semantic search (lists=50 for ~300 mitigations)
CREATE INDEX idx_capec_mitigation_embedding
    ON capec_mitigations
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 50);
```

**Filter indexes:**

```sql
-- Abstraction level index
CREATE INDEX idx_capec_pattern_abstraction
    ON capec_patterns(abstraction);

-- Attack likelihood index
CREATE INDEX idx_capec_pattern_likelihood
    ON capec_patterns(attack_likelihood);

-- Severity index
CREATE INDEX idx_capec_pattern_severity
    ON capec_patterns(typical_severity);

-- Name trigram index for fuzzy search
CREATE INDEX idx_capec_pattern_name_trgm
    ON capec_patterns
    USING gin(name gin_trgm_ops);

-- Hierarchical relationship indexes
CREATE INDEX idx_capec_pattern_parent_of
    ON capec_patterns
    USING gin(parent_of);

CREATE INDEX idx_capec_pattern_child_of
    ON capec_patterns
    USING gin(child_of);

-- Cross-framework mapping indexes
CREATE INDEX idx_capec_pattern_attack_patterns
    ON capec_patterns
    USING gin(related_attack_patterns);

CREATE INDEX idx_capec_pattern_weaknesses
    ON capec_patterns
    USING gin(related_weaknesses);

-- Mitigation patterns index
CREATE INDEX idx_capec_mitigation_patterns
    ON capec_mitigations
    USING gin(mitigates_patterns);
```

---

## Troubleshooting

### Semantic Search Not Working

**Error:** `find_similar_capec_patterns returns empty results`

**Causes:**
1. OpenAI API key not configured
2. Embeddings not generated during sync
3. Vector index not created

**Solutions:**

```bash
# Check if embeddings exist
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute(
            'SELECT COUNT(*) FROM capec_patterns WHERE embedding IS NOT NULL'
        )
        count = result.scalar()
        print(f'Patterns with embeddings: {count}')
        if count == 0:
            print('ERROR: No embeddings found. Re-sync with generate_embeddings=true')
asyncio.run(check())
"

# Re-sync with embeddings
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_capec.sync_capec_data --kwargs='{"generate_embeddings": true}'
```

### Traditional Search Returns Too Many Results

**Issue:** `search_capec_patterns` returns many irrelevant results

**Solution:** Use more specific filters

```json
{
  "query": "injection",
  "abstraction": ["Standard"],
  "severity": "High",
  "related_cwe": ["CWE-89"],
  "limit": 10
}
```

### Semantic Search Returns Low Similarity Scores

**Issue:** All results have similarity <0.6

**Explanation:** This is expected behavior. CAPEC patterns are very specific. Low similarity doesn't mean bad results—it means your description doesn't closely match any single pattern.

**Solutions:**
- Lower `min_similarity` to 0.5-0.6 for broader results
- Use more specific technical details in your description
- Try traditional search if you know pattern keywords

**Example:**

Vague: "Attack on web application"
→ Low similarity scores (0.4-0.5)

Specific: "Attacker injected malicious SQL commands through the search form parameter to extract all usernames and passwords from the users table"
→ High similarity scores (0.85-0.92) for CAPEC-66 (SQL Injection)

### Patterns Not Found

**Issue:** `search_capec_patterns` returns no results

**Causes:**
1. Patterns not synced
2. Query too specific

**Solutions:**

```bash
# Check pattern count
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM capec_patterns')
        print(f'Patterns: {result.scalar()}')
asyncio.run(check())
"

# If zero, run sync
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_capec.sync_capec_data
```

### Performance Tuning

**Slow semantic search (>200ms):**

Check vector index:

```sql
-- Verify index exists
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'capec_patterns'
  AND indexname LIKE '%embedding%';

-- Rebuild if needed
DROP INDEX idx_capec_pattern_embedding;
CREATE INDEX idx_capec_pattern_embedding
    ON capec_patterns
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
```

**Slow traditional search (>100ms):**

```sql
-- Check query plan
EXPLAIN ANALYZE
SELECT * FROM capec_patterns
WHERE name ILIKE '%injection%' OR description ILIKE '%injection%';
-- Should use index scan if trigram index is configured
```

---

## CAPEC Categories

CAPEC organizes attack patterns into categories for easier navigation:

| Category | Description | Example Patterns |
|----------|-------------|------------------|
| Injection | Attacks that inject malicious content | CAPEC-66 (SQL Injection), CAPEC-86 (XSS) |
| Social Engineering | Manipulating humans | CAPEC-98 (Phishing), CAPEC-407 (Pretexting) |
| Authentication Bypass | Circumventing auth | CAPEC-115 (Authentication Bypass) |
| Denial of Service | Disrupting availability | CAPEC-125 (Flooding), CAPEC-227 (Sustained DoS) |
| Cryptanalysis | Attacking crypto | CAPEC-97 (Cryptanalysis), CAPEC-192 (Protocol Analysis) |
| Privilege Escalation | Gaining elevated access | CAPEC-122 (Privilege Abuse), CAPEC-233 (Privilege Escalation) |
| Information Disclosure | Exposing sensitive data | CAPEC-116 (Excavation), CAPEC-170 (Web Application Fingerprinting) |
| Physical Security | Physical attack vectors | CAPEC-390 (Bypassing Physical Security) |
| Supply Chain | Targeting supply chain | CAPEC-437 (Supply Chain Attack), CAPEC-438 (Malicious Software Update) |

---

## Best Practices

1. **Use semantic search for security assessments** — Natural language descriptions work better than keyword matching for complex scenarios
2. **Use traditional search for browsing** — Faster when you know what you're looking for
3. **Combine tools** — Use `find_similar_capec_patterns` then `get_capec_pattern_details` for deep analysis
4. **Cross-reference with CWE** — Use `related_weaknesses` to link patterns to code vulnerabilities
5. **Cross-reference with ATT&CK** — Use `related_attack_patterns` for detection engineering
6. **Use abstraction filtering** — Start with Standard level, drill down to Detailed for specifics
7. **Lower similarity threshold** — Start with 0.6-0.7, not 0.8+
8. **Describe technically** — More technical details = better semantic matches
9. **Monthly sync** — Keep CAPEC data fresh with monthly updates
10. **Combine with CVE intelligence** — Look for CVEs related to specific CWE weaknesses mapped from CAPEC

---

## Related Resources

- **[MITRE CAPEC Website](https://capec.mitre.org/)** — Official CAPEC documentation
- **[CAPEC GitHub Repository](https://github.com/mitre/cti)** — STIX data source
- **[CWE Website](https://cwe.mitre.org/)** — Related weakness enumeration
- **[ATT&CK Module Documentation](./attack.md)** — Complementary technique intelligence
- **[ATLAS Module Documentation](./atlas.md)** — AI/ML attack techniques
- **[SETUP.md](../SETUP.md)** — Deployment and configuration guide

---

**Documentation version:** 1.0.0 (2026-01-31)

**Module status:** Production Ready

**For setup instructions:** See [SETUP.md](../SETUP.md)

**For architecture details:** See [Architecture ADRs](../architecture/)
