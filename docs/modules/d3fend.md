# MITRE D3FEND Module

**Offline-first defensive countermeasures with AI-powered semantic search for security operations.**

## Overview

The D3FEND module provides comprehensive access to the MITRE D3FEND (Detection, Denial, and Disruption Framework Empowering Network Defense) framework with both traditional keyword search and AI-powered semantic similarity search. D3FEND provides a knowledge graph of cybersecurity defensive countermeasures that map directly to ATT&CK techniques, enabling defense-to-offense correlation.

### Key Features

- **158 Defensive Techniques** — Comprehensive catalog of security countermeasures
- **7 Defensive Tactics** — Model, Harden, Detect, Isolate, Deceive, Evict, Restore
- **100+ Digital Artifacts** — What techniques produce or analyze
- **ATT&CK Mappings** — Direct correlation to offensive techniques (counters, enables, related-to)
- **Dual Search Modes** — Traditional keyword search (<50ms) + AI semantic search (<100ms)
- **Coverage Analysis** — Assess your defensive posture against ATT&CK techniques
- **Cross-Framework Correlation** — Complete CVE → CWE → CAPEC → ATT&CK ↔ D3FEND chain
- **RAG Integration** — Fresh data (<7 days) for AI assistant workflows
- **Offline-First** — All queries run locally, no external API calls during runtime

### Data Coverage

| Category | Count | Description |
|----------|-------|-------------|
| Tactics | 7 | Defensive phases (Model, Harden, Detect, Isolate, Deceive, Evict, Restore) |
| Techniques | 158 | Defensive countermeasures with ATT&CK mappings |
| Artifacts | ~100 | Digital artifacts (files, network traffic, processes) |
| ATT&CK Mappings | 2,255 | D3FEND → ATT&CK technique correlations (via ontology graph) |
| Relationship Types | 5 | counters, enables, related-to, produces, uses |

### D3FEND vs ATT&CK

| Aspect | D3FEND | ATT&CK |
|--------|--------|--------|
| **Focus** | Defensive countermeasures | Offensive techniques |
| **Purpose** | How to defend | What adversaries do |
| **Scope** | Security controls | Threat techniques |
| **ID Format** | D3-AL (Application Lockdown) | T1566 (Phishing) |
| **Use Case** | Security architecture | Threat intelligence |
| **Audience** | Blue team, architects | SOC, IR, red team |

### D3FEND Tactics

D3FEND organizes defensive techniques into 7 tactics:

| Tactic | Description | Example Technique |
|--------|-------------|-------------------|
| **Model** | Understanding system components and behavior | D3-MA (Model Activity) |
| **Harden** | Reducing attack surface | D3-AL (Application Lockdown) |
| **Detect** | Identifying malicious activity | D3-DA (Detection Activity) |
| **Isolate** | Containing threats | D3-NI (Network Isolation) |
| **Deceive** | Misleading adversaries | D3-DCE (Decoy Environment) |
| **Evict** | Removing threats | D3-ER (Eviction Response) |
| **Restore** | Recovering from attacks | D3-RS (Restore) |

---

## Data Source

### Source Information

| Property | Value |
|----------|-------|
| **Format** | MISP Galaxy JSON |
| **URL** | https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-d3fend.json |
| **Update Frequency** | Quarterly (MITRE releases) |
| **License** | Apache 2.0 |
| **Maintainer** | MITRE Corporation |

### Why MISP Galaxy Format?

D3FEND data is available in multiple formats. We use the MISP Galaxy JSON because:
- Pre-processed and normalized
- Includes ATT&CK technique mappings via tags
- Maintained by active security community
- Consistent with other MISP galaxy integrations

---

## Database Schema

The D3FEND module uses 5 database tables:

### d3fend_tactics

Stores the 7 defensive tactic categories.

```sql
CREATE TABLE d3fend_tactics (
    tactic_id VARCHAR(20) PRIMARY KEY,        -- D3-MODEL, D3-HARDEN, etc.
    name VARCHAR(200) NOT NULL,                -- Model, Harden, Detect, etc.
    description TEXT,
    display_order INTEGER NOT NULL,            -- For matrix rendering
    created TIMESTAMP,
    modified TIMESTAMP,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

### d3fend_techniques

Stores defensive techniques with semantic search via HNSW vector index.

```sql
CREATE TABLE d3fend_techniques (
    technique_id VARCHAR(20) PRIMARY KEY,      -- D3-AL, D3-NI, etc.
    name VARCHAR(300) NOT NULL,                -- Application Lockdown
    description TEXT NOT NULL,                 -- Full definition
    tactic_id VARCHAR(20) REFERENCES d3fend_tactics(tactic_id),
    parent_id VARCHAR(20) REFERENCES d3fend_techniques(technique_id),
    synonyms TEXT[],                           -- Alternative names
    references JSONB,                          -- [{title, url, authors}]
    kb_article_url VARCHAR(500),               -- d3fend.mitre.org link
    d3fend_version VARCHAR(20),                -- Dataset version
    deprecated BOOLEAN DEFAULT FALSE,
    embedding vector(1536),                    -- pgvector column (text-embedding-3-small)
    embedding_model VARCHAR(50),
    embedding_generated_at TIMESTAMP,
    created TIMESTAMP,
    modified TIMESTAMP,
    data_last_updated TIMESTAMP DEFAULT NOW()
);

-- HNSW index for small dataset (~200 techniques) - no training required
CREATE INDEX idx_d3fend_embedding ON d3fend_techniques
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Trigram index for fuzzy name search
CREATE INDEX idx_d3fend_name_trgm ON d3fend_techniques
    USING gin (name gin_trgm_ops);
```

### d3fend_artifacts

Stores digital artifacts that techniques interact with.

```sql
CREATE TABLE d3fend_artifacts (
    artifact_id VARCHAR(50) PRIMARY KEY,       -- d3f:File, d3f:NetworkTraffic
    name VARCHAR(200) NOT NULL,
    description TEXT,
    artifact_type VARCHAR(50)                  -- DigitalArtifact, NetworkTraffic
);
```

### d3fend_technique_attack_mappings

The core correlation table enabling defense-to-offense mapping.

```sql
CREATE TABLE d3fend_technique_attack_mappings (
    mapping_id SERIAL PRIMARY KEY,
    d3fend_technique_id VARCHAR(20) REFERENCES d3fend_techniques(technique_id),
    attack_technique_id VARCHAR(20) REFERENCES attack_techniques(technique_id),
    relationship_type d3fend_relationship_type NOT NULL,  -- counters, enables, etc.
    UNIQUE(d3fend_technique_id, attack_technique_id, relationship_type)
);

-- Index for reverse lookups (find defenses for an attack technique)
CREATE INDEX idx_d3fend_attack_mapping ON d3fend_technique_attack_mappings(attack_technique_id);
```

### d3fend_technique_artifacts

Join table between techniques and artifacts.

```sql
CREATE TABLE d3fend_technique_artifacts (
    technique_id VARCHAR(20) REFERENCES d3fend_techniques(technique_id),
    artifact_id VARCHAR(50) REFERENCES d3fend_artifacts(artifact_id),
    relationship_type d3fend_artifact_relationship_type,  -- produces, uses, analyzes
    PRIMARY KEY (technique_id, artifact_id, relationship_type)
);
```

---

## MCP Tools

The D3FEND module provides 5 MCP tools divided into traditional search, semantic search, and cross-framework categories.

### Traditional Search Tools

#### 1. search_defenses

**Description:** Search MITRE D3FEND defensive techniques using traditional keyword and filter-based search. Filter by D3FEND tactics: Model, Harden, Detect, Isolate, Deceive, Evict, Restore.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_defenses",
  "arguments": {
    "query": "network isolation",
    "tactic": ["Isolate", "Harden"],
    "include_children": false,
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "defenses": [
      {
        "technique_id": "D3-NI",
        "name": "Network Isolation",
        "description": "Network isolation restricts network communication...",
        "tactic_id": "D3-ISOLATE",
        "deprecated": false,
        "badge_url": "https://d3fend.mitre.org/technique/D3-NI/"
      },
      {
        "technique_id": "D3-DNSAL",
        "name": "DNS Allowlisting",
        "description": "DNS allowlisting restricts DNS queries to approved domains...",
        "tactic_id": "D3-HARDEN",
        "deprecated": false,
        "badge_url": "https://d3fend.mitre.org/technique/D3-DNSAL/"
      }
    ],
    "total_results": 8,
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
| `query` | string | Yes | Full-text search in name/description |
| `tactic` | array | No | Filter by D3FEND tactics (e.g., ["Harden", "Detect"]) |
| `include_children` | boolean | No | Include child techniques of matches (default: false) |
| `limit` | integer | No | Max results (default: 50, max: 500) |

**Use Cases:**
- Find defensive techniques by name or description keywords
- Filter by specific defensive phases (tactics)
- Hierarchical search including child techniques
- Browse the D3FEND framework by category

---

#### 2. get_defense_details

**Description:** Get complete details for a specific D3FEND defensive technique including description, tactic, ATT&CK mappings, synonyms, references, and knowledge base article URL.

**Performance:** <30ms average latency

**Example Request:**

```json
{
  "name": "get_defense_details",
  "arguments": {
    "technique_id": "D3-AL"
  }
}
```

**Example Response:**

```json
{
  "data": {
    "technique_id": "D3-AL",
    "name": "Application Lockdown",
    "description": "Application lockdown restricts which applications can execute on a system...",
    "tactic_id": "D3-HARDEN",
    "tactic_name": "Harden",
    "parent_id": null,
    "synonyms": ["Application Whitelisting", "Application Control"],
    "references": [
      {"url": "https://www.nist.gov/publications/guide-application-whitelisting"}
    ],
    "kb_article_url": "https://d3fend.mitre.org/technique/d3f:ApplicationLockdown/",
    "d3fend_version": "0.15.0",
    "deprecated": false,
    "created": "2021-01-15T00:00:00",
    "modified": "2024-06-01T00:00:00",
    "badge_url": "https://d3fend.mitre.org/technique/D3-AL/",
    "embedding_generated": true,
    "attack_mappings": [
      {"attack_technique_id": "T1059", "relationship_type": "counters"},
      {"attack_technique_id": "T1204", "relationship_type": "counters"},
      {"attack_technique_id": "T1203", "relationship_type": "counters"}
    ],
    "attack_mappings_count": 12
  },
  "metadata": {
    "query_time_ms": 28
  }
}
```

**Use Cases:**
- Deep-dive analysis of specific defensive techniques
- Understanding which ATT&CK techniques a defense counters
- Security architecture planning
- Documentation and compliance reporting

---

### Semantic Search Tools

#### 3. find_similar_defenses

**Description:** Find MITRE D3FEND defensive techniques using AI-powered semantic similarity search. Describe a defensive need or security control in natural language and get matching D3FEND techniques with similarity scores.

**Performance:** <100ms average latency

**Requirements:** OpenAI API key configured (OPENAI_API_KEY environment variable)

**Example Request:**

```json
{
  "name": "find_similar_defenses",
  "arguments": {
    "description": "network segmentation to prevent lateral movement between systems",
    "min_similarity": 0.7,
    "tactic": ["Isolate"],
    "limit": 5
  }
}
```

**Example Response:**

```json
{
  "data": {
    "defenses": [
      {
        "technique_id": "D3-NI",
        "name": "Network Isolation",
        "description": "Network isolation restricts network communication...",
        "tactic_id": "D3-ISOLATE",
        "deprecated": false,
        "badge_url": "https://d3fend.mitre.org/technique/D3-NI/",
        "similarity_score": 0.89
      },
      {
        "technique_id": "D3-ISVA",
        "name": "Inbound Session Volume Analysis",
        "description": "Analyzing inbound session volumes to detect anomalies...",
        "tactic_id": "D3-DETECT",
        "deprecated": false,
        "badge_url": "https://d3fend.mitre.org/technique/D3-ISVA/",
        "similarity_score": 0.74
      }
    ],
    "returned_results": 2,
    "query_embedding_generated": true,
    "min_similarity": 0.7
  },
  "metadata": {
    "query_time_ms": 85
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | string | Yes | Natural language description of defensive need (10-5000 chars) |
| `min_similarity` | float | No | Minimum similarity threshold (default: 0.7, range: 0-1) |
| `tactic` | array | No | Filter by D3FEND tactics |
| `limit` | integer | No | Max results (default: 10, max: 100) |

**Use Cases:**
- **Security Architecture:** Describe security requirements, get matching D3FEND techniques
- **Gap Analysis:** Find defenses for specific security scenarios
- **Compliance Mapping:** Map control requirements to D3FEND techniques
- **Training:** Learn D3FEND classifications from practical examples

---

### Cross-Framework Tools

#### 4. get_defenses_for_attack

**Description:** Find D3FEND countermeasures for a specific ATT&CK technique. **KEY FEATURE:** answers "How do I defend against this attack?" Returns defensive techniques that counter the specified attack, optionally including defenses for all subtechniques.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "get_defenses_for_attack",
  "arguments": {
    "attack_technique_id": "T1059",
    "include_subtechniques": true,
    "relationship_type": ["counters"]
  }
}
```

**Example Response:**

```json
{
  "data": {
    "defenses": [
      {
        "technique_id": "D3-AL",
        "name": "Application Lockdown",
        "description": "Application lockdown restricts which applications can execute...",
        "tactic_id": "D3-HARDEN",
        "deprecated": false,
        "badge_url": "https://d3fend.mitre.org/technique/D3-AL/",
        "defends_against": [
          {"attack_technique_id": "T1059", "relationship_type": "counters"},
          {"attack_technique_id": "T1059.001", "relationship_type": "counters"}
        ]
      },
      {
        "technique_id": "D3-SEA",
        "name": "Script Execution Analysis",
        "description": "Script execution analysis monitors script interpreter activity...",
        "tactic_id": "D3-DETECT",
        "deprecated": false,
        "badge_url": "https://d3fend.mitre.org/technique/D3-SEA/",
        "defends_against": [
          {"attack_technique_id": "T1059.001", "relationship_type": "counters"}
        ]
      }
    ],
    "returned_results": 5,
    "attack_technique_id": "T1059",
    "include_subtechniques": true
  },
  "metadata": {
    "query_time_ms": 42
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `attack_technique_id` | string | Yes | ATT&CK technique ID (e.g., "T1059" or "T1059.001") |
| `include_subtechniques` | boolean | No | Also find defenses for subtechniques (default: true) |
| `relationship_type` | array | No | Filter by relationship type: counters, enables, related-to, produces, uses |

**Use Cases:**
- **Incident Response:** "We detected T1059 (PowerShell) — what defenses should we prioritize?"
- **Threat Modeling:** Map attack scenarios to defensive controls
- **Security Architecture:** Design defense-in-depth for specific threats
- **Purple Team:** Validate defenses against specific attack techniques

---

#### 5. get_attack_coverage

**Description:** Analyze ATT&CK coverage for given D3FEND techniques. Helps assess defensive posture by showing which ATT&CK techniques are covered by your defenses and identifying gaps.

**Performance:** <100ms average latency

**Example Request:**

```json
{
  "name": "get_attack_coverage",
  "arguments": {
    "technique_ids": ["D3-AL", "D3-NI", "D3-SEA"],
    "show_gaps": true
  }
}
```

**Example Response:**

```json
{
  "data": {
    "covered_techniques": ["T1059", "T1059.001", "T1059.003", "T1021", "T1021.001"],
    "coverage_details": {
      "T1059": [
        {
          "d3fend_technique_id": "D3-AL",
          "d3fend_technique_name": "Application Lockdown",
          "relationship_type": "counters"
        }
      ],
      "T1059.001": [
        {
          "d3fend_technique_id": "D3-AL",
          "d3fend_technique_name": "Application Lockdown",
          "relationship_type": "counters"
        },
        {
          "d3fend_technique_id": "D3-SEA",
          "d3fend_technique_name": "Script Execution Analysis",
          "relationship_type": "counters"
        }
      ]
    },
    "total_covered": 5,
    "gaps": ["T1566", "T1566.001", "T1078", "T1078.001", "T1110"],
    "total_gaps": 695,
    "coverage_percentage": 0.71
  },
  "metadata": {
    "query_time_ms": 95
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `technique_ids` | array | Yes | List of D3FEND technique IDs to analyze |
| `show_gaps` | boolean | No | Include list of uncovered ATT&CK techniques (default: true) |

**Use Cases:**
- **Security Posture Assessment:** "What percentage of ATT&CK are we defending against?"
- **Gap Analysis:** Identify which attack techniques lack defensive coverage
- **Investment Planning:** Prioritize new security controls based on coverage gaps
- **Compliance Reporting:** Demonstrate defensive coverage to auditors

---

## Usage Examples

### Finding Defenses for Specific Attacks

```python
import anthropic

client = anthropic.Anthropic()

# Step 1: Find defenses for a specific attack technique
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": "Find D3FEND defenses for ATT&CK technique T1059 (Command and Scripting Interpreter)"
    }]
)
# Claude uses get_defenses_for_attack tool automatically
# Returns: D3-AL (Application Lockdown), D3-SEA (Script Execution Analysis), etc.

# Step 2: Get detailed information on recommended defenses
for d3fend_id in ["D3-AL", "D3-SEA"]:
    details = client.messages.create(
        model="claude-sonnet-4.5",
        messages=[{
            "role": "user",
            "content": f"Get full details for D3FEND technique {d3fend_id}"
        }]
    )
    # Returns complete technique information with references
```

### Assessing Defensive Coverage

```python
# Analyze current defensive posture
query = """
We have implemented these D3FEND techniques:
- D3-AL (Application Lockdown)
- D3-NI (Network Isolation)
- D3-SEA (Script Execution Analysis)
- D3-PCA (Process Code Analysis)

What's our ATT&CK coverage and what are the biggest gaps?
"""

response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{"role": "user", "content": query}]
)
# Claude uses get_attack_coverage tool
# Returns coverage percentage and gap analysis
```

### Semantic Search for Security Controls

```python
# Describe a defensive need in natural language
query = """
Find D3FEND techniques that would help with:
- Preventing unauthorized code execution
- Detecting suspicious process behavior
- Blocking lateral movement attempts
"""

response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{"role": "user", "content": query}]
)
# Claude uses find_similar_defenses tool
# Returns matching techniques with similarity scores
```

---

## Cross-Framework Correlation

### Complete Threat Intelligence Chain

The D3FEND module completes the threat intelligence chain by adding defensive correlation:

```
CVE-2021-44228 (Log4Shell)
       │
       ▼ (get_cve_details)
   CWE-917 (Expression Language Injection)
   CWE-20 (Improper Input Validation)
       │
       ▼ (get_cwe_weakness_details)
   CAPEC-135 (Format String Injection)
   CAPEC-242 (Code Injection)
       │
       ▼ (get_capec_pattern_details)
   T1059 (Command and Scripting Interpreter)
   T1190 (Exploit Public-Facing Application)
       │
       ▼ (get_defenses_for_attack)  ← D3FEND
   D3-AL (Application Lockdown)
   D3-SEA (Script Execution Analysis)
```

### Example: Building the Complete Chain

```python
# Complete threat intelligence chain
query = """
For CVE-2021-44228 (Log4Shell):
1. What CWE weaknesses are involved?
2. What CAPEC attack patterns exploit these weaknesses?
3. What ATT&CK techniques would an attacker use?
4. What D3FEND defenses counter these attacks?
"""

response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{"role": "user", "content": query}]
)

# Claude automatically chains:
# 1. get_cve_details("CVE-2021-44228") → CWE-917, CWE-20
# 2. get_cwe_weakness_details → related CAPEC patterns
# 3. get_capec_pattern_details → related ATT&CK techniques
# 4. get_defenses_for_attack → D3FEND countermeasures
# Returns unified vulnerability-to-defense analysis
```

---

## Data Sync

### Manual Sync Commands

**Sync D3FEND data WITHOUT embeddings (faster):**

```bash
# Download + parse only (1-2 minutes)
python scripts/sync_d3fend_data.py --no-embeddings

# Or using docker-compose
docker-compose exec celery-worker python -c "
import asyncio
from cve_mcp.models.base import AsyncSessionLocal
from cve_mcp.tasks.sync_d3fend import sync_d3fend_data

async def sync():
    async with AsyncSessionLocal() as session:
        result = await sync_d3fend_data(session, generate_embeddings=False)
        print(f'Synced {result}')

asyncio.run(sync())
"
```

**Sync D3FEND data WITH embeddings (semantic search):**

```bash
# Download + parse + generate embeddings (5-10 minutes)
# Requires OPENAI_API_KEY in environment
python scripts/sync_d3fend_data.py

# Verify sync
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM d3fend_techniques')
        print(f'Techniques: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM d3fend_technique_attack_mappings')
        print(f'ATT&CK mappings: {result.scalar()}')
        result = await session.execute(
            'SELECT COUNT(*) FROM d3fend_techniques WHERE embedding IS NOT NULL'
        )
        print(f'Techniques with embeddings: {result.scalar()}')
asyncio.run(check())
"
```

### Prerequisites

**Important:** ATT&CK data should be synced before D3FEND to properly validate D3FEND → ATT&CK foreign key mappings.

```bash
# Sync ATT&CK first
python scripts/sync_attack_data.py

# Then sync D3FEND
python scripts/sync_d3fend_data.py
```

### Expected Durations

| Operation | Duration | Notes |
|-----------|----------|-------|
| Download JSON data | 10-30 sec | ~1 MB from GitHub |
| Parse + insert tactics | 5 sec | 7 tactics |
| Parse + insert techniques | 30 sec | 158 techniques |
| Validate ATT&CK mappings | 15 sec | FK validation, 2,255 mappings |
| Generate embeddings | 3-5 min | OpenAI API, ~158 requests |
| **Total (with embeddings)** | **5-10 min** | One-time cost |
| **Total (without embeddings)** | **1-2 min** | Traditional search only |

### Recommendations

- **Development:** Sync without embeddings for faster iteration
- **Production:** Sync with embeddings for full semantic search capabilities
- **Scheduled:** Run quarterly after MITRE D3FEND releases
- **Dependency:** Always sync ATT&CK data before D3FEND

---

## Performance Metrics

### Query Latency (p95)

| Operation | Target | Typical | Notes |
|-----------|--------|---------|-------|
| `search_defenses` | <50ms | 30-45ms | PostgreSQL ILIKE + trigram |
| `find_similar_defenses` | <100ms | 70-90ms | HNSW vector similarity |
| `get_defense_details` | <30ms | 20-28ms | Indexed lookup |
| `get_defenses_for_attack` | <50ms | 35-48ms | Join with FK index |
| `get_attack_coverage` | <100ms | 80-95ms | Aggregation query |

### Database Size

| Component | Size | Details |
|-----------|------|---------|
| D3FEND tactics | ~0.01 MB | 7 records |
| D3FEND techniques | ~2 MB | 158 records with descriptions |
| D3FEND artifacts | ~0.5 MB | ~100 records |
| ATT&CK mappings | ~1.5 MB | 2,255 relationship records (ontology-derived) |
| Technique embeddings | ~3 MB | 1536-dim vectors (text-embedding-3-small) |
| Indexes (HNSW + GIN) | ~1 MB | Vector + trigram indexes |
| **Total D3FEND module** | **~7 MB** | Minimal overhead |

### Embedding Generation Cost

Using OpenAI `text-embedding-3-small` model:

| Item | Count | Cost per 1M tokens | Total Cost |
|------|-------|-------------------|------------|
| Technique embeddings | 158 | $0.02 | ~$0.03 |
| **Total (one-time)** | **158** | - | **~$0.03** |

**Quarterly refresh cost:** ~$0.04

---

## Troubleshooting

### Semantic Search Not Working

**Error:** `find_similar_defenses returns empty results`

**Causes:**
1. OpenAI API key not configured
2. Embeddings not generated during sync
3. HNSW index not created

**Solutions:**

```bash
# Check if embeddings exist
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute(
            'SELECT COUNT(*) FROM d3fend_techniques WHERE embedding IS NOT NULL'
        )
        count = result.scalar()
        print(f'Techniques with embeddings: {count}')
        if count == 0:
            print('ERROR: No embeddings found. Re-sync with generate_embeddings=True')
asyncio.run(check())
"

# Re-sync with embeddings
python scripts/sync_d3fend_data.py
```

### ATT&CK Mappings Not Found

**Issue:** `get_defenses_for_attack` returns empty results

**Causes:**
1. D3FEND data not synced
2. ATT&CK data not synced (FK validation failed)
3. No D3FEND techniques map to that ATT&CK technique

**Solutions:**

```bash
# Check mapping count
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM d3fend_technique_attack_mappings')
        print(f'Total mappings: {result.scalar()}')
asyncio.run(check())
"

# Verify ATT&CK technique exists
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute(
            \"SELECT technique_id FROM attack_techniques WHERE technique_id = 'T1059'\"
        )
        print(f'Found: {result.scalar()}')
asyncio.run(check())
"
```

### Coverage Analysis Shows 0%

**Issue:** `get_attack_coverage` returns 0% coverage

**Causes:**
1. Invalid D3FEND technique IDs provided
2. D3FEND IDs not normalized (should be D3-XX format)

**Solution:** Ensure technique IDs use D3- prefix:

```json
// Correct
{"technique_ids": ["D3-AL", "D3-NI"]}

// Also correct (auto-normalized)
{"technique_ids": ["AL", "NI"]}

// Incorrect
{"technique_ids": ["Application Lockdown"]}
```

---

## Best Practices

1. **Use `get_defenses_for_attack` for incident response** — Quickly find defenses for observed attacks
2. **Use semantic search for security requirements** — Natural language works better than keywords
3. **Combine tools** — Use `find_similar_defenses` then `get_defense_details` for deep analysis
4. **Assess coverage regularly** — Use `get_attack_coverage` to identify defensive gaps
5. **Cross-reference with ATT&CK** — Link defensive planning to threat intelligence
6. **Monthly sync** — Keep D3FEND data fresh with quarterly updates (more frequent for edge cases)
7. **Lower similarity threshold** — Start with 0.6-0.7, not 0.8+
8. **Build complete chains** — Use CVE → CWE → CAPEC → ATT&CK → D3FEND for comprehensive analysis

---

## Related Resources

- **[MITRE D3FEND Website](https://d3fend.mitre.org/)** — Official D3FEND documentation
- **[D3FEND Knowledge Graph](https://d3fend.mitre.org/ontology/)** — Full ontology browser
- **[MISP Galaxy D3FEND](https://github.com/MISP/misp-galaxy)** — Data source
- **[ATT&CK Module Documentation](./attack.md)** — Offensive technique intelligence
- **[CAPEC Module Documentation](./capec.md)** — Attack pattern intelligence
- **[CWE Module Documentation](./cwe.md)** — Software weakness intelligence
- **[SETUP.md](../SETUP.md)** — Deployment and configuration guide

---

**Documentation version:** 1.0.0 (2026-01-31)

**Module status:** Production Ready

**For setup instructions:** See [SETUP.md](../SETUP.md)

**For architecture details:** See [Architecture ADRs](../architecture/)
