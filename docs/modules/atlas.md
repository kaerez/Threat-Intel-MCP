# MITRE ATLAS Module

**Offline-first AI/ML security framework with AI-powered semantic search for adversarial machine learning threats.**

## Overview

The ATLAS module provides comprehensive access to the MITRE ATLAS (Adversarial Threat Landscape for Artificial Intelligence Systems) framework with both traditional keyword search and AI-powered semantic similarity search. All queries run against a local PostgreSQL database with pgvector for semantic search capabilities.

### Key Features

- **200+ ATLAS Techniques** — Adversarial ML attack techniques across the AI/ML lifecycle
- **14 Tactics** — ML attack kill chain from Reconnaissance to Impact
- **30+ Case Studies** — Real-world AI/ML security incidents with technique mappings
- **ML Lifecycle Filtering** — Filter by data collection, training, deployment stages
- **AI System Type Filtering** — Filter by computer vision, NLP, recommendation systems
- **Dual Search Modes** — Traditional keyword search (<50ms) + AI semantic search (<100ms)
- **Cross-Domain Queries** — Combine CVE + ATT&CK + ATLAS intelligence
- **RAG Integration** — Fresh data (<7 days) for AI assistant workflows
- **Offline-First** — All queries run locally, no external API calls during runtime

### Data Coverage

| Category | Count | Description |
|----------|-------|-------------|
| Techniques | 200+ | AI/ML attack techniques |
| Tactics | 14 | ML kill chain phases |
| Case Studies | 30+ | Real-world AI/ML incidents |
| ML Lifecycle Stages | 5+ | Data collection, training, deployment, inference, maintenance |
| AI System Types | 10+ | Computer vision, NLP, speech, recommendation, robotics, etc. |

### ATLAS vs ATT&CK

| Aspect | ATLAS | ATT&CK |
|--------|-------|--------|
| **Focus** | AI/ML systems | Traditional IT systems |
| **Techniques** | Adversarial ML attacks | Enterprise cyber attacks |
| **Kill Chain** | ML-specific lifecycle | Traditional cyber kill chain |
| **ID Format** | AML.T0001 | T1566 |
| **Case Studies** | Real-world AI incidents | Threat actor campaigns |
| **Use Case** | AI/ML security | Enterprise security |

---

## MCP Tools

The ATLAS module provides 5 MCP tools divided into traditional search and semantic search categories.

### Traditional Search Tools

#### 1. search_atlas_techniques

**Description:** Search MITRE ATLAS AI/ML attack techniques using keyword and filter-based search.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_atlas_techniques",
  "arguments": {
    "query": "data poisoning",
    "tactics": ["ml-attack-staging"],
    "ml_lifecycle_stage": "training",
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "techniques": [
      {
        "technique_id": "AML.T0020",
        "name": "Poison Training Data",
        "description": "Adversaries may attempt to poison training data used by an ML model...",
        "tactics": ["ml-attack-staging"],
        "ml_lifecycle_stage": "training",
        "ai_system_type": ["computer-vision", "nlp"],
        "deprecated": false,
        "revoked": false,
        "badge_url": "https://atlas.mitre.org/techniques/AML.T0020"
      }
    ],
    "total_results": 5,
    "returned_results": 5
  },
  "metadata": {
    "query_time_ms": 38,
    "timestamp": "2026-01-31T13:00:00Z"
  }
}
```

**Use Cases:**
- Find techniques by name or description keywords
- Filter by specific tactics (e.g., only ML attack staging techniques)
- ML lifecycle stage filtering (training, deployment, inference)
- AI system type discovery (computer vision, NLP, robotics)

---

#### 2. get_atlas_technique_details

**Description:** Get complete details for a specific MITRE ATLAS technique.

**Performance:** <30ms average latency

**Example Request:**

```json
{
  "name": "get_atlas_technique_details",
  "arguments": {
    "technique_id": "AML.T0020"
  }
}
```

**Example Response:**

```json
{
  "data": {
    "technique_id": "AML.T0020",
    "stix_id": "attack-pattern--abc123",
    "name": "Poison Training Data",
    "description": "Adversaries may attempt to poison training data used by an ML model to cause the model to learn incorrect patterns or biases. This can be done by injecting malicious samples into the training dataset, modifying existing samples, or influencing the data collection process.",
    "tactics": ["ml-attack-staging"],
    "ml_lifecycle_stage": "training",
    "ai_system_type": ["computer-vision", "nlp", "recommendation"],
    "detection": "Monitor training data for anomalies, implement data validation, track data provenance...",
    "mitigation": "Implement robust data validation, use data sanitization, employ anomaly detection on training data...",
    "version": "1.1",
    "created": "2022-03-01T00:00:00",
    "modified": "2024-06-15T00:00:00",
    "deprecated": false,
    "revoked": false,
    "badge_url": "https://atlas.mitre.org/techniques/AML.T0020",
    "embedding_generated": true
  },
  "metadata": {
    "query_time_ms": 25
  }
}
```

**Use Cases:**
- Deep-dive analysis of specific AI/ML attack techniques
- Detection engineering (data sources + detection guidance)
- Mitigation planning (recommended controls for AI/ML systems)
- Documentation and reporting for AI security assessments

---

#### 3. search_atlas_case_studies

**Description:** Search MITRE ATLAS real-world case studies of AI/ML attacks.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_atlas_case_studies",
  "arguments": {
    "query": "autonomous vehicle",
    "techniques": ["AML.T0020"],
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "case_studies": [
      {
        "case_study_id": "AML.CS0003",
        "name": "Adversarial Attack on Tesla Autopilot",
        "summary": "Researchers demonstrated adversarial attacks on Tesla's Autopilot system using physical perturbations on road signs...",
        "techniques_used": ["AML.T0020", "AML.T0015"],
        "incident_date": "2019-04-01",
        "target_system": "Tesla Autopilot"
      }
    ],
    "total_results": 3,
    "returned_results": 3
  },
  "metadata": {
    "query_time_ms": 42
  }
}
```

**Use Cases:**
- Research real-world AI/ML security incidents
- Find case studies involving specific techniques
- Understand attack patterns against production AI systems
- Learn from documented AI security failures

---

### Semantic Search Tools

#### 4. find_similar_atlas_techniques

**Description:** Find MITRE ATLAS techniques using AI-powered semantic similarity search. Perfect for AI/ML security assessments—describe an adversarial attack scenario in natural language and get matching techniques.

**Performance:** <100ms average latency

**Requirements:** OpenAI API key configured (OPENAI_API_KEY environment variable)

**Example Request:**

```json
{
  "name": "find_similar_atlas_techniques",
  "arguments": {
    "description": "Attacker injected malicious images into our training dataset that cause the model to misclassify stop signs as speed limit signs",
    "min_similarity": 0.7,
    "limit": 5
  }
}
```

**Example Response:**

```json
{
  "data": {
    "techniques": [
      {
        "technique_id": "AML.T0020",
        "name": "Poison Training Data",
        "description": "Adversaries may attempt to poison training data used by an ML model...",
        "similarity_score": 0.91,
        "tactics": ["ml-attack-staging"],
        "ml_lifecycle_stage": "training",
        "ai_system_type": ["computer-vision"],
        "badge_url": "https://atlas.mitre.org/techniques/AML.T0020"
      },
      {
        "technique_id": "AML.T0019",
        "name": "Backdoor ML Model",
        "description": "Adversaries may embed a backdoor in an ML model...",
        "similarity_score": 0.85,
        "tactics": ["ml-attack-staging"],
        "ml_lifecycle_stage": "training",
        "ai_system_type": ["computer-vision", "nlp"],
        "badge_url": "https://atlas.mitre.org/techniques/AML.T0019"
      }
    ],
    "returned_results": 2,
    "query_embedding_generated": true,
    "min_similarity": 0.7
  },
  "metadata": {
    "query_time_ms": 87
  }
}
```

**Use Cases:**
- **AI Security Assessments:** Describe observed attack behavior, get matching techniques
- **Threat Modeling:** Map adversarial ML scenarios to ATLAS framework
- **Detection Gap Analysis:** Find techniques similar to detected attacks
- **Red Team Exercises:** Map AI/ML attack activities to ATLAS

---

#### 5. find_similar_atlas_case_studies

**Description:** Find similar MITRE ATLAS case studies using AI-powered semantic similarity search. Describe an AI/ML incident or attack scenario and get matching real-world case studies.

**Performance:** <100ms average latency

**Requirements:** OpenAI API key configured

**Example Request:**

```json
{
  "name": "find_similar_atlas_case_studies",
  "arguments": {
    "description": "Our autonomous vehicle's object detection system was fooled by adversarial patches placed on road signs",
    "min_similarity": 0.65,
    "limit": 5
  }
}
```

**Example Response:**

```json
{
  "data": {
    "case_studies": [
      {
        "case_study_id": "AML.CS0003",
        "name": "Adversarial Attack on Tesla Autopilot",
        "summary": "Researchers demonstrated adversarial attacks on Tesla's Autopilot system using physical perturbations on road signs...",
        "techniques_used": ["AML.T0020", "AML.T0015"],
        "incident_date": "2019-04-01",
        "target_system": "Tesla Autopilot",
        "similarity_score": 0.88
      },
      {
        "case_study_id": "AML.CS0007",
        "name": "Adversarial Stop Sign Attack",
        "summary": "Researchers demonstrated how adversarial perturbations can cause object detection systems to misclassify stop signs...",
        "techniques_used": ["AML.T0015", "AML.T0018"],
        "incident_date": "2018-08-15",
        "target_system": "Object Detection System",
        "similarity_score": 0.82
      }
    ],
    "returned_results": 2,
    "query_embedding_generated": true,
    "min_similarity": 0.65
  },
  "metadata": {
    "query_time_ms": 92
  }
}
```

**Use Cases:**
- **Incident Response:** Find similar real-world incidents to understand attack patterns
- **Threat Intelligence:** Research AI/ML attack trends and precedents
- **Risk Assessment:** Understand potential impacts from similar incidents
- **Executive Briefings:** Reference documented incidents for stakeholder communication

---

## Semantic Search vs Traditional Search

### Comparison Table

| Feature | Traditional Search | Semantic Search |
|---------|-------------------|-----------------|
| **Query Type** | Keywords, filters | Natural language descriptions |
| **Matching** | Exact keyword matches | Contextual similarity |
| **Latency** | <50ms | <100ms |
| **Use Case** | Known technique lookup | AI security assessment, mapping scenarios |
| **Requirements** | None | OpenAI API key |
| **Best For** | Specific technique research | Discovering relevant techniques from description |

### When to Use Each

**Use Traditional Search (`search_atlas_techniques`) when:**
- You know the technique name or ID
- You want to filter by specific tactics/ML lifecycle stages
- You need fastest possible results
- You're browsing the ATLAS framework

**Use Semantic Search (`find_similar_atlas_techniques`) when:**
- You have an AI/ML security incident description
- You want to discover relevant techniques without knowing exact names
- You're mapping real-world attacks to ATLAS
- You're doing AI/ML threat modeling or red team exercises

**Example Scenario:**

Traditional: "Find all data poisoning techniques for training phase"
```json
{"query": "poison", "ml_lifecycle_stage": "training"}
```

Semantic: "Attacker modified our image dataset to create a backdoor that activates when specific patterns appear"
```json
{"description": "Attacker modified our image dataset to create a backdoor that activates when specific patterns appear"}
```
Returns AML.T0020 (Poison Training Data), AML.T0019 (Backdoor ML Model) with high similarity

---

## Example Workflows

### AI/ML Security Assessment with Semantic Search

```python
import anthropic

client = anthropic.Anthropic()

# Step 1: Describe the AI/ML attack scenario
scenario = """
Security assessment finding: We discovered that our image classification
model sometimes misclassifies specific images in unexpected ways.
Investigation revealed unusual patterns in training data that may have
been injected during data collection from crowdsourced labeling.
"""

# Step 2: Find matching techniques
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"Find ATLAS techniques for this AI security finding: {scenario}"
    }]
)
# Claude uses find_similar_atlas_techniques tool automatically
# Returns: AML.T0020 (Poison Training Data), AML.T0019 (Backdoor ML Model)

# Step 3: Get detailed mitigation guidance
for technique_id in ["AML.T0020", "AML.T0019"]:
    details = client.messages.create(
        model="claude-sonnet-4.5",
        messages=[{
            "role": "user",
            "content": f"Get detection and mitigation methods for {technique_id}"
        }]
    )
    # Returns detection strategies, mitigations, ML lifecycle context
```

### Cross-Domain Query: CVE + ATLAS

```python
# Find CVE details and related AI/ML attack techniques
query = """
1. Search for CVEs related to machine learning frameworks (TensorFlow, PyTorch)
2. Find ATLAS techniques that could exploit ML framework vulnerabilities
3. Search for case studies involving ML framework attacks
"""

response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{"role": "user", "content": query}]
)

# Claude automatically:
# 1. Calls search_cve("tensorflow OR pytorch", cvss_min=7.0)
# 2. Calls find_similar_atlas_techniques("exploit ML framework vulnerability")
# 3. Calls search_atlas_case_studies("framework vulnerability")
# Returns unified AI security threat intelligence
```

### LLM Security Assessment

```python
# Assess threats to LLM deployment
llm_scenario = """
We're deploying a customer service chatbot powered by a large language model.
Concerned about prompt injection, data extraction, and adversarial inputs.
"""

# Find relevant ATLAS techniques
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"What ATLAS techniques apply to this LLM deployment: {llm_scenario}"
    }]
)
# Returns techniques related to prompt injection, model extraction, evasion attacks
# Claude can then provide mitigation recommendations based on ATLAS guidance
```

### Case Study Research for Executive Briefing

```python
# Find real-world incidents similar to your AI deployment
activity = """
Autonomous vehicle perception system using computer vision for object detection.
Need to understand real-world attack precedents for risk briefing.
"""

# Find matching case studies
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"Find ATLAS case studies relevant to: {activity}"
    }]
)
# Returns Tesla Autopilot attacks, adversarial road sign incidents, etc.
# Provides documented precedents for risk communication
```

---

## Data Sync

### Manual Sync Commands

**Sync ATLAS data WITHOUT embeddings (faster):**

```bash
# Download + parse only (2-3 minutes)
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_atlas.sync_atlas_data

# Verify sync
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM atlas_techniques')
        print(f'Techniques: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM atlas_case_studies')
        print(f'Case Studies: {result.scalar()}')
asyncio.run(check())
"
```

**Sync ATLAS data WITH embeddings (semantic search):**

```bash
# Download + parse + generate embeddings (8-12 minutes)
# Requires OPENAI_API_KEY in environment
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_atlas.sync_atlas_data --kwargs='{"generate_embeddings": true}'

# Verify embeddings
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute(
            'SELECT COUNT(*) FROM atlas_techniques WHERE embedding IS NOT NULL'
        )
        print(f'Techniques with embeddings: {result.scalar()}')
        result = await session.execute(
            'SELECT COUNT(*) FROM atlas_case_studies WHERE embedding IS NOT NULL'
        )
        print(f'Case studies with embeddings: {result.scalar()}')
asyncio.run(check())
"
```

### Expected Durations

| Operation | Duration | Notes |
|-----------|----------|-------|
| Download STIX data | 30 sec | ~2MB JSON file |
| Parse + insert techniques | 1-2 min | ~200 techniques |
| Parse + insert tactics | 30 sec | ~14 tactics |
| Parse + insert case studies | 30 sec | ~30 case studies |
| Generate technique embeddings | 5-8 min | OpenAI API, ~200 requests |
| Generate case study embeddings | 2-3 min | OpenAI API, ~30 requests |
| **Total (with embeddings)** | **8-12 min** | One-time cost |
| **Total (without embeddings)** | **2-3 min** | Traditional search only |

### Recommendations

- **Development:** Sync without embeddings for faster iteration
- **Production:** Sync with embeddings for full semantic search capabilities
- **Scheduled:** Run monthly to get latest ATLAS updates
- **Embeddings:** Re-generate only when MITRE updates technique descriptions

---

## Performance Metrics

### Query Latency (p95)

| Operation | Target | Typical | Notes |
|-----------|--------|---------|-------|
| `search_atlas_techniques` | <50ms | 35-45ms | PostgreSQL ILIKE search |
| `find_similar_atlas_techniques` | <100ms | 75-95ms | pgvector cosine similarity |
| `get_atlas_technique_details` | <30ms | 20-28ms | Indexed lookup |
| `search_atlas_case_studies` | <50ms | 38-48ms | PostgreSQL ILIKE search |
| `find_similar_atlas_case_studies` | <100ms | 75-92ms | pgvector cosine similarity |

### Database Size

| Component | Size | Details |
|-----------|------|---------|
| ATLAS techniques | ~3 MB | ~200 records with descriptions |
| ATLAS tactics | ~0.5 MB | ~14 records |
| ATLAS case studies | ~1.5 MB | ~30 records with summaries |
| Technique embeddings | ~1.5 MB | 1536-dim vectors (text-embedding-3-small) |
| Case study embeddings | ~0.3 MB | 1536-dim vectors |
| Indexes (IVFFlat) | ~1 MB | Vector similarity indexes |
| **Total ATLAS module** | **~8 MB** | Minimal overhead |

### Embedding Generation Cost

Using OpenAI `text-embedding-3-small` model:

| Item | Count | Cost per 1M tokens | Total Cost |
|------|-------|-------------------|------------|
| Technique embeddings | ~200 | $0.02 | ~$0.04 |
| Case study embeddings | ~30 | $0.02 | ~$0.01 |
| **Total (one-time)** | **~230** | - | **~$0.05** |

**Monthly refresh cost:** ~$0.05 (assuming 10% content changes)

---

## Integration with Ansvar AI Platform

The ATLAS module eliminates RAG staleness by providing fresh, local AI/ML security data to AI assistants.

### Before: RAG Without MCP

```
┌─────────────────┐
│   Claude API    │  Knowledge cutoff: May 2025
│  (RAG context)  │  ATLAS data: 180-365 days stale
└─────────────────┘
```

**Problems:**
- ATLAS knowledge outdated by 180-365 days
- No access to latest AI/ML attack techniques
- Cannot query by semantic similarity
- Requires prompt engineering for technique mapping

### After: RAG + MCP Hybrid

```
┌─────────────────┐
│   Claude API    │  General knowledge (cutoff: May 2025)
│  (RAG context)  │  +
└────────┬────────┘  MCP tools for fresh ATLAS data
         │
         ▼
┌─────────────────┐
│  ATLAS MCP      │  Data freshness: <7 days
│  (Local DB)     │  Semantic search: ✅
│                 │  Full technique database: ✅
└─────────────────┘
```

**Benefits:**
- ATLAS data freshness: <7 days (monthly sync)
- Semantic search for scenario → technique mapping
- Cross-domain queries (CVE + ATT&CK + ATLAS)
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

### Key Columns

**atlas_techniques table:**

```sql
CREATE TABLE atlas_techniques (
    technique_id VARCHAR(20) PRIMARY KEY,      -- e.g., AML.T0001
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    tactics TEXT[],                            -- Array of tactic names
    ml_lifecycle_stage VARCHAR(100),           -- training, deployment, etc.
    ai_system_type TEXT[],                     -- computer-vision, nlp, etc.
    detection TEXT,
    mitigation TEXT,
    version VARCHAR(20),
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    deprecated BOOLEAN DEFAULT FALSE,
    revoked BOOLEAN DEFAULT FALSE,
    embedding vector(1536),                    -- pgvector column
    embedding_model VARCHAR(50),               -- text-embedding-3-small
    embedding_generated_at TIMESTAMP,
    stix_extensions JSONB,                     -- Full STIX object
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**atlas_case_studies table:**

```sql
CREATE TABLE atlas_case_studies (
    case_study_id VARCHAR(50) PRIMARY KEY,     -- e.g., AML.CS0001
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    summary TEXT NOT NULL,
    incident_date TIMESTAMP,
    techniques_used TEXT[],                    -- Array of technique IDs
    target_system VARCHAR(200),
    impact TEXT,
    references TEXT[],
    version VARCHAR(20),
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    embedding vector(1536),                    -- pgvector column
    embedding_model VARCHAR(50),
    embedding_generated_at TIMESTAMP,
    stix_extensions JSONB,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**atlas_tactics table:**

```sql
CREATE TABLE atlas_tactics (
    tactic_id VARCHAR(50) PRIMARY KEY,         -- e.g., AML.TA0001
    stix_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    shortname VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

### Indexes

**Vector similarity indexes (IVFFlat):**

```sql
-- Technique semantic search (lists=50 for ~200 techniques)
CREATE INDEX idx_atlas_tech_embedding
    ON atlas_techniques
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 50);

-- Case study semantic search (lists=20 for ~30 case studies)
CREATE INDEX idx_atlas_case_embedding
    ON atlas_case_studies
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 20);
```

**Filter indexes:**

```sql
-- Tactic array index
CREATE INDEX idx_atlas_tech_tactics
    ON atlas_techniques
    USING gin(tactics);

-- ML lifecycle stage index
CREATE INDEX idx_atlas_tech_lifecycle
    ON atlas_techniques(ml_lifecycle_stage);

-- AI system type array index
CREATE INDEX idx_atlas_tech_ai_type
    ON atlas_techniques
    USING gin(ai_system_type);

-- Name trigram index for fuzzy search
CREATE INDEX idx_atlas_tech_name_trgm
    ON atlas_techniques
    USING gin(name gin_trgm_ops);

-- Case study techniques array index
CREATE INDEX idx_atlas_case_techniques
    ON atlas_case_studies
    USING gin(techniques_used);

-- Case study incident date index
CREATE INDEX idx_atlas_case_date
    ON atlas_case_studies(incident_date);
```

---

## Troubleshooting

### Semantic Search Not Working

**Error:** `find_similar_atlas_techniques returns empty results`

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
            'SELECT COUNT(*) FROM atlas_techniques WHERE embedding IS NOT NULL'
        )
        count = result.scalar()
        print(f'Techniques with embeddings: {count}')
        if count == 0:
            print('ERROR: No embeddings found. Re-sync with generate_embeddings=true')
asyncio.run(check())
"

# Re-sync with embeddings
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_atlas.sync_atlas_data --kwargs='{"generate_embeddings": true}'
```

### Traditional Search Returns Too Many Results

**Issue:** `search_atlas_techniques` returns many irrelevant results

**Solution:** Use more specific filters

```json
{
  "query": "evasion",
  "tactics": ["ml-attack-staging"],
  "ml_lifecycle_stage": "deployment",
  "ai_system_type": ["computer-vision"],
  "limit": 10
}
```

### Semantic Search Returns Low Similarity Scores

**Issue:** All results have similarity <0.6

**Explanation:** This is expected behavior. ATLAS techniques are very specific to AI/ML attacks. Low similarity doesn't mean bad results—it means your description doesn't closely match any single technique.

**Solutions:**
- Lower `min_similarity` to 0.5-0.6 for broader results
- Use more specific AI/ML technical details
- Try traditional search if you know technique keywords

**Example:**

Vague: "Attack on AI system"
 Low similarity scores (0.4-0.5)

Specific: "Attacker injected adversarial examples into image classifier training data to create backdoor triggered by specific pixel patterns"
 High similarity scores (0.75-0.90) for AML.T0020 (Poison Training Data)

### Case Studies Not Found

**Issue:** `search_atlas_case_studies` returns no results

**Causes:**
1. Case studies not synced
2. Query too specific

**Solutions:**

```bash
# Check case study count
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM atlas_case_studies')
        print(f'Case studies: {result.scalar()}')
asyncio.run(check())
"

# If zero, re-run sync
docker-compose exec celery-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_atlas.sync_atlas_data
```

### Performance Tuning

**Slow semantic search (>200ms):**

Check vector index:

```sql
-- Verify index exists
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'atlas_techniques'
  AND indexname LIKE '%embedding%';

-- Rebuild if needed
DROP INDEX idx_atlas_tech_embedding;
CREATE INDEX idx_atlas_tech_embedding
    ON atlas_techniques
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 50);
```

**Slow traditional search (>100ms):**

```sql
-- Check query plan
EXPLAIN ANALYZE
SELECT * FROM atlas_techniques
WHERE name ILIKE '%poisoning%' OR description ILIKE '%poisoning%';
-- Should use index scan if trigram index is configured
```

---

## ATLAS Tactics (ML Kill Chain)

The ATLAS framework defines 14 tactics that represent the adversarial ML attack kill chain:

| Tactic ID | Name | Description |
|-----------|------|-------------|
| AML.TA0001 | Reconnaissance | Gathering information about target AI/ML system |
| AML.TA0002 | Resource Development | Acquiring resources for attack (compute, data, models) |
| AML.TA0003 | Initial Access | Gaining initial access to target ML system |
| AML.TA0004 | ML Model Access | Obtaining access to the target ML model |
| AML.TA0005 | Execution | Running adversarial techniques against ML system |
| AML.TA0006 | Persistence | Maintaining access to ML system |
| AML.TA0007 | Defense Evasion | Avoiding detection of adversarial activity |
| AML.TA0008 | Discovery | Exploring the ML system and environment |
| AML.TA0009 | Collection | Gathering data from ML system |
| AML.TA0010 | ML Attack Staging | Preparing adversarial attacks |
| AML.TA0011 | Exfiltration | Stealing ML models or training data |
| AML.TA0012 | Impact | Disrupting or degrading ML system performance |

---

## Best Practices

1. **Use semantic search for AI security assessments** — Natural language descriptions work better than keyword matching for complex scenarios
2. **Use traditional search for browsing** — Faster when you know what you're looking for
3. **Combine tools** — Use `find_similar_atlas_techniques` then `get_atlas_technique_details` for deep analysis
4. **Cross-reference with ATT&CK** — Map AI/ML attacks to traditional cyber techniques for complete coverage
5. **Reference case studies** — Use real-world incidents to inform risk assessments and executive briefings
6. **Monthly sync** — Keep ATLAS data fresh with monthly updates
7. **Lower similarity threshold** — Start with 0.6-0.7, not 0.8+
8. **Describe technically** — More AI/ML technical details = better semantic matches
9. **Filter by ML lifecycle** — Use lifecycle stage filters to narrow results to relevant attack phases
10. **Combine with CVE intelligence** — Look for CVEs in ML frameworks (TensorFlow, PyTorch) alongside ATLAS techniques

---

## Related Resources

- **[MITRE ATLAS Website](https://atlas.mitre.org/)** — Official ATLAS documentation
- **[ATLAS GitHub Repository](https://github.com/mitre-atlas/atlas-data)** — STIX data source
- **[ATT&CK Module Documentation](./attack.md)** — Complementary traditional cyber attack techniques
- **[SETUP.md](../SETUP.md)** — Deployment and configuration guide

---

**Documentation version:** 1.0.0 (2026-01-31)

**Module status:** Production Ready

**For setup instructions:** See [SETUP.md](../SETUP.md)

**For architecture details:** See [Architecture ADRs](../architecture/)
