# D3FEND Module Design

**Date:** 2026-01-31
**Status:** Approved
**Author:** Claude (with Jeffrey's input)

## Overview

Add MITRE D3FEND (Detection, Denial, and Disruption Framework Empowering Network Defense) defensive countermeasures framework with semantic search to the Threat Intelligence MCP Server. This provides ~200 defensive techniques mapped to ATT&CK offensive techniques, completing the attack→defense correlation chain.

## Goals

- ~200 defensive techniques with semantic search
- 7 defensive tactics (Model, Harden, Detect, Isolate, Deceive, Evict, Restore)
- Bidirectional ATT&CK linkage (D3FEND counters ATT&CK techniques)
- Digital artifact relationships (what techniques produce/use)
- Attack coverage gap analysis
- Academic references for compliance evidence

## Data Source

- **Primary:** MISP Galaxy format `https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-d3fend.json`
- **Supplemental:** Official API `https://d3fend.mitre.org/ontologies/d3fend.json`
- **Format:** JSON (MISP) / JSON-LD (Official)
- **Size:** ~2MB
- **Update frequency:** Quarterly

## Database Schema

### 1. d3fend_tactics (~7 records)

```python
tactic_id: String(20) PK           # "D3-MODEL"
name: String(200)                   # "Model"
description: Text
display_order: Integer              # For matrix rendering

created: DateTime
modified: DateTime
data_last_updated: DateTime
```

### 2. d3fend_techniques (~200 records)

```python
# Primary identification
technique_id: String(20) PK         # "D3-AL"

# Semantic search
embedding: Vector(1536)
embedding_model: String(50)
embedding_generated_at: DateTime

# Core fields
name: String(300)                   # "Application Hardening"
description: Text                   # Full definition
tactic_id: String(20) FK → d3fend_tactics

# Hierarchy
parent_id: String(20) FK nullable → self

# Added from ontology
synonyms: ARRAY(Text)               # Alternative names
references: JSONB                   # [{title, url, authors}]
kb_article_url: String(500)

# Timestamps
created: DateTime
modified: DateTime
data_last_updated: DateTime

# Metadata
d3fend_version: String(20)
deprecated: Boolean
```

### 3. d3fend_artifacts (~100 records)

```python
artifact_id: String(50) PK          # "d3f:File"
name: String(200)
description: Text
artifact_type: String(50)           # DigitalArtifact, NetworkTraffic, etc.
```

### 4. d3fend_technique_attack_mappings (ATT&CK correlation)

```python
mapping_id: Integer PK autoincrement
d3fend_technique_id: String(20) FK → d3fend_techniques
attack_technique_id: String(20) FK → attack_techniques  # Proper FK!
relationship_type: Enum('counters', 'enables', 'related-to', 'produces', 'uses')

# Composite unique (d3fend_technique_id, attack_technique_id, relationship_type)
```

### 5. d3fend_technique_artifacts (join table)

```python
technique_id: String(20) FK → d3fend_techniques
artifact_id: String(50) FK → d3fend_artifacts
relationship_type: Enum('produces', 'uses', 'analyzes')

# Composite PK (technique_id, artifact_id, relationship_type)
```

### Indexes

```python
# HNSW for small dataset (no training, better for ~200 records)
Index("idx_d3fend_embedding", embedding, postgresql_using="hnsw",
      postgresql_with={"m": 16, "ef_construction": 64},
      postgresql_ops={"embedding": "vector_cosine_ops"})

# Fast lookups
Index("idx_d3fend_tactic", tactic_id)
Index("idx_d3fend_parent", parent_id)
Index("idx_d3fend_name_trgm", name, postgresql_using="gin",
      postgresql_ops={"name": "gin_trgm_ops"})

# Mapping table indexes
Index("idx_d3fend_attack_mapping", attack_technique_id)  # For reverse lookups
```

## MCP Tools (5 tools)

### 1. search_defenses
Traditional keyword search for defensive techniques.

```json
{
  "query": "application hardening",
  "tactic": ["Harden", "Detect"],
  "include_children": true,
  "limit": 50
}
```

### 2. find_similar_defenses
Semantic search on technique descriptions.

```json
{
  "description": "Prevent malicious code execution in applications",
  "min_similarity": 0.7,
  "tactic": ["Harden"],
  "limit": 10
}
```

### 3. get_defense_details
Full technique info with artifacts and ATT&CK mappings.

```json
{
  "technique_id": "D3-AL"
}
```

### 4. get_defenses_for_attack
Find defensive countermeasures for a specific ATT&CK technique.

```json
{
  "attack_technique_id": "T1059",
  "include_subtechniques": true,
  "relationship_type": ["counters"]
}
```

### 5. get_attack_coverage
Analyze which ATT&CK techniques are covered by specified defenses.

```json
{
  "technique_ids": ["D3-AL", "D3-NTA", "D3-PSA"],
  "show_gaps": true
}
```

## Parser Architecture

```
src/cve_mcp/ingest/d3fend_parser.py
├── parse_technique(entry: dict) → dict
├── parse_tactic_from_kill_chain(kill_chain: list) → str
├── extract_attack_mappings(related: list) → list[dict]
├── parse_artifact(entry: dict) → dict
└── _normalize_d3fend_id(external_id: str) → str
```

**Parser Library:** Standard `json` module (MISP format is clean JSON)

## Sync Flow

```
scripts/sync_d3fend_data.py
    ↓
src/cve_mcp/tasks/sync_d3fend.py
    ├── 1. Download MISP Galaxy JSON
    ├── 2. Extract tactics from kill_chain values → d3fend_tactics
    ├── 3. Parse techniques → d3fend_techniques
    ├── 4. Fetch artifacts from official API → d3fend_artifacts
    ├── 5. Build technique-artifact mappings → d3fend_technique_artifacts
    ├── 6. Extract ATT&CK relations → d3fend_technique_attack_mappings
    │       └── Validate FK against attack_techniques table
    ├── 7. Generate embeddings (~200 techniques, ~$0.02)
    └── 8. Update ATT&CK techniques with d3fend_countermeasures (bidirectional)
```

## Testing Strategy

- `tests/ingest/test_d3fend_parser.py` - 12 parser tests
- `tests/tasks/test_sync_d3fend.py` - 8 sync tests
- `tests/services/test_d3fend_queries.py` - 10 query tests
- `tests/api/test_d3fend_tools.py` - 10 tool tests

**Total: ~40 tests**

## Metrics

| Component | Count/Size |
|-----------|------------|
| Database Tables | 5 |
| Techniques | ~200 |
| Tactics | 7 |
| Artifacts | ~100 |
| MCP Tools | 5 (total: 36) |
| Tests | ~40 |
| Embedding Cost | ~$0.02/sync |
| Index Type | HNSW (m=16) |

## Cross-Framework Integration

After D3FEND implementation, full correlation path:

```
CVE → CWE → CAPEC → ATT&CK ↔ D3FEND
                      ↑         ↑
                   (attack)  (defense)
```

Example query: "For CVE-2024-1234, what ATT&CK techniques exploit it, and what D3FEND countermeasures can I deploy?"
