# CWE Module Design

**Date:** 2026-01-31
**Status:** Approved
**Author:** Claude (with Jeffrey's input)

## Overview

Add MITRE CWE (Common Weakness Enumeration) framework with semantic search to the Threat Intelligence MCP Server. This provides comprehensive software weakness data with hierarchical search, external mappings (OWASP, SANS), and cross-framework correlation to CAPEC attack patterns.

## Goals

- ~900 software weaknesses with semantic search
- Hierarchical search (searching "SQL Injection" returns class + all variants)
- All CWE views (CWE-1003, CWE-699, CWE-1000, CWE-1194)
- External mappings (OWASP Top 10, SANS Top 25)
- Bidirectional CAPEC linkage
- Actionable intelligence (mitigations, detection methods, consequences)

## Data Source

- **URL:** `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`
- **Format:** XML (custom schema, not STIX 2.1)
- **Size:** ~15MB uncompressed
- **Update frequency:** Quarterly

## Database Schema

### 1. cwe_weaknesses (~900 records)

```python
# Primary identification
cwe_id: String(20) PK              # "CWE-79"
weakness_id: Integer unique         # 79

# Semantic search
embedding: Vector(1536)
embedding_model: String(50)
embedding_generated_at: DateTime

# Core fields
name: String(500)
description: Text
extended_description: Text
abstraction: String(20)            # Pillar, Class, Base, Variant, Compound
status: String(20)                 # Draft, Incomplete, Stable, Deprecated

# Actionable intelligence
common_consequences: JSONB         # [{scope, impact, likelihood, note}]
potential_mitigations: JSONB       # [{phase, strategy, effectiveness, description}]
detection_methods: JSONB           # [{method, effectiveness, description}]
likelihood_of_exploit: String(20)  # High, Medium, Low

# Relationships
parent_of: ARRAY(Text)             # ["CWE-20", "CWE-74"]
child_of: ARRAY(Text)
peer_of: ARRAY(Text)
related_attack_patterns: ARRAY(Text)  # CAPEC IDs for bidirectional link

# Timestamps
created: DateTime
modified: DateTime
data_last_updated: DateTime        # Sync freshness

# Metadata
cwe_version: String(20)            # "4.14" dataset version
deprecated: Boolean
```

### 2. cwe_categories (~300 records)

```python
category_id: String(20) PK         # "CWE-310" (native CWE ID)
name: String(300)
description: Text
view_id: String(20) FK             # Which view owns this category
```

### 3. cwe_views (~10 records)

```python
view_id: String(20) PK             # "CWE-1003"
name: String(300)                  # "Weaknesses for Simplified Mapping"
type: String(50)                   # Graph, Explicit, Implicit
status: String(20)
description: Text
```

### 4. cwe_weakness_categories (join table)

```python
weakness_id: String(20) FK → cwe_weaknesses(cwe_id)
category_id: String(20) FK → cwe_categories(category_id)
view_id: String(20) FK → cwe_views(view_id)

# Composite PK (weakness_id, category_id, view_id)
```

### 5. cwe_external_mappings

```python
mapping_id: Integer PK autoincrement
weakness_id: String(20) FK → cwe_weaknesses(cwe_id)
external_source: String(50)        # "OWASP Top 10 2021", "SANS Top 25"
external_id: String(100)           # "A03:2021"
mapping_type: String(50)           # "Primary", "Secondary"
rationale: Text
```

### Indexes

```python
# Vector similarity
Index("idx_cwe_embedding", embedding, postgresql_using="ivfflat",
      postgresql_with={"lists": 100}, postgresql_ops={"embedding": "vector_cosine_ops"})

# Array relationships
Index("idx_cwe_parent_of", parent_of, postgresql_using="gin")
Index("idx_cwe_child_of", child_of, postgresql_using="gin")
Index("idx_cwe_related_capec", related_attack_patterns, postgresql_using="gin")

# Fuzzy text search
Index("idx_cwe_name_trgm", name, postgresql_using="gin",
      postgresql_ops={"name": "gin_trgm_ops"})

# Fast lookups
Index("idx_cwe_weakness_id", weakness_id)  # B-tree
Index("idx_cwe_external_mapping", external_source, external_id)  # Composite B-tree
```

## MCP Tools (6 tools)

### 1. search_weaknesses
Traditional keyword search with hierarchical support.

```json
{
  "query": "SQL injection",
  "abstraction": ["Class", "Base"],
  "include_children": true,
  "view": "CWE-699",
  "limit": 50
}
```

### 2. find_similar_weaknesses
Semantic search on descriptions.

```json
{
  "description": "User uploads file that gets executed on server",
  "min_similarity": 0.7,
  "abstraction": ["Base", "Variant"],
  "limit": 10
}
```

### 3. get_weakness_details
Full weakness info with actionable intelligence.

```json
{
  "weakness_id": "CWE-79"
}
```

### 4. search_by_external_mapping
Query by OWASP/SANS standards.

```json
{
  "source": "OWASP Top 10 2021",
  "external_id": "A03:2021"
}
```

### 5. get_weakness_hierarchy
Navigate parent/child tree.

```json
{
  "weakness_id": "CWE-89",
  "direction": "both",
  "depth": 3
}
```

### 6. find_weaknesses_for_capec
Cross-framework correlation.

```json
{
  "pattern_id": "CAPEC-66"
}
```

## Parser Architecture

New XML parser (CWE uses custom XML, not STIX 2.1):

```
src/cve_mcp/ingest/cwe_parser.py
├── parse_weakness(xml_element) → dict
├── parse_category(xml_element) → dict
├── parse_view(xml_element) → dict
├── parse_external_mapping(xml_element) → dict
└── _extract_structured_field(element, field_name) → dict/list
```

**Parser Library:** `lxml` for fast XML parsing

## Sync Flow

```
scripts/sync_cwe_data.py
    ↓
src/cve_mcp/tasks/sync_cwe.py
    ├── 1. Download & unzip XML
    ├── 2. Parse views → cwe_views table
    ├── 3. Parse categories → cwe_categories table
    ├── 4. Parse weaknesses → cwe_weaknesses table
    ├── 5. Build category memberships → cwe_weakness_categories
    ├── 6. Extract external mappings → cwe_external_mappings
    ├── 7. Generate embeddings (~900 weaknesses, ~$0.10)
    └── 8. Update CAPEC related_weaknesses (bidirectional link)
```

## Testing Strategy

- `tests/ingest/test_cwe_parser.py` - 15 parser tests
- `tests/tasks/test_sync_cwe.py` - 10 sync tests
- `tests/services/test_cwe_queries.py` - 12 query tests
- `tests/test_cwe_integration.py` - 8 integration tests

**Total: ~45 tests**

## Metrics

| Component | Count/Size |
|-----------|------------|
| Database Tables | 5 |
| Weaknesses | ~900 |
| Categories | ~300 |
| Views | ~10 |
| MCP Tools | 6 (total: 31) |
| Tests | ~45 |
| Embedding Cost | ~$0.10/sync |
| Estimated Time | ~14 hours |

## Cross-Framework Integration

After CWE implementation, full correlation path:

```
CVE → CWE → CAPEC → ATT&CK/ATLAS
```

Example query: "Find CVEs with CVSS > 9.0 that exploit authentication weaknesses mapped to credential access techniques"
