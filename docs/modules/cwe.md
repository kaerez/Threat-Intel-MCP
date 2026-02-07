# MITRE CWE Module

**Offline-first weakness enumeration with AI-powered semantic search for secure software development.**

## Overview

The CWE module provides comprehensive access to the MITRE CWE (Common Weakness Enumeration) framework with both traditional keyword search and AI-powered semantic similarity search. All queries run against a local PostgreSQL database with pgvector for semantic search capabilities.

### Key Features

- **960+ Software Weaknesses** — Comprehensive catalog of software and hardware weakness types
- **5 Abstraction Levels** — Hierarchical organization (Pillar → Class → Base → Variant → Compound)
- **External Mappings** — OWASP Top 10, SANS Top 25, and other industry standards
- **Actionable Intelligence** — Common consequences, mitigations, and detection methods
- **CAPEC Cross-Reference** — Attack patterns that exploit each weakness
- **Dual Search Modes** — Traditional keyword search (<50ms) + AI semantic search (<100ms)
- **Hierarchical Navigation** — Parent/child relationship traversal
- **RAG Integration** — Fresh data (<7 days) for AI assistant workflows
- **Offline-First** — All queries run locally, no external API calls during runtime

### Data Coverage

| Category | Count | Description |
|----------|-------|-------------|
| Weaknesses | 900+ | Software and hardware weakness types |
| Views | ~10 | Organizational perspectives (Research, Development, etc.) |
| Categories | ~300 | Logical groupings of weaknesses |
| External Mappings | 1,000+ | OWASP, SANS, CERT references |
| CAPEC Links | 500+ | Related attack patterns |
| Abstraction Levels | 5 | Pillar, Class, Base, Variant, Compound |

### CWE vs CAPEC vs ATT&CK

| Aspect | CWE | CAPEC | ATT&CK |
|--------|-----|-------|--------|
| **Focus** | Software weaknesses | Attack patterns | Threat techniques |
| **Abstraction** | Code/design flaws | How attacks work | What adversaries do |
| **Scope** | Secure development | Attack methodology | Threat intelligence |
| **ID Format** | CWE-79 | CAPEC-66 | T1566 |
| **Use Case** | Code review, SAST | Security design | Detection/response |
| **Audience** | Developers, architects | Security architects | SOC/IR teams |

### CWE Abstraction Hierarchy

CWE organizes weaknesses into five abstraction levels forming a hierarchy:

| Level | Description | Example |
|-------|-------------|---------|
| **Pillar** | Highest-level weakness categories | CWE-664: Improper Control of a Resource Through its Lifetime |
| **Class** | Abstract weakness patterns | CWE-20: Improper Input Validation |
| **Base** | Specific weakness types | CWE-79: Cross-site Scripting (XSS) |
| **Variant** | Detailed variations of base weaknesses | CWE-80: Basic XSS |
| **Compound** | Composite weaknesses combining multiple issues | CWE-352: Cross-Site Request Forgery |

---

## MCP Tools

The CWE module provides 6 MCP tools divided into traditional search, semantic search, and navigation categories.

### Traditional Search Tools

#### 1. search_cwe_weaknesses

**Description:** Search MITRE CWE weaknesses using traditional keyword and filter-based search. Filter by abstraction level (Pillar, Class, Base, Variant, Compound) and optionally include child weaknesses in results.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_cwe_weaknesses",
  "arguments": {
    "query": "SQL injection",
    "abstraction": ["Base", "Variant"],
    "include_children": false,
    "active_only": true,
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "weaknesses": [
      {
        "cwe_id": "CWE-89",
        "weakness_id": 89,
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs all or part of an SQL command using externally-influenced input...",
        "abstraction": "Base",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/89.html"
      },
      {
        "cwe_id": "CWE-564",
        "weakness_id": 564,
        "name": "SQL Injection: Hibernate",
        "description": "Using Hibernate to execute a dynamic SQL statement built with user-controlled input...",
        "abstraction": "Variant",
        "status": "Incomplete",
        "likelihood_of_exploit": "Medium",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/564.html"
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
| `query` | string | No | Full-text search in name/description |
| `abstraction` | array | No | Filter by levels: Pillar, Class, Base, Variant, Compound |
| `include_children` | boolean | No | Include child weaknesses of matches (default: false) |
| `active_only` | boolean | No | Exclude deprecated weaknesses (default: true) |
| `limit` | integer | No | Max results (default: 50, max: 500) |

**Use Cases:**
- Find weaknesses by name or description keywords
- Filter by abstraction level for appropriate detail
- Hierarchical search including child weaknesses
- Browse the CWE framework by category

---

#### 2. get_cwe_weakness_details

**Description:** Get complete details for a specific CWE weakness including common consequences, potential mitigations, detection methods, external mappings (OWASP, SANS), and relationships to other weaknesses.

**Performance:** <30ms average latency

**Example Request:**

```json
{
  "name": "get_cwe_weakness_details",
  "arguments": {
    "weakness_id": "CWE-79"
  }
}
```

**Example Response:**

```json
{
  "data": {
    "cwe_id": "CWE-79",
    "weakness_id": 79,
    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
    "extended_description": "Cross-site scripting (XSS) vulnerabilities occur when user input is echoed back to a web browser...",
    "abstraction": "Base",
    "status": "Stable",
    "common_consequences": [
      {
        "scope": ["Confidentiality", "Integrity", "Availability"],
        "impact": "Execute Unauthorized Code or Commands",
        "likelihood": "High",
        "note": "Attackers can execute arbitrary JavaScript in victim's browser"
      },
      {
        "scope": "Confidentiality",
        "impact": "Read Application Data",
        "note": "Session cookies can be stolen"
      }
    ],
    "potential_mitigations": [
      {
        "phase": "Architecture and Design",
        "strategy": "Libraries or Frameworks",
        "description": "Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.",
        "effectiveness": "High"
      },
      {
        "phase": "Implementation",
        "strategy": "Output Encoding",
        "description": "Encode all output that includes untrusted data so it cannot be interpreted as active content.",
        "effectiveness": "High"
      },
      {
        "phase": "Implementation",
        "strategy": "Input Validation",
        "description": "Assume all input is malicious. Use an 'accept known good' input validation strategy.",
        "effectiveness": "Moderate"
      }
    ],
    "detection_methods": [
      {
        "method": "Automated Static Analysis",
        "effectiveness": "Moderate",
        "description": "Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code..."
      },
      {
        "method": "Dynamic Analysis with Automated Results Interpretation",
        "effectiveness": "Moderate",
        "description": "Web application scanners can dynamically identify XSS vulnerabilities..."
      }
    ],
    "likelihood_of_exploit": "High",
    "parent_of": ["CWE-80", "CWE-81", "CWE-82", "CWE-83", "CWE-84", "CWE-85", "CWE-86", "CWE-87"],
    "child_of": ["CWE-74"],
    "peer_of": ["CWE-352"],
    "can_precede": ["CWE-494"],
    "can_follow": null,
    "related_attack_patterns": ["CAPEC-86", "CAPEC-198", "CAPEC-591", "CAPEC-592"],
    "external_mappings": [
      {
        "source": "OWASP Top Ten 2021",
        "external_id": "A03:2021",
        "mapping_type": "owasp",
        "rationale": "Injection"
      },
      {
        "source": "SANS Top 25",
        "external_id": "1",
        "mapping_type": "sans",
        "rationale": "Improper Neutralization of Input During Web Page Generation"
      }
    ],
    "created": "2006-07-19T00:00:00",
    "modified": "2024-11-19T00:00:00",
    "cwe_version": "4.14",
    "deprecated": false,
    "badge_url": "https://cwe.mitre.org/data/definitions/79.html",
    "embedding_generated": true
  },
  "metadata": {
    "query_time_ms": 28
  }
}
```

**Use Cases:**
- Deep-dive analysis of specific weaknesses
- Understanding attack consequences and impacts
- Mitigation planning with recommended controls
- Detection engineering with SAST/DAST guidance
- Compliance mapping to OWASP/SANS standards
- Documentation and reporting for security assessments

---

#### 3. search_by_external_mapping

**Description:** Search CWE weaknesses by external standard mappings like OWASP Top Ten or SANS Top 25. Useful for compliance and prioritization based on industry standards.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_by_external_mapping",
  "arguments": {
    "source": "OWASP Top Ten 2021",
    "external_id": "A03:2021",
    "limit": 20
  }
}
```

**Example Response:**

```json
{
  "data": {
    "weaknesses": [
      {
        "cwe_id": "CWE-79",
        "weakness_id": 79,
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The product does not neutralize or incorrectly neutralizes user-controllable input...",
        "abstraction": "Base",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/79.html",
        "external_mapping": {
          "source": "OWASP Top Ten 2021",
          "external_id": "A03:2021",
          "mapping_type": "owasp"
        }
      },
      {
        "cwe_id": "CWE-89",
        "weakness_id": 89,
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs all or part of an SQL command using externally-influenced input...",
        "abstraction": "Base",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/89.html",
        "external_mapping": {
          "source": "OWASP Top Ten 2021",
          "external_id": "A03:2021",
          "mapping_type": "owasp"
        }
      }
    ],
    "total_results": 15,
    "returned_results": 2
  },
  "metadata": {
    "query_time_ms": 42
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | string | Yes | External source name (e.g., "OWASP Top Ten 2021", "SANS Top 25") |
| `external_id` | string | No | External ID filter (e.g., "A03:2021") |
| `limit` | integer | No | Max results (default: 50, max: 500) |

**Use Cases:**
- Find all weaknesses in OWASP Top 10 category
- Compliance-driven prioritization
- Map security requirements to CWE weaknesses
- Build remediation checklists by industry standard

---

### Semantic Search Tools

#### 4. find_similar_cwe_weaknesses

**Description:** Find MITRE CWE weaknesses using AI-powered semantic similarity search. Describe a vulnerability or coding issue in natural language and get matching weaknesses with similarity scores.

**Performance:** <100ms average latency

**Requirements:** OpenAI API key configured (OPENAI_API_KEY environment variable)

**Example Request:**

```json
{
  "name": "find_similar_cwe_weaknesses",
  "arguments": {
    "description": "User input is directly concatenated into SQL queries without any validation or parameterization, allowing attackers to modify query logic",
    "min_similarity": 0.7,
    "limit": 5
  }
}
```

**Example Response:**

```json
{
  "data": {
    "weaknesses": [
      {
        "cwe_id": "CWE-89",
        "weakness_id": 89,
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs all or part of an SQL command using externally-influenced input...",
        "abstraction": "Base",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "similarity_score": 0.94,
        "badge_url": "https://cwe.mitre.org/data/definitions/89.html"
      },
      {
        "cwe_id": "CWE-943",
        "weakness_id": 943,
        "name": "Improper Neutralization of Special Elements in Data Query Logic",
        "description": "The product generates a query intended to access or manipulate data in a data store...",
        "abstraction": "Class",
        "status": "Incomplete",
        "likelihood_of_exploit": "High",
        "similarity_score": 0.87,
        "badge_url": "https://cwe.mitre.org/data/definitions/943.html"
      },
      {
        "cwe_id": "CWE-20",
        "weakness_id": 20,
        "name": "Improper Input Validation",
        "description": "The product receives input or data, but it does not validate or incorrectly validates...",
        "abstraction": "Class",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "similarity_score": 0.78,
        "badge_url": "https://cwe.mitre.org/data/definitions/20.html"
      }
    ],
    "returned_results": 3,
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
| `description` | string | Yes | Natural language description of weakness (10-5000 chars) |
| `min_similarity` | float | No | Minimum similarity threshold (default: 0.7, range: 0-1) |
| `abstraction` | array | No | Filter by abstraction levels |
| `active_only` | boolean | No | Exclude deprecated weaknesses (default: true) |
| `limit` | integer | No | Max results (default: 10, max: 100) |

**Use Cases:**
- **Code Review:** Describe suspicious code patterns, get matching CWEs
- **SAST Triage:** Map scanner findings to appropriate CWE classifications
- **Security Assessments:** Identify weaknesses from vulnerability descriptions
- **Developer Training:** Learn CWE classifications from real examples

---

### Hierarchy Navigation Tools

#### 5. get_cwe_hierarchy

**Description:** Navigate the CWE parent/child hierarchy. Useful for understanding weakness relationships—e.g., finding all specific variants of a high-level weakness class, or understanding which broader category a specific weakness belongs to.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "get_cwe_hierarchy",
  "arguments": {
    "weakness_id": "CWE-79",
    "direction": "both",
    "depth": 2
  }
}
```

**Example Response:**

```json
{
  "data": {
    "cwe_id": "CWE-79",
    "weakness_id": 79,
    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "description": "The product does not neutralize or incorrectly neutralizes user-controllable input...",
    "abstraction": "Base",
    "status": "Stable",
    "badge_url": "https://cwe.mitre.org/data/definitions/79.html",
    "parents": [
      {
        "cwe_id": "CWE-74",
        "weakness_id": 74,
        "name": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
        "abstraction": "Class",
        "badge_url": "https://cwe.mitre.org/data/definitions/74.html",
        "parents": [
          {
            "cwe_id": "CWE-707",
            "weakness_id": 707,
            "name": "Improper Neutralization",
            "abstraction": "Pillar",
            "badge_url": "https://cwe.mitre.org/data/definitions/707.html"
          }
        ]
      }
    ],
    "children": [
      {
        "cwe_id": "CWE-80",
        "weakness_id": 80,
        "name": "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)",
        "abstraction": "Variant",
        "badge_url": "https://cwe.mitre.org/data/definitions/80.html"
      },
      {
        "cwe_id": "CWE-81",
        "weakness_id": 81,
        "name": "Improper Neutralization of Script in an Error Message Web Page",
        "abstraction": "Variant",
        "badge_url": "https://cwe.mitre.org/data/definitions/81.html"
      },
      {
        "cwe_id": "CWE-83",
        "weakness_id": 83,
        "name": "Improper Neutralization of Script in Attributes in a Web Page",
        "abstraction": "Variant",
        "badge_url": "https://cwe.mitre.org/data/definitions/83.html"
      }
    ],
    "peers": [
      {
        "cwe_id": "CWE-352",
        "weakness_id": 352,
        "name": "Cross-Site Request Forgery (CSRF)",
        "abstraction": "Compound",
        "badge_url": "https://cwe.mitre.org/data/definitions/352.html"
      }
    ]
  },
  "metadata": {
    "query_time_ms": 45
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `weakness_id` | string | Yes | CWE weakness ID (e.g., "CWE-79" or "79") |
| `direction` | string | No | Traversal direction: "parents", "children", or "both" (default: "both") |
| `depth` | integer | No | Maximum depth to traverse (default: 3, max: 10) |

**Use Cases:**
- **Understand Context:** See where a specific weakness fits in the CWE taxonomy
- **Find Variants:** Discover specific variations of a general weakness class
- **Impact Analysis:** Traverse up to understand broader vulnerability categories
- **Training:** Learn CWE hierarchy for security awareness programs

---

### Cross-Framework Tools

#### 6. find_weaknesses_for_capec

**Description:** Cross-framework search: find CWE weaknesses that are exploited by a specific CAPEC attack pattern. Links attack patterns to the underlying weaknesses they target.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "find_weaknesses_for_capec",
  "arguments": {
    "pattern_id": "CAPEC-66",
    "limit": 20
  }
}
```

**Example Response:**

```json
{
  "data": {
    "weaknesses": [
      {
        "cwe_id": "CWE-89",
        "weakness_id": 89,
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs all or part of an SQL command using externally-influenced input...",
        "abstraction": "Base",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/89.html",
        "related_via_capec": "CAPEC-66"
      },
      {
        "cwe_id": "CWE-20",
        "weakness_id": 20,
        "name": "Improper Input Validation",
        "description": "The product receives input or data, but it does not validate or incorrectly validates...",
        "abstraction": "Class",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/20.html",
        "related_via_capec": "CAPEC-66"
      },
      {
        "cwe_id": "CWE-943",
        "weakness_id": 943,
        "name": "Improper Neutralization of Special Elements in Data Query Logic",
        "description": "The product generates a query intended to access or manipulate data in a data store...",
        "abstraction": "Class",
        "status": "Incomplete",
        "likelihood_of_exploit": "High",
        "deprecated": false,
        "badge_url": "https://cwe.mitre.org/data/definitions/943.html",
        "related_via_capec": "CAPEC-66"
      }
    ],
    "total_results": 3,
    "returned_results": 3
  },
  "metadata": {
    "query_time_ms": 38
  }
}
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern_id` | string | Yes | CAPEC pattern ID (e.g., "CAPEC-66" or "66") |
| `limit` | integer | No | Max results (default: 50, max: 500) |

**Use Cases:**
- **Threat Modeling:** Understand which weaknesses enable specific attack patterns
- **Secure Design:** Identify weaknesses to prevent known attack techniques
- **Remediation Planning:** Prioritize fixes that block multiple attack patterns
- **Cross-Framework Analysis:** Build comprehensive CVE → CWE → CAPEC → ATT&CK chains

---

## Semantic Search vs Traditional Search

### Comparison Table

| Feature | Traditional Search | Semantic Search |
|---------|-------------------|-----------------|
| **Query Type** | Keywords, filters | Natural language descriptions |
| **Matching** | Exact keyword matches | Contextual similarity |
| **Latency** | <50ms | <100ms |
| **Use Case** | Known weakness lookup | Security assessment, code review |
| **Requirements** | None | OpenAI API key |
| **Best For** | Specific weakness research | Discovering relevant weaknesses from description |

### When to Use Each

**Use Traditional Search (`search_cwe_weaknesses`) when:**
- You know the weakness name or ID
- You want to filter by specific abstraction levels
- You need fastest possible results
- You're browsing the CWE framework

**Use Semantic Search (`find_similar_cwe_weaknesses`) when:**
- You have a vulnerability description from code review
- You want to classify a SAST finding
- You're mapping a penetration test finding to CWE
- You're doing security assessments

**Example Scenario:**

Traditional: "Find all XSS weaknesses at Base level"
```json
{"query": "XSS", "abstraction": ["Base"]}
```

Semantic: "The web application echoes user comments back to the page without encoding special characters, allowing JavaScript injection"
```json
{"description": "The web application echoes user comments back to the page without encoding special characters, allowing JavaScript injection"}
```
Returns CWE-79 (XSS), CWE-80 (Basic XSS) with high similarity

---

## Example Workflows

### Security Code Review with Semantic Search

```python
import anthropic

client = anthropic.Anthropic()

# Step 1: Describe the suspicious code pattern
code_issue = """
The application takes a user-supplied filename parameter and directly
uses it in a file path to read file contents. No validation is performed
to prevent directory traversal characters like ../ in the filename.
"""

# Step 2: Find matching weaknesses
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"Find CWE weaknesses for this code issue: {code_issue}"
    }]
)
# Claude uses find_similar_cwe_weaknesses tool automatically
# Returns: CWE-22 (Path Traversal), CWE-73 (External Control of File Name)

# Step 3: Get detailed mitigation guidance
for cwe_id in ["CWE-22", "CWE-73"]:
    details = client.messages.create(
        model="claude-sonnet-4.5",
        messages=[{
            "role": "user",
            "content": f"Get full details and mitigations for {cwe_id}"
        }]
    )
    # Returns mitigations, detection methods, OWASP mappings
```

### Cross-Framework Correlation: CVE → CWE → CAPEC → ATT&CK

```python
# Complete threat intelligence chain
query = """
1. Get details for CVE-2021-44228 (Log4Shell)
2. Find the CWE weaknesses associated with this CVE
3. Find CAPEC attack patterns that exploit these weaknesses
4. Map to ATT&CK techniques for detection
"""

response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{"role": "user", "content": query}]
)

# Claude automatically:
# 1. Calls get_cve_details("CVE-2021-44228") → CWE-917, CWE-20
# 2. Calls get_cwe_weakness_details("CWE-917") → Related CAPEC patterns
# 3. Calls find_weaknesses_for_capec to verify links
# 4. Uses CAPEC related_attack_patterns for ATT&CK mapping
# Returns unified threat intelligence chain
```

### OWASP Top 10 Compliance Assessment

```python
# Get all weaknesses for OWASP Top 10 2021
owasp_categories = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
]

for owasp_id, name in owasp_categories:
    response = client.messages.create(
        model="claude-sonnet-4.5",
        messages=[{
            "role": "user",
            "content": f"Find all CWE weaknesses mapped to OWASP {owasp_id} ({name})"
        }]
    )
    # Returns CWE weaknesses with external mappings
    # Build compliance checklist for each OWASP category
```

### SAST Finding Triage

```python
# Triage a SAST scanner finding
sast_finding = """
SAST Rule: Potential SQL Injection
Location: UserController.java:142
Code: String query = "SELECT * FROM users WHERE name = '" + userName + "'";
Severity: High
"""

# Classify and get remediation guidance
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": f"""
        Classify this SAST finding with CWE:
        {sast_finding}

        Then provide:
        1. The appropriate CWE classification
        2. Specific mitigation recommendations
        3. Detection methods to validate the fix
        """
    }]
)
# Returns CWE-89 classification with Java-specific mitigations
```

### Weakness Hierarchy Exploration

```python
# Understand the XSS weakness family
response = client.messages.create(
    model="claude-sonnet-4.5",
    messages=[{
        "role": "user",
        "content": """
        Show me the CWE hierarchy for XSS (CWE-79):
        1. What broader categories does it fall under?
        2. What specific variants exist?
        3. What related weaknesses should I also check for?
        """
    }]
)
# Returns full hierarchy: Pillar → Class → Base → Variants
# Plus peer weaknesses like CSRF
```

---

## Data Sync

### Manual Sync Commands

**Sync CWE data WITHOUT embeddings (faster):**

```bash
# Download + parse only (3-5 minutes)
docker-compose exec celery-worker python -c "
import asyncio
from cve_mcp.tasks.sync_cwe import sync_cwe_full
asyncio.run(sync_cwe_full(generate_embeddings=False))
"

# Verify sync
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM cwe_weaknesses')
        print(f'Weaknesses: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM cwe_views')
        print(f'Views: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM cwe_categories')
        print(f'Categories: {result.scalar()}')
        result = await session.execute('SELECT COUNT(*) FROM cwe_external_mappings')
        print(f'External mappings: {result.scalar()}')
asyncio.run(check())
"
```

**Sync CWE data WITH embeddings (semantic search):**

```bash
# Download + parse + generate embeddings (10-15 minutes)
# Requires OPENAI_API_KEY in environment
docker-compose exec celery-worker python -c "
import asyncio
from cve_mcp.tasks.sync_cwe import sync_cwe_full
asyncio.run(sync_cwe_full(generate_embeddings=True))
"

# Verify embeddings
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute(
            'SELECT COUNT(*) FROM cwe_weaknesses WHERE embedding IS NOT NULL'
        )
        print(f'Weaknesses with embeddings: {result.scalar()}')
asyncio.run(check())
"
```

### Expected Durations

| Operation | Duration | Notes |
|-----------|----------|-------|
| Download XML data | 30-60 sec | ~15MB ZIP file |
| Parse + insert views | 10 sec | ~10 views |
| Parse + insert categories | 30 sec | ~300 categories |
| Parse + insert weaknesses | 2-3 min | ~900 weaknesses |
| Parse + insert external mappings | 1-2 min | ~1000+ mappings |
| Build CAPEC-CWE links | 30 sec | Reverse mapping |
| Generate embeddings | 8-12 min | OpenAI API, ~900 requests |
| **Total (with embeddings)** | **10-15 min** | One-time cost |
| **Total (without embeddings)** | **3-5 min** | Traditional search only |

### Recommendations

- **Development:** Sync without embeddings for faster iteration
- **Production:** Sync with embeddings for full semantic search capabilities
- **Scheduled:** Run monthly to get latest CWE updates
- **Embeddings:** Re-generate only when MITRE updates weakness descriptions

---

## Performance Metrics

### Query Latency (p95)

| Operation | Target | Typical | Notes |
|-----------|--------|---------|-------|
| `search_cwe_weaknesses` | <50ms | 35-45ms | PostgreSQL ILIKE search |
| `find_similar_cwe_weaknesses` | <100ms | 75-95ms | pgvector cosine similarity |
| `get_cwe_weakness_details` | <30ms | 20-28ms | Indexed lookup |
| `search_by_external_mapping` | <50ms | 38-48ms | Composite index lookup |
| `get_cwe_hierarchy` | <50ms | 35-48ms | Recursive CTE queries |
| `find_weaknesses_for_capec` | <50ms | 30-42ms | GIN array index |

### Database Size

| Component | Size | Details |
|-----------|------|---------|
| CWE weaknesses | ~8 MB | ~900 records with descriptions |
| CWE views | ~0.1 MB | ~10 records |
| CWE categories | ~2 MB | ~300 records with descriptions |
| CWE external mappings | ~1 MB | ~1000+ mapping records |
| CWE weakness-category joins | ~0.5 MB | ~3000+ relationships |
| Weakness embeddings | ~7 MB | 1536-dim vectors (text-embedding-3-small) |
| Indexes (IVFFlat + GIN) | ~3 MB | Vector similarity + array indexes |
| **Total CWE module** | **~22 MB** | Minimal overhead |

### Embedding Generation Cost

Using OpenAI `text-embedding-3-small` model:

| Item | Count | Cost per 1M tokens | Total Cost |
|------|-------|-------------------|------------|
| Weakness embeddings | ~900 | $0.02 | ~$0.10 |
| **Total (one-time)** | **~900** | - | **~$0.10** |

**Monthly refresh cost:** ~$0.10 (assuming content changes require full re-sync)

---

## Database Schema

### Key Tables

**cwe_weaknesses table:**

```sql
CREATE TABLE cwe_weaknesses (
    cwe_id VARCHAR(20) PRIMARY KEY,              -- e.g., CWE-79
    weakness_id INTEGER UNIQUE NOT NULL,          -- e.g., 79
    name VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    extended_description TEXT,
    abstraction VARCHAR(20),                      -- Pillar, Class, Base, Variant, Compound
    status VARCHAR(20),                           -- Draft, Incomplete, Stable, Deprecated
    common_consequences JSONB,                    -- [{scope, impact, likelihood, note}]
    potential_mitigations JSONB,                  -- [{phase, strategy, effectiveness, description}]
    detection_methods JSONB,                      -- [{method, effectiveness, description}]
    likelihood_of_exploit VARCHAR(20),            -- High, Medium, Low
    parent_of TEXT[],                             -- Child weakness IDs
    child_of TEXT[],                              -- Parent weakness IDs
    peer_of TEXT[],                               -- Peer weakness IDs
    can_precede TEXT[],                           -- Weaknesses this can lead to
    can_follow TEXT[],                            -- Weaknesses this can follow
    related_attack_patterns TEXT[],               -- CAPEC IDs
    created TIMESTAMP,
    modified TIMESTAMP,
    cwe_version VARCHAR(20),                      -- Dataset version e.g., "4.14"
    deprecated BOOLEAN DEFAULT FALSE,
    embedding vector(1536),                       -- pgvector column
    embedding_model VARCHAR(50),                  -- text-embedding-3-small
    embedding_generated_at TIMESTAMP,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**cwe_views table:**

```sql
CREATE TABLE cwe_views (
    view_id VARCHAR(20) PRIMARY KEY,              -- e.g., CWE-1000
    name VARCHAR(300) NOT NULL,
    view_type VARCHAR(50),                        -- Graph, Explicit, Implicit
    status VARCHAR(20),
    description TEXT,
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**cwe_categories table:**

```sql
CREATE TABLE cwe_categories (
    category_id VARCHAR(20) PRIMARY KEY,          -- e.g., CWE-310
    name VARCHAR(300) NOT NULL,
    description TEXT,
    view_id VARCHAR(20) REFERENCES cwe_views(view_id),
    data_last_updated TIMESTAMP DEFAULT NOW()
);
```

**cwe_weakness_categories table:**

```sql
CREATE TABLE cwe_weakness_categories (
    id SERIAL PRIMARY KEY,
    weakness_id VARCHAR(20) REFERENCES cwe_weaknesses(cwe_id),
    category_id VARCHAR(20) REFERENCES cwe_categories(category_id),
    view_id VARCHAR(20) REFERENCES cwe_views(view_id),
    UNIQUE(weakness_id, category_id, view_id)
);
```

**cwe_external_mappings table:**

```sql
CREATE TABLE cwe_external_mappings (
    mapping_id SERIAL PRIMARY KEY,
    weakness_id VARCHAR(20) REFERENCES cwe_weaknesses(cwe_id),
    external_source VARCHAR(100) NOT NULL,        -- "OWASP Top Ten 2021"
    external_id VARCHAR(100) NOT NULL,            -- "A03:2021"
    mapping_type VARCHAR(50),                     -- Primary, Secondary
    rationale TEXT
);
```

### Indexes

**Vector similarity indexes (IVFFlat):**

```sql
-- Weakness semantic search (lists=100 for ~900 weaknesses)
CREATE INDEX idx_cwe_weakness_embedding
    ON cwe_weaknesses
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
```

**Hierarchical relationship indexes (GIN):**

```sql
-- Parent/child navigation
CREATE INDEX idx_cwe_parent_of
    ON cwe_weaknesses
    USING gin(parent_of);

CREATE INDEX idx_cwe_child_of
    ON cwe_weaknesses
    USING gin(child_of);

CREATE INDEX idx_cwe_peer_of
    ON cwe_weaknesses
    USING gin(peer_of);

-- Cross-framework mapping
CREATE INDEX idx_cwe_related_capec
    ON cwe_weaknesses
    USING gin(related_attack_patterns);
```

**Filter indexes:**

```sql
-- Abstraction level filtering
CREATE INDEX idx_cwe_abstraction
    ON cwe_weaknesses(abstraction);

-- Weakness ID for CVE joins
CREATE INDEX idx_cwe_weakness_id
    ON cwe_weaknesses(weakness_id);

-- External mapping composite index
CREATE INDEX idx_cwe_ext_source_id
    ON cwe_external_mappings(external_source, external_id);

-- External mapping weakness lookup
CREATE INDEX idx_cwe_ext_weakness
    ON cwe_external_mappings(weakness_id);

-- Category view lookup
CREATE INDEX idx_cwe_category_view
    ON cwe_categories(view_id);
```

---

## Integration with Ansvar AI Platform

The CWE module eliminates RAG staleness by providing fresh, local weakness data to AI assistants.

### Before: RAG Without MCP

```
┌─────────────────┐
│   Claude API    │  Knowledge cutoff: May 2025
│  (RAG context)  │  CWE data: 180-365 days stale
└─────────────────┘
```

**Problems:**
- CWE knowledge outdated by 180-365 days
- No access to latest weakness definitions
- Cannot query by semantic similarity
- Requires prompt engineering for weakness classification

### After: RAG + MCP Hybrid

```
┌─────────────────┐
│   Claude API    │  General knowledge (cutoff: May 2025)
│  (RAG context)  │  +
└────────┬────────┘  MCP tools for fresh CWE data
         │
         ▼
┌─────────────────┐
│  CWE MCP        │  Data freshness: <7 days
│  (Local DB)     │  Semantic search: Yes
│                 │  Full weakness database: Yes
└─────────────────┘
```

**Benefits:**
- CWE data freshness: <7 days (monthly sync)
- Semantic search for vulnerability → weakness mapping
- Cross-domain queries (CVE + CWE + CAPEC + ATT&CK)
- No prompt engineering needed

### Performance Targets

| Metric | Target | Status |
|--------|--------|--------|
| Data freshness | <7 days | Monthly sync |
| Query latency | <100ms | 28-95ms typical |
| Semantic accuracy | >0.7 similarity | Validated |
| Availability | 99.99% | Offline-first |

---

## Cross-Framework Correlation

### Complete Threat Intelligence Chain

The CWE module enables comprehensive cross-framework correlation:

```
CVE-2021-44228 (Log4Shell)
       │
       ▼
   CWE-917 (Expression Language Injection)
   CWE-20 (Improper Input Validation)
       │
       ▼
   CAPEC-135 (Format String Injection)
   CAPEC-242 (Code Injection)
       │
       ▼
   T1059 (Command and Scripting Interpreter)
   T1190 (Exploit Public-Facing Application)
```

### Example: Building the Chain

```python
# Start with a CVE
cve_details = await mcp_client.call_tool(
    "get_cve_details",
    {"cve_id": "CVE-2021-44228"}
)
# → Returns CWE-917, CWE-20

# Get weakness details including CAPEC mappings
for cwe_id in ["CWE-917", "CWE-20"]:
    weakness = await mcp_client.call_tool(
        "get_cwe_weakness_details",
        {"weakness_id": cwe_id}
    )
    # → Returns related_attack_patterns: ["CAPEC-135", "CAPEC-242"]

# Get CAPEC details including ATT&CK mappings
for capec_id in ["CAPEC-135", "CAPEC-242"]:
    pattern = await mcp_client.call_tool(
        "get_capec_pattern_details",
        {"pattern_id": capec_id}
    )
    # → Returns related_attack_patterns: ["T1059", "T1190"]

# Get ATT&CK technique details for detection
for attack_id in ["T1059", "T1190"]:
    technique = await mcp_client.call_tool(
        "get_technique_details",
        {"technique_id": attack_id}
    )
    # → Returns detection methods, data sources, mitigations
```

---

## Troubleshooting

### Semantic Search Not Working

**Error:** `find_similar_cwe_weaknesses returns empty results`

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
            'SELECT COUNT(*) FROM cwe_weaknesses WHERE embedding IS NOT NULL'
        )
        count = result.scalar()
        print(f'Weaknesses with embeddings: {count}')
        if count == 0:
            print('ERROR: No embeddings found. Re-sync with generate_embeddings=True')
asyncio.run(check())
"

# Re-sync with embeddings
docker-compose exec celery-worker python -c "
import asyncio
from cve_mcp.tasks.sync_cwe import sync_cwe_full
asyncio.run(sync_cwe_full(generate_embeddings=True))
"
```

### Traditional Search Returns Too Many Results

**Issue:** `search_cwe_weaknesses` returns many irrelevant results

**Solution:** Use more specific filters

```json
{
  "query": "injection",
  "abstraction": ["Base"],
  "active_only": true,
  "limit": 10
}
```

### Semantic Search Returns Low Similarity Scores

**Issue:** All results have similarity <0.6

**Explanation:** This is expected behavior. CWE weaknesses are very specific. Low similarity doesn't mean bad results—it means your description doesn't closely match any single weakness.

**Solutions:**
- Lower `min_similarity` to 0.5-0.6 for broader results
- Use more specific technical details in your description
- Try traditional search if you know weakness keywords

**Example:**

Vague: "Security bug in web app"
→ Low similarity scores (0.4-0.5)

Specific: "User input from login form is concatenated directly into SQL query string without parameterization, allowing UNION-based data extraction"
→ High similarity scores (0.85-0.94) for CWE-89 (SQL Injection)

### External Mappings Not Found

**Issue:** `search_by_external_mapping` returns no results

**Causes:**
1. External mappings not synced
2. Source name doesn't match exactly

**Solutions:**

```bash
# Check external mapping count
docker-compose exec server python -c "
from cve_mcp.services.database import db_service
import asyncio
async def check():
    async with db_service.session() as session:
        result = await session.execute('SELECT COUNT(*) FROM cwe_external_mappings')
        print(f'External mappings: {result.scalar()}')

        # List available sources
        result = await session.execute(
            'SELECT DISTINCT external_source FROM cwe_external_mappings LIMIT 20'
        )
        sources = result.scalars().all()
        print(f'Available sources: {sources}')
asyncio.run(check())
"
```

### Hierarchy Navigation Returns Empty

**Issue:** `get_cwe_hierarchy` returns no parents or children

**Explanation:** Some weaknesses (especially Pillars) have no parents, and some variants have no children. This is expected.

**Solution:** Check the weakness abstraction level:
- Pillars have no parents
- Variants typically have no children
- Use `direction: "both"` to see all relationships

### Performance Tuning

**Slow semantic search (>200ms):**

Check vector index:

```sql
-- Verify index exists
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'cwe_weaknesses'
  AND indexname LIKE '%embedding%';

-- Rebuild if needed
DROP INDEX idx_cwe_weakness_embedding;
CREATE INDEX idx_cwe_weakness_embedding
    ON cwe_weaknesses
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
```

**Slow hierarchy navigation (>100ms):**

```sql
-- Check GIN indexes exist
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'cwe_weaknesses'
  AND indexname LIKE '%parent%' OR indexname LIKE '%child%';

-- Rebuild if needed
REINDEX INDEX idx_cwe_parent_of;
REINDEX INDEX idx_cwe_child_of;
```

---

## CWE Abstraction Levels

CWE organizes weaknesses into a hierarchy for different use cases:

| Level | Description | Example | Use Case |
|-------|-------------|---------|----------|
| **Pillar** | Highest abstraction - broad weakness themes | CWE-664: Improper Control of Resource Lifetime | Architecture review, training |
| **Class** | Abstract weakness types | CWE-20: Improper Input Validation | Design patterns, threat modeling |
| **Base** | Specific weakness types | CWE-89: SQL Injection | Code review, SAST rules |
| **Variant** | Detailed variations | CWE-564: SQL Injection: Hibernate | Framework-specific guidance |
| **Compound** | Multiple weaknesses combined | CWE-352: CSRF | Complex vulnerability patterns |

---

## Best Practices

1. **Use semantic search for code review** — Natural language descriptions work better than keyword matching for real vulnerability findings
2. **Use traditional search for browsing** — Faster when you know what you're looking for
3. **Combine tools** — Use `find_similar_cwe_weaknesses` then `get_cwe_weakness_details` for deep analysis
4. **Cross-reference with CAPEC** — Use `find_weaknesses_for_capec` to understand attack-weakness relationships
5. **Navigate hierarchy** — Use `get_cwe_hierarchy` to understand weakness context and variants
6. **Leverage OWASP mappings** — Use `search_by_external_mapping` for compliance-driven prioritization
7. **Lower similarity threshold** — Start with 0.6-0.7, not 0.8+
8. **Describe technically** — More technical details = better semantic matches
9. **Monthly sync** — Keep CWE data fresh with monthly updates
10. **Build correlation chains** — Link CVE → CWE → CAPEC → ATT&CK for comprehensive threat intelligence

---

## Related Resources

- **[MITRE CWE Website](https://cwe.mitre.org/)** — Official CWE documentation
- **[CWE Downloads](https://cwe.mitre.org/data/)** — XML data source
- **[OWASP Top 10](https://owasp.org/Top10/)** — Industry standard weakness prioritization
- **[SANS Top 25](https://www.sans.org/top25-software-errors/)** — Most dangerous software weaknesses
- **[CAPEC Module Documentation](./capec.md)** — Attack pattern intelligence
- **[ATT&CK Module Documentation](./attack.md)** — Threat technique intelligence
- **[SETUP.md](../SETUP.md)** — Deployment and configuration guide

---

**Documentation version:** 1.0.0 (2026-01-31)

**Module status:** Production Ready

**For setup instructions:** See [SETUP.md](../SETUP.md)

**For architecture details:** See [Architecture ADRs](../architecture/)
