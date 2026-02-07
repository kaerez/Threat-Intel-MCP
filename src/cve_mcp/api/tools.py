"""MCP tool definitions and handlers."""

import time
from datetime import datetime
from typing import Any

from cve_mcp.api.schemas import (
    BatchSearchRequest,
    CheckKEVStatusRequest,
    CompareCloudServicesRequest,
    FindSimilarATLASCaseStudiesRequest,
    FindSimilarATLASTechniquesRequest,
    FindSimilarCAPECMitigationsRequest,
    FindSimilarCAPECPatternsRequest,
    FindSimilarCWEWeaknessesRequest,
    FindSimilarDefensesRequest,
    FindSimilarTechniquesRequest,
    FindSimilarThreatActorsRequest,
    FindWeaknessesForCAPECRequest,
    GetATLASTechniqueDetailsRequest,
    GetAttackCoverageRequest,
    GetCAPECPatternDetailsRequest,
    GetCloudServiceSecurityRequest,
    GetCVEDetailsRequest,
    GetCWEDetailsRequest,
    GetCWEHierarchyRequest,
    GetCWEWeaknessDetailsRequest,
    GetDefenseDetailsRequest,
    GetDefensesForAttackRequest,
    GetEPSSScoreRequest,
    GetExploitsRequest,
    GetGroupProfileRequest,
    GetSharedResponsibilityRequest,
    GetTechniqueBadgesRequest,
    GetTechniqueDetailsRequest,
    MCPToolDefinition,
    SearchATLASCaseStudiesRequest,
    SearchATLASTechniquesRequest,
    SearchByExternalMappingRequest,
    SearchByProductRequest,
    SearchCAPECMitigationsRequest,
    SearchCAPECPatternsRequest,
    SearchCloudServicesRequest,
    SearchCVERequest,
    SearchCWEWeaknessesRequest,
    SearchDefensesRequest,
    SearchTechniquesRequest,
    SearchThreatActorsRequest,
)
from cve_mcp.config import get_settings
from cve_mcp.services import (
    atlas_queries,
    attack_queries,
    capec_queries,
    cloud_security_queries,
    cwe_queries,
    d3fend_queries,
)
from cve_mcp.services.cache import cache_service
from cve_mcp.services.database import db_service

# MCP Tool Definitions
MCP_TOOLS: list[MCPToolDefinition] = [
    MCPToolDefinition(
        name="search_cve",
        description="Search CVEs by keyword, severity, score range, and filters. Returns matching CVE records with CVSS scores, KEV status, and EPSS data. Use get_cve_details for full information on a specific CVE. Supports full-text search on descriptions.",
        inputSchema={
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Full-text search in CVE description",
                },
                "cvss_min": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 10,
                    "description": "Minimum CVSS v3 score (0-10)",
                },
                "cvss_max": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 10,
                    "description": "Maximum CVSS v3 score (0-10)",
                },
                "severity": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                    },
                    "description": "Severity levels to include",
                },
                "has_kev": {
                    "type": "boolean",
                    "description": "Only CVEs in CISA KEV catalog",
                },
                "has_exploit": {
                    "type": "boolean",
                    "description": "Only CVEs with public exploits",
                },
                "epss_min": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "Minimum EPSS score (0-1)",
                },
                "published_after": {
                    "type": "string",
                    "format": "date",
                    "description": "Published after date (YYYY-MM-DD)",
                },
                "published_before": {
                    "type": "string",
                    "format": "date",
                    "description": "Published before date (YYYY-MM-DD)",
                },
                "cwe_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by CWE IDs (e.g., ['CWE-79', 'CWE-89'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results to return",
                },
                "offset": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Pagination offset",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cve_details",
        description="Get complete details for a specific CVE including CVSS scores, references, CPE mappings, KEV status, EPSS score, and exploit references.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier (e.g., CVE-2024-1234)",
                },
                "include_references": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include external links",
                },
                "include_cpe": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include CPE mappings",
                },
                "include_exploits": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include exploit references",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="check_kev_status",
        description="Check if a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog. Returns KEV details including required remediation actions and due dates.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_epss_score",
        description="Get the EPSS (Exploit Prediction Scoring System) score for a CVE. Returns the probability of exploitation in the next 30 days and percentile ranking.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_by_product",
        description="Find CVEs affecting a specific product and version. Useful for vulnerability assessment of software components.",
        inputSchema={
            "type": "object",
            "required": ["product_name"],
            "properties": {
                "product_name": {
                    "type": "string",
                    "description": "Product name to search (e.g., 'apache', 'nginx')",
                },
                "vendor": {
                    "type": "string",
                    "description": "Vendor name filter (e.g., 'apache', 'microsoft')",
                },
                "version": {
                    "type": "string",
                    "description": "Specific version to check (e.g., '2.4.49')",
                },
                "version_operator": {
                    "type": "string",
                    "enum": ["eq", "lt", "lte", "gt", "gte"],
                    "description": "Version comparison operator",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_exploits",
        description="Get public exploit code references for a CVE from Metasploit, ExploitDB, GitHub PoCs, and other sources.",
        inputSchema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$",
                    "description": "CVE identifier",
                },
                "verified_only": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only return verified exploits",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cwe_details",
        description="Get details about a CWE (Common Weakness Enumeration) including name, description, consequences, mitigations, detection methods, external mappings (OWASP, SANS), and relationships. Alias for get_cwe_weakness_details - both return the same comprehensive data.",
        inputSchema={
            "type": "object",
            "required": ["cwe_id"],
            "properties": {
                "cwe_id": {
                    "type": "string",
                    "pattern": "^(CWE-)?\\d+$",
                    "description": "CWE identifier (e.g., CWE-79 or 79)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="batch_search",
        description="Get details for multiple CVEs in one query (max 100). Efficient for bulk vulnerability assessment.",
        inputSchema={
            "type": "object",
            "required": ["cve_ids"],
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,}$"},
                    "maxItems": 100,
                    "description": "List of CVE IDs to look up",
                },
                "include_kev": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include KEV status",
                },
                "include_epss": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include EPSS scores",
                },
            },
        },
    ),
    # ATT&CK Tools
    MCPToolDefinition(
        name="search_techniques",
        description="Search MITRE ATT&CK techniques using traditional keyword and filter-based search. Filter by tactics, platforms, and search technique names/descriptions.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in technique name/description",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics (e.g., ['initial-access', 'execution'])",
                },
                "platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by platforms (e.g., ['windows', 'linux'])",
                },
                "include_subtechniques": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include subtechniques in results",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_techniques",
        description="Find MITRE ATT&CK techniques using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Perfect for incident response - describe an attack scenario in natural language and get matching techniques with similarity scores. Uses AI embeddings for intelligent matching beyond keyword search. Example: 'Attacker sent phishing email with malicious PDF that executed PowerShell commands'. Use get_defenses_for_attack to find countermeasures for matched techniques.",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of attack scenario or technique",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics",
                },
                "platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by platforms",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_technique_details",
        description="Get complete details for a specific MITRE ATT&CK technique including tactics, platforms, detection methods, data sources, and mitigation strategies.",
        inputSchema={
            "type": "object",
            "required": ["technique_id"],
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "Technique ID (e.g., T1566 or T1566.001)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_technique_badges",
        description="Get ATT&CK Navigator badge URLs for multiple techniques. Returns a mapping of technique IDs to their badge URLs for documentation and reporting.",
        inputSchema={
            "type": "object",
            "required": ["technique_ids"],
            "properties": {
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of technique IDs (e.g., ['T1566', 'T1566.001'])",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_threat_actors",
        description="Search MITRE ATT&CK threat actor groups using traditional keyword search. Filter by group names, aliases, and techniques used.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in group name/aliases/description",
                },
                "techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by techniques used (e.g., ['T1566.001'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_threat_actors",
        description="Find MITRE ATT&CK threat actor groups using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Perfect for threat attribution - describe observed threat actor behavior and get matching groups with similarity scores. Example: 'Advanced persistent threat targeting financial institutions with custom malware'. Use get_group_profile for full details on a matched group.",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of threat actor or observed activity",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_group_profile",
        description="Get complete profile for a specific MITRE ATT&CK threat actor group including aliases, techniques used, software, and attribution details.",
        inputSchema={
            "type": "object",
            "required": ["group_id"],
            "properties": {
                "group_id": {
                    "type": "string",
                    "description": "Group ID (e.g., G0001)",
                },
            },
        },
    ),
    # ATLAS Tools
    MCPToolDefinition(
        name="search_atlas_techniques",
        description="Search MITRE ATLAS AI/ML attack techniques using traditional keyword and filter-based search. Filter by tactics, ML lifecycle stage, and AI system type. ATLAS focuses on adversarial ML attacks against AI/ML systems.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in technique name/description",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics (e.g., ['reconnaissance', 'ml-attack', 'impact'])",
                },
                "ml_lifecycle_stage": {
                    "type": "string",
                    "description": "Filter by ML lifecycle stage (e.g., 'data-collection', 'training', 'deployment')",
                },
                "ai_system_type": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by AI system type (e.g., ['computer-vision', 'nlp', 'recommendation'])",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_atlas_techniques",
        description="Find MITRE ATLAS AI/ML attack techniques using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Describe an adversarial ML attack scenario in natural language and get matching techniques with similarity scores. Example: 'Attacker poisoned training data to create backdoor in image classifier'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of AI/ML attack scenario",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tactics",
                },
                "ml_lifecycle_stage": {
                    "type": "string",
                    "description": "Filter by ML lifecycle stage",
                },
                "ai_system_type": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by AI system type",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated/revoked techniques",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_atlas_technique_details",
        description="Get complete details for a specific MITRE ATLAS AI/ML attack technique including tactics, ML lifecycle stage, AI system types, detection methods, and mitigations.",
        inputSchema={
            "type": "object",
            "required": ["technique_id"],
            "properties": {
                "technique_id": {
                    "type": "string",
                    "pattern": "^AML\\.T\\d{4}$",
                    "description": "ATLAS technique ID (e.g., AML.T0001)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_atlas_case_studies",
        description="Search MITRE ATLAS real-world case studies of AI/ML attacks. Filter by techniques used and search case study names and summaries.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in case study name/summary",
                },
                "techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by ATLAS techniques used (e.g., ['AML.T0001'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_atlas_case_studies",
        description="Find similar MITRE ATLAS case studies using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Describe an AI/ML incident or attack scenario and get matching real-world case studies with similarity scores. Example: 'Autonomous vehicle fooled by adversarial road signs'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of AI/ML incident or scenario",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    # CAPEC Tools
    MCPToolDefinition(
        name="search_capec_patterns",
        description="Search MITRE CAPEC attack patterns using traditional keyword and filter-based search. Filter by abstraction level, attack likelihood, and severity. CAPEC provides detailed descriptions of common attack patterns used by adversaries.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in pattern name/description",
                },
                "abstraction": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["Meta", "Standard", "Detailed"]},
                    "description": "Filter by abstraction levels (Meta=high-level, Standard=middle, Detailed=specific)",
                },
                "likelihood": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                    "description": "Filter by attack likelihood",
                },
                "severity": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                    "description": "Filter by typical severity",
                },
                "related_cwe": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by related CWE IDs (e.g., ['CWE-79', 'CWE-89'])",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated patterns",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_capec_patterns",
        description="Find MITRE CAPEC attack patterns using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Describe an attack scenario in natural language and get matching patterns with similarity scores. Example: 'Attacker manipulates input fields to inject SQL commands and extract database contents'. Use find_weaknesses_for_capec to find CWEs exploited by matched patterns.",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of attack scenario",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "abstraction": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["Meta", "Standard", "Detailed"]},
                    "description": "Filter by abstraction levels",
                },
                "likelihood": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                    "description": "Filter by attack likelihood",
                },
                "severity": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                    "description": "Filter by typical severity",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated patterns",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_capec_pattern_details",
        description="Get complete details for a specific MITRE CAPEC attack pattern including prerequisites, execution flow, consequences, mitigations, and related weaknesses (CWEs).",
        inputSchema={
            "type": "object",
            "required": ["pattern_id"],
            "properties": {
                "pattern_id": {
                    "type": "string",
                    "pattern": "^CAPEC-\\d+$",
                    "description": "CAPEC pattern ID (e.g., CAPEC-66)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_capec_mitigations",
        description="Search MITRE CAPEC mitigations (security controls) using traditional keyword search. Filter by effectiveness and patterns mitigated.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in mitigation name/description",
                },
                "effectiveness": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                    "description": "Filter by effectiveness level",
                },
                "patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by patterns mitigated (e.g., ['CAPEC-66'])",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_capec_mitigations",
        description="Find MITRE CAPEC mitigations using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Describe what kind of security control or mitigation you need and get matching mitigations with similarity scores. Example: 'Input validation to prevent injection attacks'",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of mitigation need or security control",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "effectiveness": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low"],
                    "description": "Filter by effectiveness level",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    # CWE Tools
    MCPToolDefinition(
        name="search_cwe_weaknesses",
        description="Search MITRE CWE weaknesses using traditional keyword and filter-based search. Filter by abstraction level (Pillar, Class, Base, Variant, Compound) and optionally include child weaknesses in results. CWE provides a comprehensive catalog of software and hardware weakness types.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in weakness name/description",
                },
                "abstraction": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["Pillar", "Class", "Base", "Variant", "Compound"],
                    },
                    "description": "Filter by abstraction levels (Pillar=highest, Variant=most specific)",
                },
                "include_children": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include child weaknesses of matched results",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated weaknesses",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_cwe_weaknesses",
        description="Find MITRE CWE weaknesses using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Describe a vulnerability or coding issue in natural language and get matching weaknesses with similarity scores. Example: 'User input is directly used in SQL queries without validation'. Use get_cwe_weakness_details for full weakness info, or get_cwe_hierarchy to explore related weaknesses.",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of weakness or vulnerability",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "abstraction": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["Pillar", "Class", "Base", "Variant", "Compound"],
                    },
                    "description": "Filter by abstraction levels",
                },
                "active_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Exclude deprecated weaknesses",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cwe_weakness_details",
        description="Get complete details for a specific CWE weakness including common consequences, potential mitigations, detection methods, external mappings (OWASP, SANS), and relationships to other weaknesses.",
        inputSchema={
            "type": "object",
            "required": ["weakness_id"],
            "properties": {
                "weakness_id": {
                    "type": "string",
                    "pattern": "^(CWE-)?\\d+$",
                    "description": "CWE weakness ID (e.g., CWE-79 or 79)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="search_by_external_mapping",
        description="Search CWE weaknesses by external standard mappings like OWASP Top Ten or SANS Top 25. Useful for compliance and prioritization based on industry standards.",
        inputSchema={
            "type": "object",
            "required": ["source"],
            "properties": {
                "source": {
                    "type": "string",
                    "description": "External source name (e.g., 'OWASP Top Ten 2021', 'SANS Top 25')",
                },
                "external_id": {
                    "type": "string",
                    "description": "External ID filter (e.g., 'A03:2021' for OWASP)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cwe_hierarchy",
        description="Navigate the CWE parent/child hierarchy. Useful for understanding weakness relationships - e.g., finding all specific variants of a high-level weakness class, or understanding which broader category a specific weakness belongs to.",
        inputSchema={
            "type": "object",
            "required": ["weakness_id"],
            "properties": {
                "weakness_id": {
                    "type": "string",
                    "pattern": "^(CWE-)?\\d+$",
                    "description": "CWE weakness ID (e.g., CWE-79 or 79)",
                },
                "direction": {
                    "type": "string",
                    "enum": ["parents", "children", "both"],
                    "default": "both",
                    "description": "Direction to traverse hierarchy",
                },
                "depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "default": 3,
                    "description": "Maximum depth to traverse",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_weaknesses_for_capec",
        description="Cross-framework search: find CWE weaknesses that are exploited by a specific CAPEC attack pattern. Links attack patterns to the underlying weaknesses they target.",
        inputSchema={
            "type": "object",
            "required": ["pattern_id"],
            "properties": {
                "pattern_id": {
                    "type": "string",
                    "pattern": "^(CAPEC-)?\\d+$",
                    "description": "CAPEC pattern ID (e.g., CAPEC-66)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    # D3FEND Tools
    MCPToolDefinition(
        name="search_defenses",
        description="Search MITRE D3FEND defensive techniques using traditional keyword and filter-based search. D3FEND provides a catalog of defensive countermeasures that map to ATT&CK techniques. Filter by D3FEND tactics: Model, Harden, Detect, Isolate, Deceive, Evict, Restore. Omit query to browse by tactic.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Full-text search in defensive technique name/description",
                },
                "tactic": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by D3FEND tactics (e.g., ['Harden', 'Detect'])",
                },
                "include_children": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include child techniques of matches",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="find_similar_defenses",
        description="Find MITRE D3FEND defensive techniques using AI-powered semantic similarity search. Requires OPENAI_API_KEY. Describe a defensive need or security control in natural language and get matching D3FEND techniques with similarity scores. Example: 'network segmentation to prevent lateral movement'. Use get_defense_details for full technique info including ATT&CK mappings.",
        inputSchema={
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "minLength": 10,
                    "maxLength": 5000,
                    "description": "Natural language description of defensive need or security control",
                },
                "min_similarity": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.7,
                    "description": "Minimum similarity threshold (0-1)",
                },
                "tactic": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by D3FEND tactics",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Max results",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_defense_details",
        description="Get complete details for a specific D3FEND defensive technique including description, tactic, ATT&CK mappings, synonyms, references, and knowledge base article URL.",
        inputSchema={
            "type": "object",
            "required": ["technique_id"],
            "properties": {
                "technique_id": {
                    "type": "string",
                    "pattern": "^(D3-)?[A-Z]{2,}$",
                    "description": "D3FEND technique ID (e.g., D3-AL for Application Lockdown)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_defenses_for_attack",
        description="Find D3FEND countermeasures for a specific ATT&CK technique. KEY FEATURE: answers 'How do I defend against this attack?' Returns defensive techniques that counter the specified attack, optionally including defenses for all subtechniques.",
        inputSchema={
            "type": "object",
            "required": ["attack_technique_id"],
            "properties": {
                "attack_technique_id": {
                    "type": "string",
                    "pattern": "^T?\\d{4}(\\.\\d{3})?$",
                    "description": "ATT&CK technique ID (e.g., T1059 or T1059.001)",
                },
                "include_subtechniques": {
                    "type": "boolean",
                    "default": True,
                    "description": "Also find defenses for subtechniques (T1059.001, T1059.002, etc.)",
                },
                "relationship_type": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["counters", "enables", "related-to", "produces", "uses"],
                    },
                    "description": "Filter by relationship type (e.g., ['counters'])",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_attack_coverage",
        description="Analyze ATT&CK coverage for given D3FEND techniques. Helps assess defensive posture by showing which ATT&CK techniques are covered by your defenses and identifying gaps. Returns coverage percentage, covered techniques, and uncovered gaps.",
        inputSchema={
            "type": "object",
            "required": ["technique_ids"],
            "properties": {
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of D3FEND technique IDs to analyze (e.g., ['D3-AL', 'D3-NI'])",
                },
                "show_gaps": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include list of uncovered ATT&CK techniques",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_data_freshness",
        description="Check the freshness and sync status of all data sources. Returns last sync time, data age in hours, record counts, and health status (current/stale/critical) for each source: NVD, CISA KEV, EPSS, ExploitDB, ATT&CK, ATLAS, CAPEC, CWE, D3FEND. Use this to verify data is up-to-date before making security assessments.",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    MCPToolDefinition(
        name="search_cloud_services",
        description="Search cloud services across AWS, Azure, and GCP. Filter by provider, category, or search text. Returns service names, descriptions, and categories. Use get_cloud_service_security for detailed security properties.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Text search in service name and description",
                },
                "provider": {
                    "type": "string",
                    "enum": ["aws", "azure", "gcp"],
                    "description": "Filter by cloud provider",
                },
                "category": {
                    "type": "string",
                    "description": "Filter by service category (e.g., object_storage, compute, database_relational)",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 50,
                    "description": "Max results to return",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_cloud_service_security",
        description="Get comprehensive security properties for a specific cloud service. Returns all security dimensions: encryption (at rest/in transit), access control, network isolation, audit logging, threat detection, compliance certifications, shared responsibility boundaries, and security defaults. Each property includes source documentation URL, confidence score, and verification metadata.",
        inputSchema={
            "type": "object",
            "required": ["provider", "service"],
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["aws", "azure", "gcp"],
                    "description": "Cloud provider",
                },
                "service": {
                    "type": "string",
                    "description": "Service short name (e.g., s3, blob-storage, cloud-storage)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="compare_cloud_services",
        description="Compare equivalent services across cloud providers. Returns side-by-side comparison with comparable security dimensions, non-comparable aspects, and nuanced differences that matter for security (e.g., S3 Object Lock vs Azure Immutable Storage). Includes confidence scores and last verification dates.",
        inputSchema={
            "type": "object",
            "required": ["service_category"],
            "properties": {
                "service_category": {
                    "type": "string",
                    "description": "Service category to compare (e.g., object_storage, compute, database_relational)",
                },
                "providers": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["aws", "azure", "gcp"],
                    },
                    "description": "Optional list of providers to compare (default: all)",
                },
            },
        },
    ),
    MCPToolDefinition(
        name="get_shared_responsibility",
        description="Get shared responsibility model breakdown for a cloud service. Returns responsibilities by layer (physical, network, hypervisor, OS, application, data, identity, client endpoint) with owner (provider/customer/shared) and detailed descriptions. Includes official documentation links.",
        inputSchema={
            "type": "object",
            "required": ["provider", "service"],
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["aws", "azure", "gcp"],
                    "description": "Cloud provider",
                },
                "service": {
                    "type": "string",
                    "description": "Service short name (e.g., s3, blob-storage, cloud-storage)",
                },
                "layer": {
                    "type": "string",
                    "enum": [
                        "physical",
                        "network",
                        "hypervisor",
                        "operating_system",
                        "application",
                        "data",
                        "identity",
                        "client_endpoint",
                    ],
                    "description": "Optional specific layer to query",
                },
            },
        },
    ),
]


def get_mcp_tools() -> list[MCPToolDefinition]:
    """Get list of MCP tool definitions."""
    return MCP_TOOLS


async def _get_metadata(query_time_ms: int, cache_hit: bool = False) -> dict[str, Any]:
    """Build metadata for response."""
    settings = get_settings()

    # Get last sync time
    async with db_service.session() as session:
        sync_metadata = await db_service.get_sync_metadata(session)

    nvd_sync = sync_metadata.get("nvd_recent", {})
    last_sync = nvd_sync.get("last_sync")

    data_age_hours = None
    data_freshness = "current"
    if last_sync:
        try:
            last_sync_dt = datetime.fromisoformat(last_sync)
            data_age_hours = int((datetime.now() - last_sync_dt).total_seconds() / 3600)
            if data_age_hours > settings.data_freshness_critical_hours:
                data_freshness = "critical"
            elif data_age_hours > settings.data_freshness_warning_hours:
                data_freshness = "stale"
        except Exception:
            pass

    return {
        "query_time_ms": query_time_ms,
        "cache_hit": cache_hit,
        "data_freshness": data_freshness,
        "last_sync_time": last_sync,
        "data_age_hours": data_age_hours,
    }


async def handle_search_cve(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_cve tool call."""
    start_time = time.time()

    # Check cache
    cached = await cache_service.get_search(params)
    if cached:
        query_time_ms = int((time.time() - start_time) * 1000)
        return {
            "data": cached,
            "metadata": await _get_metadata(query_time_ms, cache_hit=True),
        }

    # Parse request
    request = SearchCVERequest(**params)

    # Execute query
    async with db_service.session() as session:
        cves, total_count = await db_service.search_cves(
            session,
            keyword=request.keyword,
            cvss_min=request.cvss_min,
            cvss_max=request.cvss_max,
            severity=request.severity,
            has_kev=request.has_kev,
            has_exploit=request.has_exploit,
            epss_min=request.epss_min,
            published_after=request.published_after,
            published_before=request.published_before,
            cwe_ids=request.cwe_ids,
            limit=request.limit,
            offset=request.offset,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    data = {
        "cves": cves,
        "total_results": total_count,
        "returned_results": len(cves),
    }

    # Cache results
    await cache_service.set_search(params, data)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cve_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cve_details tool call."""
    start_time = time.time()
    request = GetCVEDetailsRequest(**params)

    # Check cache
    cached = await cache_service.get_cve(request.cve_id)
    if cached:
        query_time_ms = int((time.time() - start_time) * 1000)
        return {
            "data": cached,
            "metadata": await _get_metadata(query_time_ms, cache_hit=True),
        }

    # Execute query
    async with db_service.session() as session:
        data = await db_service.get_cve_details(
            session,
            cve_id=request.cve_id,
            include_references=request.include_references,
            include_cpe=request.include_cpe,
            include_exploits=request.include_exploits,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    if data:
        await cache_service.set_cve(request.cve_id, data)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_check_kev_status(params: dict[str, Any]) -> dict[str, Any]:
    """Handle check_kev_status tool call."""
    start_time = time.time()
    request = CheckKEVStatusRequest(**params)

    async with db_service.session() as session:
        data = await db_service.check_kev_status(session, request.cve_id)

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_epss_score(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_epss_score tool call."""
    start_time = time.time()
    request = GetEPSSScoreRequest(**params)

    async with db_service.session() as session:
        data = await db_service.get_epss_score(session, request.cve_id)

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_by_product(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_by_product tool call."""
    start_time = time.time()
    request = SearchByProductRequest(**params)

    async with db_service.session() as session:
        cves, total_count = await db_service.search_by_product(
            session,
            product_name=request.product_name,
            vendor=request.vendor,
            version=request.version,
            version_operator=request.version_operator,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "cves": cves,
            "total_results": total_count,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_exploits(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_exploits tool call."""
    start_time = time.time()
    request = GetExploitsRequest(**params)

    async with db_service.session() as session:
        data = await db_service.get_exploits(
            session,
            cve_id=request.cve_id,
            verified_only=request.verified_only,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cwe_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cwe_details tool call - routes to comprehensive CWE data."""
    start_time = time.time()
    request = GetCWEDetailsRequest(**params)

    # Route to the comprehensive CWE query service (same as get_cwe_weakness_details)
    async with db_service.session() as session:
        data = await cwe_queries.get_weakness_details(session, weakness_id=request.cwe_id)

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_batch_search(params: dict[str, Any]) -> dict[str, Any]:
    """Handle batch_search tool call."""
    start_time = time.time()
    request = BatchSearchRequest(**params)

    async with db_service.session() as session:
        data = await db_service.batch_search(
            session,
            cve_ids=request.cve_ids,
            include_kev=request.include_kev,
            include_epss=request.include_epss,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


# ATT&CK Tool Handlers


async def handle_search_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_techniques tool call."""
    start_time = time.time()
    request = SearchTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques, total_count = await attack_queries.search_techniques(
            session,
            query=request.query,
            tactics=request.tactics,
            platforms=request.platforms,
            include_subtechniques=request.include_subtechniques,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "total_results": total_count,
            "returned_results": len(techniques),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_techniques tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques = await attack_queries.find_similar_techniques(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            tactics=request.tactics,
            platforms=request.platforms,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "returned_results": len(techniques),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_technique_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_technique_details tool call."""
    start_time = time.time()
    request = GetTechniqueDetailsRequest(**params)

    async with db_service.session() as session:
        data = await attack_queries.get_technique_details(
            session,
            technique_id=request.technique_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_technique_badges(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_technique_badges tool call."""
    start_time = time.time()
    request = GetTechniqueBadgesRequest(**params)

    async with db_service.session() as session:
        badges = await attack_queries.get_technique_badges(
            session,
            technique_ids=request.technique_ids,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "badges": badges,
            "count": len(badges),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_threat_actors(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_threat_actors tool call."""
    start_time = time.time()
    request = SearchThreatActorsRequest(**params)

    async with db_service.session() as session:
        groups, total_count = await attack_queries.search_threat_actors(
            session,
            query=request.query,
            techniques=request.techniques,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "groups": groups,
            "total_results": total_count,
            "returned_results": len(groups),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_threat_actors(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_threat_actors tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarThreatActorsRequest(**params)

    async with db_service.session() as session:
        groups = await attack_queries.find_similar_threat_actors(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "groups": groups,
            "returned_results": len(groups),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_group_profile(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_group_profile tool call."""
    start_time = time.time()
    request = GetGroupProfileRequest(**params)

    async with db_service.session() as session:
        data = await attack_queries.get_group_profile(
            session,
            group_id=request.group_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


# ATLAS Tool Handlers


async def handle_search_atlas_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_atlas_techniques tool call."""
    start_time = time.time()
    request = SearchATLASTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques, total_count = await atlas_queries.search_techniques(
            session,
            query=request.query,
            tactics=request.tactics,
            ml_lifecycle_stage=request.ml_lifecycle_stage,
            ai_system_type=request.ai_system_type,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "total_results": total_count,
            "returned_results": len(techniques),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_atlas_techniques(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_atlas_techniques tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarATLASTechniquesRequest(**params)

    async with db_service.session() as session:
        techniques = await atlas_queries.find_similar_techniques(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            tactics=request.tactics,
            ml_lifecycle_stage=request.ml_lifecycle_stage,
            ai_system_type=request.ai_system_type,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "techniques": techniques,
            "returned_results": len(techniques),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_atlas_technique_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_atlas_technique_details tool call."""
    start_time = time.time()
    request = GetATLASTechniqueDetailsRequest(**params)

    async with db_service.session() as session:
        data = await atlas_queries.get_technique_details(
            session,
            technique_id=request.technique_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_atlas_case_studies(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_atlas_case_studies tool call."""
    start_time = time.time()
    request = SearchATLASCaseStudiesRequest(**params)

    async with db_service.session() as session:
        case_studies, total_count = await atlas_queries.search_case_studies(
            session,
            query=request.query,
            techniques=request.techniques,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "case_studies": case_studies,
            "total_results": total_count,
            "returned_results": len(case_studies),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_atlas_case_studies(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_atlas_case_studies tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarATLASCaseStudiesRequest(**params)

    async with db_service.session() as session:
        case_studies = await atlas_queries.find_similar_case_studies(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "case_studies": case_studies,
            "returned_results": len(case_studies),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


# CAPEC Tool Handlers


async def handle_search_capec_patterns(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_capec_patterns tool call."""
    start_time = time.time()
    request = SearchCAPECPatternsRequest(**params)

    async with db_service.session() as session:
        patterns, total_count = await capec_queries.search_patterns(
            session,
            query=request.query,
            abstraction=request.abstraction,
            likelihood=request.likelihood,
            severity=request.severity,
            related_cwe=request.related_cwe,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "patterns": patterns,
            "total_results": total_count,
            "returned_results": len(patterns),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_capec_patterns(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_capec_patterns tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarCAPECPatternsRequest(**params)

    async with db_service.session() as session:
        patterns = await capec_queries.find_similar_patterns(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            abstraction=request.abstraction,
            likelihood=request.likelihood,
            severity=request.severity,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "patterns": patterns,
            "returned_results": len(patterns),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_capec_pattern_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_capec_pattern_details tool call."""
    start_time = time.time()
    request = GetCAPECPatternDetailsRequest(**params)

    async with db_service.session() as session:
        data = await capec_queries.get_pattern_details(
            session,
            pattern_id=request.pattern_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_capec_mitigations(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_capec_mitigations tool call."""
    start_time = time.time()
    request = SearchCAPECMitigationsRequest(**params)

    async with db_service.session() as session:
        mitigations, total_count = await capec_queries.search_mitigations(
            session,
            query=request.query,
            effectiveness=request.effectiveness,
            patterns=request.patterns,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "mitigations": mitigations,
            "total_results": total_count,
            "returned_results": len(mitigations),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_capec_mitigations(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_capec_mitigations tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarCAPECMitigationsRequest(**params)

    async with db_service.session() as session:
        mitigations = await capec_queries.find_similar_mitigations(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            effectiveness=request.effectiveness,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "mitigations": mitigations,
            "returned_results": len(mitigations),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


# CWE Tool Handlers


async def handle_search_cwe_weaknesses(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_cwe_weaknesses tool call."""
    start_time = time.time()
    request = SearchCWEWeaknessesRequest(**params)

    async with db_service.session() as session:
        weaknesses, total_count = await cwe_queries.search_weaknesses(
            session,
            query=request.query,
            abstraction=request.abstraction,
            include_children=request.include_children,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "weaknesses": weaknesses,
            "total_results": total_count,
            "returned_results": len(weaknesses),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_cwe_weaknesses(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_cwe_weaknesses tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarCWEWeaknessesRequest(**params)

    async with db_service.session() as session:
        weaknesses = await cwe_queries.find_similar_weaknesses(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            abstraction=request.abstraction,
            active_only=request.active_only,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "weaknesses": weaknesses,
            "returned_results": len(weaknesses),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cwe_weakness_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cwe_weakness_details tool call."""
    start_time = time.time()
    request = GetCWEWeaknessDetailsRequest(**params)

    async with db_service.session() as session:
        data = await cwe_queries.get_weakness_details(
            session,
            weakness_id=request.weakness_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_search_by_external_mapping(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_by_external_mapping tool call."""
    start_time = time.time()
    request = SearchByExternalMappingRequest(**params)

    async with db_service.session() as session:
        weaknesses = await cwe_queries.search_by_external_mapping(
            session,
            source=request.source,
            external_id=request.external_id,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "weaknesses": weaknesses,
            "returned_results": len(weaknesses),
            "source_filter": request.source,
            "external_id_filter": request.external_id,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cwe_hierarchy(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cwe_hierarchy tool call."""
    start_time = time.time()
    request = GetCWEHierarchyRequest(**params)

    async with db_service.session() as session:
        data = await cwe_queries.get_weakness_hierarchy(
            session,
            weakness_id=request.weakness_id,
            direction=request.direction,
            depth=request.depth,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_weaknesses_for_capec(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_weaknesses_for_capec tool call."""
    start_time = time.time()
    request = FindWeaknessesForCAPECRequest(**params)

    async with db_service.session() as session:
        weaknesses = await cwe_queries.find_weaknesses_for_capec(
            session,
            pattern_id=request.pattern_id,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "weaknesses": weaknesses,
            "returned_results": len(weaknesses),
            "capec_pattern": request.pattern_id,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


# D3FEND Tool Handlers


async def handle_search_defenses(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_defenses tool call."""
    start_time = time.time()
    request = SearchDefensesRequest(**params)

    async with db_service.session() as session:
        defenses, total_count = await d3fend_queries.search_defenses(
            session,
            query=request.query,
            tactic=request.tactic,
            include_children=request.include_children,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "defenses": defenses,
            "total_results": total_count,
            "returned_results": len(defenses),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_find_similar_defenses(params: dict[str, Any]) -> dict[str, Any]:
    """Handle find_similar_defenses tool call (semantic search)."""
    start_time = time.time()
    request = FindSimilarDefensesRequest(**params)

    async with db_service.session() as session:
        defenses = await d3fend_queries.find_similar_defenses(
            session,
            description=request.description,
            min_similarity=request.min_similarity,
            tactic=request.tactic,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "defenses": defenses,
            "returned_results": len(defenses),
            "query_embedding_generated": True,
            "min_similarity": request.min_similarity,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_defense_details(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_defense_details tool call."""
    start_time = time.time()
    request = GetDefenseDetailsRequest(**params)

    async with db_service.session() as session:
        data = await d3fend_queries.get_defense_details(
            session,
            technique_id=request.technique_id,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_defenses_for_attack(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_defenses_for_attack tool call."""
    start_time = time.time()
    request = GetDefensesForAttackRequest(**params)

    async with db_service.session() as session:
        defenses = await d3fend_queries.get_defenses_for_attack(
            session,
            attack_technique_id=request.attack_technique_id,
            include_subtechniques=request.include_subtechniques,
            relationship_type=request.relationship_type,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "defenses": defenses,
            "returned_results": len(defenses),
            "attack_technique_id": request.attack_technique_id,
            "include_subtechniques": request.include_subtechniques,
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_attack_coverage(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_attack_coverage tool call."""
    start_time = time.time()
    request = GetAttackCoverageRequest(**params)

    async with db_service.session() as session:
        data = await d3fend_queries.get_attack_coverage(
            session,
            technique_ids=request.technique_ids,
            show_gaps=request.show_gaps,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_data_freshness(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_data_freshness tool call."""
    start_time = time.time()
    settings = get_settings()

    async with db_service.session() as session:
        db_stats = await db_service.get_database_stats(session)
        sync_metadata = await db_service.get_sync_metadata(session)

    # Build per-source freshness info
    data_freshness: dict[str, Any] = {}
    for source, meta in sync_metadata.items():
        status = "current"
        age_hours = None
        if meta.get("last_sync"):
            try:
                last_sync = datetime.fromisoformat(meta["last_sync"])
                age_hours = int((datetime.now() - last_sync).total_seconds() / 3600)
                if age_hours > settings.data_freshness_critical_hours:
                    status = "critical"
                elif age_hours > settings.data_freshness_warning_hours:
                    status = "stale"
            except Exception:
                pass

        data_freshness[source] = {
            "last_sync": meta.get("last_sync"),
            "age_hours": age_hours,
            "status": status,
        }

    # Check cache connectivity
    cache_healthy = await cache_service.health_check()

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "data_freshness": data_freshness,
            "database": db_stats,
            "cache_connected": cache_healthy,
        },
        "metadata": {
            "query_time_ms": query_time_ms,
            "cache_hit": False,
        },
    }


# ============================================================================
# Cloud Security Handlers
# ============================================================================


async def handle_search_cloud_services(params: dict[str, Any]) -> dict[str, Any]:
    """Handle search_cloud_services tool call."""
    start_time = time.time()
    request = SearchCloudServicesRequest(**params)

    async with db_service.session() as session:
        services, total_count = await cloud_security_queries.search_services(
            session,
            query=request.query,
            provider=request.provider,
            category=request.category,
            limit=request.limit,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    return {
        "data": {
            "services": services,
            "total_results": total_count,
            "returned_results": len(services),
        },
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_cloud_service_security(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_cloud_service_security tool call."""
    start_time = time.time()
    request = GetCloudServiceSecurityRequest(**params)

    async with db_service.session() as session:
        data = await cloud_security_queries.get_service_security(
            session,
            provider=request.provider,
            service=request.service,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    if not data:
        return {
            "data": None,
            "error": f"Service not found: {request.provider}-{request.service}",
            "metadata": await _get_metadata(query_time_ms),
        }

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_compare_cloud_services(params: dict[str, Any]) -> dict[str, Any]:
    """Handle compare_cloud_services tool call."""
    start_time = time.time()
    request = CompareCloudServicesRequest(**params)

    async with db_service.session() as session:
        data = await cloud_security_queries.compare_services(
            session,
            service_category=request.service_category,
            providers=request.providers,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    if not data:
        return {
            "data": None,
            "error": f"Service category not found or no equivalence defined: {request.service_category}",
            "metadata": await _get_metadata(query_time_ms),
        }

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


async def handle_get_shared_responsibility(params: dict[str, Any]) -> dict[str, Any]:
    """Handle get_shared_responsibility tool call."""
    start_time = time.time()
    request = GetSharedResponsibilityRequest(**params)

    async with db_service.session() as session:
        data = await cloud_security_queries.get_shared_responsibility(
            session,
            provider=request.provider,
            service=request.service,
            layer=request.layer,
        )

    query_time_ms = int((time.time() - start_time) * 1000)

    if not data:
        return {
            "data": None,
            "error": f"Service not found: {request.provider}-{request.service}",
            "metadata": await _get_metadata(query_time_ms),
        }

    return {
        "data": data,
        "metadata": await _get_metadata(query_time_ms),
    }


# Tool handler mapping
TOOL_HANDLERS = {
    "search_cve": handle_search_cve,
    "get_cve_details": handle_get_cve_details,
    "check_kev_status": handle_check_kev_status,
    "get_epss_score": handle_get_epss_score,
    "search_by_product": handle_search_by_product,
    "get_exploits": handle_get_exploits,
    "get_cwe_details": handle_get_cwe_details,
    "batch_search": handle_batch_search,
    # ATT&CK handlers
    "search_techniques": handle_search_techniques,
    "find_similar_techniques": handle_find_similar_techniques,
    "get_technique_details": handle_get_technique_details,
    "get_technique_badges": handle_get_technique_badges,
    "search_threat_actors": handle_search_threat_actors,
    "find_similar_threat_actors": handle_find_similar_threat_actors,
    "get_group_profile": handle_get_group_profile,
    # ATLAS handlers
    "search_atlas_techniques": handle_search_atlas_techniques,
    "find_similar_atlas_techniques": handle_find_similar_atlas_techniques,
    "get_atlas_technique_details": handle_get_atlas_technique_details,
    "search_atlas_case_studies": handle_search_atlas_case_studies,
    "find_similar_atlas_case_studies": handle_find_similar_atlas_case_studies,
    # CAPEC handlers
    "search_capec_patterns": handle_search_capec_patterns,
    "find_similar_capec_patterns": handle_find_similar_capec_patterns,
    "get_capec_pattern_details": handle_get_capec_pattern_details,
    "search_capec_mitigations": handle_search_capec_mitigations,
    "find_similar_capec_mitigations": handle_find_similar_capec_mitigations,
    # CWE handlers
    "search_cwe_weaknesses": handle_search_cwe_weaknesses,
    "find_similar_cwe_weaknesses": handle_find_similar_cwe_weaknesses,
    "get_cwe_weakness_details": handle_get_cwe_weakness_details,
    "search_by_external_mapping": handle_search_by_external_mapping,
    "get_cwe_hierarchy": handle_get_cwe_hierarchy,
    "find_weaknesses_for_capec": handle_find_weaknesses_for_capec,
    # D3FEND handlers
    "search_defenses": handle_search_defenses,
    "find_similar_defenses": handle_find_similar_defenses,
    "get_defense_details": handle_get_defense_details,
    "get_defenses_for_attack": handle_get_defenses_for_attack,
    "get_attack_coverage": handle_get_attack_coverage,
    # System tools
    "get_data_freshness": handle_get_data_freshness,
    # Cloud security handlers
    "search_cloud_services": handle_search_cloud_services,
    "get_cloud_service_security": handle_get_cloud_service_security,
    "compare_cloud_services": handle_compare_cloud_services,
    "get_shared_responsibility": handle_get_shared_responsibility,
}


async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call an MCP tool by name."""
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        raise ValueError(f"Unknown tool: {name}")
    return await handler(arguments)
