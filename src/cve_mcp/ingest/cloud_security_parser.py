"""Parsers for cloud security properties with quality-first architecture."""

import hashlib
from datetime import datetime
from typing import Any


# ============================================================================
# AWS Parsers
# ============================================================================


def parse_aws_security_hub_control(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Parse AWS Security Hub control definition to security property format.

    Expected input from AWS Security Hub ListSecurityControlDefinitions API.

    Args:
        raw: Raw control definition from Security Hub API

    Returns:
        Parsed property dict or None if invalid
    """
    # Required fields validation
    control_id = raw.get("SecurityControlId")
    if not control_id:
        return None

    title = raw.get("Title") or ""
    description = raw.get("Description") or ""  # Guard against None

    if not title or not description:
        return None

    # Extract property type from control ID (e.g., "S3.5" -> encryption_in_transit)
    property_type = _infer_property_type_from_description(description)

    # Build property value from control details
    property_value = {
        "control_id": control_id,
        "title": title,
        "severity": raw.get("SeverityRating", "MEDIUM"),
        "control_status": raw.get("ControlStatus", "ENABLED"),
        "parameters": raw.get("Parameters") or {},  # Guard against None
        "remediation_url": raw.get("RemediationUrl"),
    }

    # Extract compliance mappings
    cis_controls = []
    nist_controls = []
    compliance_frameworks = []

    standards = raw.get("SecurityControlStandardsDefinitions") or []  # Guard
    for std in standards:
        standard_arn = std.get("StandardsArn") or ""
        control_id_in_std = std.get("ControlId")

        if "cis-aws-foundations-benchmark" in standard_arn:
            if control_id_in_std:
                cis_controls.append(f"CIS-AWS-{control_id_in_std}")
        elif "nist-800-53" in standard_arn:
            if control_id_in_std:
                nist_controls.append(control_id_in_std)

        # Extract framework from ARN
        if "pci-dss" in standard_arn:
            compliance_frameworks.append("PCI-DSS")
        elif "aws-foundational-security-best-practices" in standard_arn:
            compliance_frameworks.append("AWS-FSBP")

    # Calculate confidence score
    confidence = _calculate_confidence(
        has_source_quote=True,  # AWS API is structured
        source_is_authoritative=True,  # AWS Security Hub is authoritative
        verification_method="scraper_only",
    )

    return {
        "property_type": property_type,
        "property_name": title,
        "property_value": property_value,
        "summary": f"{title}: {description[:200]}",
        "source_url": f"https://docs.aws.amazon.com/securityhub/latest/userguide/{control_id.lower().replace('.', '-')}-controls.html",
        "source_type": "api",
        "source_section": f"Security Hub Control {control_id}",
        "source_quote": description,
        "confidence_score": confidence,
        "verification_method": "scraper_only",
        "verification_metadata": {
            "source": "AWS Security Hub API",
            "api_version": "2020-01-01",
            "control_id": control_id,
        },
        "cis_controls": cis_controls if cis_controls else None,
        "nist_controls": nist_controls if nist_controls else None,
        "compliance_frameworks": compliance_frameworks if compliance_frameworks else None,
        "extracted_date": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
    }


def parse_aws_config_rule(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Parse AWS Config managed rule to security property format.

    Args:
        raw: Raw config rule from AWS Config API

    Returns:
        Parsed property dict or None if invalid
    """
    rule_name = raw.get("ConfigRuleName")
    if not rule_name:
        return None

    description = raw.get("Description") or ""
    if not description:
        return None

    # Extract property type
    property_type = _infer_property_type_from_rule_name(rule_name)

    property_value = {
        "rule_name": rule_name,
        "rule_id": raw.get("ConfigRuleId"),
        "rule_arn": raw.get("ConfigRuleArn"),
        "source_identifier": raw.get("Source", {}).get("SourceIdentifier"),
        "input_parameters": raw.get("InputParameters") or {},
        "compliance_resource_types": raw.get("Scope", {}).get("ComplianceResourceTypes") or [],
    }

    confidence = _calculate_confidence(
        has_source_quote=True,
        source_is_authoritative=True,
        verification_method="scraper_only",
    )

    return {
        "property_type": property_type,
        "property_name": rule_name.replace("-", " ").title(),
        "property_value": property_value,
        "summary": description[:300],
        "source_url": "https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html",
        "source_type": "api",
        "source_section": f"Config Rule {rule_name}",
        "source_quote": description,
        "confidence_score": confidence,
        "verification_method": "scraper_only",
        "verification_metadata": {
            "source": "AWS Config API",
            "rule_name": rule_name,
        },
        "extracted_date": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
    }


# ============================================================================
# Azure Parsers
# ============================================================================



def parse_aws_s3_best_practice(
    raw: dict[str, Any], service_name: str = "s3"
) -> dict[str, Any] | None:
    """
    Parse AWS S3 best practice property from direct API checks.
    
    This parser handles security properties derived from:
    - Direct S3 API calls (GetBucketEncryption, GetPublicAccessBlock, etc.)
    - IAM Access Analyzer findings
    - AWS Well-Architected Framework recommendations
    
    Args:
        raw: Best practice property definition
        service_name: AWS service name (default: s3)
        
    Returns:
        Parsed property dict or None if invalid
    """
    property_id = raw.get("property_id")
    property_name = raw.get("property_name")
    description = raw.get("description")
    
    if not property_id or not property_name or not description:
        return None
    
    # Map severity to standardized levels
    severity_map = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }
    severity = severity_map.get(raw.get("severity", "medium").lower(), "MEDIUM")
    
    # Map category to property type
    category_to_type = {
        "encryption": "encryption_at_rest",
        "access_control": "access_control",
        "data_protection": "data_protection", 
        "monitoring": "monitoring_logging",
        "cost_optimization": "cost_optimization",
        "resilience": "resilience",
    }
    property_type = category_to_type.get(
        raw.get("category", "access_control"), "access_control"
    )
    
    property_value = {
        "property_id": property_id,
        "severity": severity,
        "category": raw.get("category", "access_control"),
        "compliance_frameworks": raw.get("compliance_frameworks", []),
        "remediation_url": raw.get("remediation_url"),
        "source": "aws_best_practices",
    }
    
    confidence = _calculate_confidence(
        has_source_quote=True,
        source_is_authoritative=True,
        verification_method="scraper_only",  # Direct API = authoritative source
    )
    
    return {
        "property_type": property_type,
        "property_name": property_name,
        "property_value": property_value,
        "summary": description[:300],
        "source_url": raw.get("remediation_url", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"),
        "source_type": "api",
        "source_section": f"S3 Best Practice: {property_id}",
        "source_quote": description,
        "confidence_score": confidence,
        "verification_method": "scraper_only",  # Direct API source
        "verification_metadata": {
            "source": "AWS API + Well-Architected Framework",
            "property_id": property_id,
            "service": service_name,
        },
        "extracted_date": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
    }


def parse_azure_policy_definition(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Parse Azure Policy built-in definition to security property format.

    Expected input from Azure Policy GitHub repository JSON files.

    Args:
        raw: Raw policy definition JSON

    Returns:
        Parsed property dict or None if invalid
    """
    properties = raw.get("properties") or {}

    display_name = properties.get("displayName") or ""
    description = properties.get("description") or ""

    if not display_name:
        return None

    # Extract property type from policy metadata
    metadata = properties.get("metadata") or {}
    category = metadata.get("category", "")

    property_type = _infer_property_type_from_category(category)

    # Extract policy rule
    policy_rule = properties.get("policyRule") or {}

    property_value = {
        "policy_name": properties.get("name"),
        "display_name": display_name,
        "policy_type": properties.get("policyType", "BuiltIn"),
        "mode": properties.get("mode", "All"),
        "category": category,
        "policy_rule": {
            "if": policy_rule.get("if"),
            "then": policy_rule.get("then"),
        },
        "parameters": properties.get("parameters") or {},
    }

    # Extract compliance frameworks from metadata
    compliance_frameworks = []
    if metadata.get("ASC") == "true":
        compliance_frameworks.append("Azure-Security-Benchmark")
    if metadata.get("CIS") == "true":
        compliance_frameworks.append("CIS-Azure")

    confidence = _calculate_confidence(
        has_source_quote=True,
        source_is_authoritative=True,
        verification_method="scraper_only",
    )

    policy_id = raw.get("id", "unknown")
    policy_name_slug = properties.get("name", "unknown")

    return {
        "property_type": property_type,
        "property_name": display_name,
        "property_value": property_value,
        "summary": description[:300] if description else display_name,
        "source_url": f"https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Storage/{policy_name_slug}.json",
        "source_type": "json",
        "source_section": f"Azure Policy {category}",
        "source_quote": description or display_name,
        "confidence_score": confidence,
        "verification_method": "scraper_only",
        "verification_metadata": {
            "source": "Azure Policy GitHub",
            "policy_id": policy_id,
            "category": category,
        },
        "compliance_frameworks": compliance_frameworks if compliance_frameworks else None,
        "extracted_date": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
    }


def parse_azure_arm_property(
    service_id: str,
    property_path: str,
    property_schema: dict[str, Any],
    property_name: str,
) -> dict[str, Any] | None:
    """
    Parse Azure ARM API schema property to security property format.

    Args:
        service_id: Cloud service ID (e.g., "azure-blob-storage")
        property_path: Property path in ARM template (e.g., "properties.encryption")
        property_schema: Schema definition for this property
        property_name: Human-readable property name

    Returns:
        Parsed property dict or None if invalid
    """
    description = property_schema.get("description") or ""
    property_type_val = property_schema.get("type", "")

    if not description and not property_type_val:
        return None

    # Infer security property type from path
    property_type = _infer_property_type_from_path(property_path)

    property_value = {
        "property_path": property_path,
        "schema_type": property_type_val,
        "required": property_schema.get("required", False),
        "default": property_schema.get("default"),
        "enum": property_schema.get("enum") or [],
        "allowed_values": property_schema.get("allowedValues") or [],
    }

    confidence = _calculate_confidence(
        has_source_quote=True,
        source_is_authoritative=True,
        verification_method="scraper_only",
    )

    return {
        "property_type": property_type,
        "property_name": property_name,
        "property_value": property_value,
        "summary": description[:300] if description else property_name,
        "source_url": "https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts",
        "source_type": "json",
        "source_section": f"ARM Property {property_path}",
        "source_quote": description or f"Property: {property_path}",
        "confidence_score": confidence,
        "verification_method": "scraper_only",
        "verification_metadata": {
            "source": "Azure ARM API Schema",
            "property_path": property_path,
        },
        "extracted_date": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
    }


# ============================================================================
# GCP Parsers
# ============================================================================


def parse_gcp_org_policy_constraint(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Parse GCP Organization Policy constraint to security property format.

    Args:
        raw: Raw constraint definition from GCP Org Policy

    Returns:
        Parsed property dict or None if invalid
    """
    constraint_name = raw.get("name") or ""
    display_name = raw.get("displayName") or ""
    description = raw.get("description") or ""

    if not constraint_name or not display_name:
        return None

    # Extract property type from constraint name
    # Example: "constraints/storage.publicAccessPrevention"
    property_type = _infer_property_type_from_gcp_constraint(constraint_name)

    property_value = {
        "constraint_name": constraint_name,
        "display_name": display_name,
        "constraint_type": raw.get("constraintType"),
        "list_constraint": raw.get("listConstraint") or {},
        "boolean_constraint": raw.get("booleanConstraint") or {},
        "enforcement": raw.get("enforcement", "ENFORCEMENT_ENFORCED"),
    }

    confidence = _calculate_confidence(
        has_source_quote=True,
        source_is_authoritative=True,
        verification_method="scraper_only",
    )

    # Use documentation_url from constraint if available, otherwise use default
    source_url = raw.get("documentation_url") or "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints"

    return {
        "property_type": property_type,
        "property_name": display_name,
        "property_value": property_value,
        "summary": description[:300] if description else display_name,
        "source_url": source_url,
        "source_type": "json",
        "source_section": f"Organization Policy {constraint_name}",
        "source_quote": description or display_name,
        "confidence_score": confidence,
        "verification_method": "scraper_only",
        "verification_metadata": {
            "source": "GCP Organization Policy",
            "constraint_name": constraint_name,
        },
        "extracted_date": datetime.utcnow(),
        "last_verified": datetime.utcnow(),
    }


# ============================================================================
# Service Parsers
# ============================================================================


def parse_cloud_service(
    provider: str,
    service_name: str,
    official_name: str,
    service_category: str,
    description: str | None = None,
    documentation_url: str | None = None,
) -> dict[str, Any]:
    """
    Create a cloud service entry.

    Args:
        provider: Provider ID ("aws", "azure", "gcp")
        service_name: Short service name ("S3", "Blob Storage")
        official_name: Full official name
        service_category: Service category enum value
        description: Optional description
        documentation_url: Optional documentation URL

    Returns:
        Parsed service dict
    """
    service_id = f"{provider}-{service_name.lower().replace(' ', '-')}"

    now = datetime.utcnow()

    return {
        "service_id": service_id,
        "provider_id": provider,
        "service_name": service_name,
        "official_name": official_name,
        "description": description,
        "service_category": service_category,
        "documentation_url": documentation_url,
        "last_verified": now,
        "created": now,
        "modified": now,
        "deprecated": False,
    }


# ============================================================================
# Helper Functions
# ============================================================================


def _infer_property_type_from_description(description: str) -> str:
    """Infer property type from control description text."""
    desc_lower = description.lower()

    if any(kw in desc_lower for kw in ["encrypt", "kms", "sse-", "tls", "ssl"]):
        if "transit" in desc_lower or "tls" in desc_lower or "ssl" in desc_lower:
            return "encryption_in_transit"
        return "encryption_at_rest"
    elif any(kw in desc_lower for kw in ["public", "access", "iam", "policy"]):
        return "access_control"
    elif any(kw in desc_lower for kw in ["vpc", "endpoint", "network", "firewall"]):
        return "network_isolation"
    elif any(kw in desc_lower for kw in ["log", "cloudtrail", "audit"]):
        return "audit_logging"
    elif any(kw in desc_lower for kw in ["compliance", "certification"]):
        return "compliance_certification"
    elif any(kw in desc_lower for kw in ["default", "enable"]):
        return "security_default"
    else:
        return "access_control"  # Default fallback


def _infer_property_type_from_rule_name(rule_name: str) -> str:
    """Infer property type from AWS Config rule name."""
    rule_lower = rule_name.lower()

    if "encryption" in rule_lower or "kms" in rule_lower:
        if "transit" in rule_lower or "ssl" in rule_lower:
            return "encryption_in_transit"
        return "encryption_at_rest"
    elif "public" in rule_lower or "acl" in rule_lower:
        return "access_control"
    elif "vpc" in rule_lower or "endpoint" in rule_lower:
        return "network_isolation"
    elif "logging" in rule_lower or "log" in rule_lower:
        return "audit_logging"
    elif "versioning" in rule_lower or "replication" in rule_lower:
        return "backup_recovery"
    else:
        return "security_default"


def _infer_property_type_from_category(category: str) -> str:
    """Infer property type from Azure Policy category."""
    category_lower = category.lower()

    if "encrypt" in category_lower:
        return "encryption_at_rest"
    elif "network" in category_lower:
        return "network_isolation"
    elif "identity" in category_lower or "auth" in category_lower:
        return "access_control"
    elif "logging" in category_lower or "monitoring" in category_lower:
        return "audit_logging"
    elif "compliance" in category_lower:
        return "compliance_certification"
    else:
        return "security_default"


def _infer_property_type_from_path(property_path: str) -> str:
    """Infer property type from ARM property path."""
    path_lower = property_path.lower()

    if "encryption" in path_lower:
        if "transit" in path_lower:
            return "encryption_in_transit"
        return "encryption_at_rest"
    elif "network" in path_lower or "firewall" in path_lower:
        return "network_isolation"
    elif "access" in path_lower or "auth" in path_lower:
        return "access_control"
    elif "minimumtlsversion" in path_lower:
        return "encryption_in_transit"
    else:
        return "security_default"


def _infer_property_type_from_gcp_constraint(constraint_name: str) -> str:
    """Infer property type from GCP constraint name."""
    constraint_lower = constraint_name.lower()

    if "encryption" in constraint_lower or "cmek" in constraint_lower:
        return "encryption_at_rest"
    elif "publicaccess" in constraint_lower or "iam" in constraint_lower:
        return "access_control"
    elif "vpc" in constraint_lower or "network" in constraint_lower:
        return "network_isolation"
    elif "audit" in constraint_lower or "logging" in constraint_lower:
        return "audit_logging"
    elif "tls" in constraint_lower:
        return "encryption_in_transit"
    else:
        return "security_default"


def _calculate_confidence(
    has_source_quote: bool,
    source_is_authoritative: bool,
    verification_method: str,
    llm_confidence: float | None = None,
) -> float:
    """
    Calculate confidence score for a security property.

    Args:
        has_source_quote: Whether we have a verbatim quote from source
        source_is_authoritative: Whether source is official (API, official docs)
        verification_method: How this was verified
        llm_confidence: Optional LLM confidence if LLM was used

    Returns:
        Confidence score between 0.0 and 1.0
    """
    base_confidence = 0.5

    # Source quality
    if source_is_authoritative:
        base_confidence += 0.2
    if has_source_quote:
        base_confidence += 0.1

    # Verification method
    if verification_method == "all_methods":
        base_confidence += 0.2
    elif verification_method == "scraper_llm":
        base_confidence += 0.15
    elif verification_method == "human_reviewed":
        base_confidence += 0.15
    elif verification_method == "scraper_only" and source_is_authoritative:
        base_confidence += 0.1

    # LLM confidence (if applicable)
    if llm_confidence is not None:
        # Average with LLM's own confidence
        base_confidence = (base_confidence + llm_confidence) / 2

    # Clamp to [0.0, 1.0]
    return min(max(base_confidence, 0.0), 1.0)


def generate_property_hash(service_id: str, property_type: str, property_name: str) -> str:
    """Generate a stable hash for a property (for deduplication)."""
    content = f"{service_id}:{property_type}:{property_name}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]
