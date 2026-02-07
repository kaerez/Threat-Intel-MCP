# Cloud Security Module

**Quality-first cloud service security properties with source provenance and cross-provider comparison.**

## Overview

The Cloud Security module provides comprehensive security property intelligence for AWS, Azure, and GCP services. Every property includes source documentation URL, confidence score, verification method, and verbatim source quotes. The module enables cross-provider security comparison and shared responsibility model analysis.

### Key Features

- **AWS, Azure, GCP Coverage** — Major cloud services with security property database
- **Quality-First Architecture** — Every property has source provenance and confidence scores
- **Service Equivalence** — Cross-provider comparison (S3 ↔ Blob Storage ↔ Cloud Storage)
- **Shared Responsibility** — Provider/customer boundaries by layer (physical → data)
- **Change Tracking** — Automated breaking change detection with audit trail
- **Cross-Framework Mapping** — Links to CWE, CAPEC, ATT&CK techniques
- **Verification Metadata** — Source type, verification method, last verified date
- **Offline-First** — All queries run locally, no external API calls during runtime

### Data Coverage

| Category | Coverage | Description |
|----------|----------|-------------|
| Cloud Providers | 3 | AWS, Azure, GCP |
| Service Categories | 18 | Storage, Compute, Database, Networking, Security, Identity, etc. |
| Property Types | 12 | Encryption, access control, logging, threat detection, compliance |
| Quality Gates | 5 | Source quote, URL, confidence threshold, property value, property name |
| Change Detection | Yes | Breaking changes flagged with significance levels |

### Property Types

1. **Encryption at Rest** — Default algorithms, key management, BYOK/CMEK support
2. **Encryption in Transit** — TLS versions, cipher suites, certificate management
3. **Access Control** — IAM, RBAC, ACLs, public access prevention
4. **Network Isolation** — VPC, private endpoints, network security groups
5. **Audit Logging** — CloudTrail, Azure Monitor, Cloud Audit Logs
6. **Threat Detection** — GuardDuty, Defender, Security Command Center
7. **Compliance Certification** — ISO 27001, SOC 2, PCI DSS, HIPAA, FedRAMP
8. **Shared Responsibility** — Provider vs customer boundaries by layer
9. **Security Defaults** — What's enabled by default vs requires configuration
10. **Data Residency** — Regional data storage, data sovereignty
11. **Backup & Recovery** — Automated backups, point-in-time recovery, geo-replication
12. **Incident Response** — Support channels, SLA commitments, disclosure policies

---

## MCP Tools

The Cloud Security module provides 4 MCP tools for searching, comparing, and analyzing cloud security properties.

### 1. search_cloud_services

**Description:** Search cloud services across AWS, Azure, and GCP by name, provider, or category.

**Performance:** <50ms average latency

**Example Request:**

```json
{
  "name": "search_cloud_services",
  "arguments": {
    "query": "object storage",
    "limit": 10
  }
}
```

**Example Response:**

```json
{
  "data": {
    "services": [
      {
        "service_id": "aws-s3",
        "provider_id": "aws",
        "service_name": "S3",
        "official_name": "Amazon Simple Storage Service",
        "category": "object_storage",
        "description": "Object storage service with high scalability, data availability, security..."
      },
      {
        "service_id": "azure-blob-storage",
        "provider_id": "azure",
        "service_name": "Blob Storage",
        "official_name": "Azure Blob Storage",
        "category": "object_storage",
        "description": "Massively scalable object storage for unstructured data..."
      },
      {
        "service_id": "gcp-cloud-storage",
        "provider_id": "gcp",
        "service_name": "Cloud Storage",
        "official_name": "Google Cloud Storage",
        "category": "object_storage",
        "description": "Unified object storage for developers and enterprises..."
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

**Use Cases:**
- Find equivalent services across cloud providers
- Discover services by category (storage, compute, database)
- Search by service name or description keywords

---

### 2. get_cloud_service_security

**Description:** Get comprehensive security properties for a specific cloud service with source provenance.

**Performance:** <80ms average latency

**Example Request:**

```json
{
  "name": "get_cloud_service_security",
  "arguments": {
    "provider": "aws",
    "service": "s3"
  }
}
```

**Example Response:**

```json
{
  "data": {
    "service_id": "aws-s3",
    "service_name": "S3",
    "official_name": "Amazon Simple Storage Service",
    "provider_id": "aws",
    "category": "object_storage",
    "documentation_url": "https://docs.aws.amazon.com/s3/",
    "security_documentation_url": "https://docs.aws.amazon.com/s3/latest/userguide/security.html",
    "properties_by_type": {
      "encryption_at_rest": [
        {
          "property_id": 1,
          "property_type": "encryption_at_rest",
          "property_name": "Default Encryption Algorithm",
          "summary": "S3 uses AES-256 encryption in GCM mode by default since January 5, 2023",
          "property_value": {
            "algorithm": "AES-256",
            "mode": "GCM",
            "key_length": 256,
            "enabled_by_default": true,
            "effective_date": "2023-01-05"
          },
          "confidence_score": 0.95,
          "source_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html",
          "source_type": "html",
          "source_quote": "Amazon S3 now applies server-side encryption with Amazon S3 managed keys (SSE-S3) as the base level of encryption for every bucket in Amazon S3.",
          "verification_method": "scraper_llm",
          "last_verified": "2026-02-01T10:00:00Z",
          "cis_controls": ["CIS-AWS-3.0/2.1.1"],
          "nist_controls": ["SC-13", "SC-28"],
          "compliance_frameworks": ["PCI-DSS-v4", "HIPAA"]
        }
      ],
      "encryption_in_transit": [
        {
          "property_name": "TLS Version Requirement",
          "property_value": {
            "minimum_tls_version": "1.2",
            "recommended_tls_version": "1.3",
            "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
          },
          "confidence_score": 0.92,
          "source_url": "https://docs.aws.amazon.com/console/securityhub/S3.5/remediation"
        }
      ],
      "access_control": [
        {
          "property_name": "Block Public Access",
          "property_value": {
            "available": true,
            "enabled_by_default": false,
            "account_level": true,
            "bucket_level": true
          },
          "confidence_score": 0.98,
          "source_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        }
      ]
    },
    "total_properties": 12,
    "last_verified": "2026-02-01T10:00:00Z"
  },
  "metadata": {
    "query_time_ms": 72
  }
}
```

**Use Cases:**
- Comprehensive security audit of a cloud service
- Compliance verification with source documentation
- Security posture assessment with confidence scores
- Change tracking for security-critical properties

---

### 3. compare_cloud_services

**Description:** Compare equivalent services across cloud providers with nuanced security differences.

**Performance:** <100ms average latency

**Example Request:**

```json
{
  "name": "compare_cloud_services",
  "arguments": {
    "service_category": "object_storage",
    "providers": ["aws", "azure", "gcp"]
  }
}
```

**Example Response:**

```json
{
  "data": {
    "category": "object_storage",
    "services": {
      "aws-s3": {
        "service_name": "S3",
        "official_name": "Amazon Simple Storage Service",
        "provider": "aws",
        "documentation_url": "https://docs.aws.amazon.com/s3/"
      },
      "azure-blob-storage": {
        "service_name": "Blob Storage",
        "official_name": "Azure Blob Storage",
        "provider": "azure",
        "documentation_url": "https://learn.microsoft.com/en-us/azure/storage/blobs/"
      },
      "gcp-cloud-storage": {
        "service_name": "Cloud Storage",
        "official_name": "Google Cloud Storage",
        "provider": "gcp",
        "documentation_url": "https://cloud.google.com/storage/docs"
      }
    },
    "comparable_dimensions": [
      "encryption_at_rest",
      "encryption_in_transit",
      "access_control",
      "audit_logging",
      "network_isolation"
    ],
    "non_comparable_dimensions": [
      "pricing",
      "performance_slas"
    ],
    "nuances": {
      "aws-s3": "Supports S3 Object Lock (WORM compliance mode) and S3 Glacier for archival",
      "azure-blob-storage": "Immutable storage with time-based retention and legal hold policies",
      "gcp-cloud-storage": "Retention policies with bucket lock, but not true WORM until locked"
    },
    "comparison_notes": "All three provide comparable security features for encryption, access control, and logging. Key difference is in data immutability: AWS S3 Object Lock provides WORM compliance mode, Azure has immutable storage with legal holds, GCP has retention policies that become immutable when locked.",
    "confidence_score": 0.95,
    "last_verified": "2026-02-01T10:00:00Z"
  },
  "metadata": {
    "query_time_ms": 89
  }
}
```

**Use Cases:**
- Cloud provider selection for security requirements
- Multi-cloud strategy security comparison
- Migration planning with security feature parity analysis
- Compliance requirement mapping across providers

---

### 4. get_shared_responsibility

**Description:** Get shared responsibility model breakdown showing provider vs customer security responsibilities by layer.

**Performance:** <60ms average latency

**Example Request:**

```json
{
  "name": "get_shared_responsibility",
  "arguments": {
    "provider": "aws",
    "service": "rds"
  }
}
```

**Example Response:**

```json
{
  "data": {
    "service_id": "aws-rds",
    "service_name": "RDS",
    "provider": "aws",
    "responsibilities_by_layer": {
      "physical": {
        "layer": "physical",
        "owner": "provider",
        "description": "AWS manages physical data center security, including facility access, environmental controls, and hardware disposal",
        "specifics": {},
        "source_url": "https://aws.amazon.com/compliance/shared-responsibility-model/"
      },
      "network": {
        "layer": "network",
        "owner": "provider",
        "description": "AWS manages network infrastructure, DDoS protection, and physical network security",
        "specifics": {},
        "source_url": "https://aws.amazon.com/compliance/shared-responsibility-model/"
      },
      "hypervisor": {
        "layer": "hypervisor",
        "owner": "provider",
        "description": "AWS manages hypervisor patching, isolation, and security",
        "specifics": {},
        "source_url": "https://aws.amazon.com/compliance/shared-responsibility-model/"
      },
      "operating_system": {
        "layer": "operating_system",
        "owner": "provider",
        "description": "AWS manages OS patching and security for RDS instances",
        "specifics": {
          "provider": ["OS patching", "Security updates", "Database engine patches"],
          "customer": []
        },
        "source_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html"
      },
      "application": {
        "layer": "application",
        "owner": "shared",
        "description": "AWS manages database engine security; customer manages database configuration",
        "specifics": {
          "provider": ["Database engine patches", "Automated backups"],
          "customer": ["Database parameter groups", "Option groups", "Security groups"]
        },
        "source_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html"
      },
      "data": {
        "layer": "data",
        "owner": "customer",
        "description": "Customer is responsible for data classification, encryption key management, and access control",
        "specifics": {
          "provider": ["Encryption infrastructure"],
          "customer": ["Data classification", "Encryption key management", "Access policies"]
        },
        "source_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html"
      },
      "identity": {
        "layer": "identity",
        "owner": "customer",
        "description": "Customer manages IAM policies, database users, and authentication",
        "specifics": {},
        "source_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html"
      }
    },
    "total_layers": 7
  },
  "metadata": {
    "query_time_ms": 54
  }
}
```

**Use Cases:**
- Compliance scoping for security assessments
- Security control ownership mapping
- Cloud security architecture design
- Risk assessment with clear accountability boundaries

---

## Data Quality Architecture

### Quality Gates

Every cloud security property must pass these quality gates before insertion:

1. **Source Quote Required** — Verbatim quote from official documentation
2. **Source URL Required** — Direct link to authoritative documentation
3. **Confidence Threshold** — Minimum 0.70 confidence score
4. **Property Value Required** — Structured JSONB with security property details
5. **Property Name Required** — Human-readable property name

### Verification Methods

- **scraper_only** — Extracted by automated scraper from documentation
- **llm_only** — Extracted by LLM from documentation
- **scraper_llm** — Both scraper and LLM verified (highest confidence)
- **human_reviewed** — Manual verification by security engineer
- **all_methods** — Scraper + LLM + human review (production gold standard)

### Change Detection

The module tracks all property changes with:

- **Change Significance** — major (breaking), minor (feature), correction (bug fix), refresh (re-verification)
- **Breaking Change Flag** — Security downgrades automatically flagged
- **Audit Trail** — Full history in `cloud_security_property_changes` table
- **Review Workflow** — Breaking changes require manual review

**Breaking Change Heuristics:**
- Security feature disabled (was enabled → now disabled)
- Encryption downgraded (AES-256 → AES-128)
- Access controls loosened

---

## Service Equivalence

The module maps equivalent services across providers for cross-cloud comparison:

### Service Categories

| Category | AWS Example | Azure Example | GCP Example |
|----------|-------------|---------------|-------------|
| Object Storage | S3 | Blob Storage | Cloud Storage |
| Block Storage | EBS | Managed Disks | Persistent Disk |
| File Storage | EFS | Files | Filestore |
| Compute | EC2 | Virtual Machines | Compute Engine |
| Container | ECS/EKS | AKS | GKE |
| Serverless | Lambda | Functions | Cloud Functions |
| Database (Relational) | RDS | SQL Database | Cloud SQL |
| Database (NoSQL) | DynamoDB | Cosmos DB | Firestore |
| Database (Cache) | ElastiCache | Cache for Redis | Memorystore |
| Networking (VPC) | VPC | Virtual Network | VPC |
| Networking (CDN) | CloudFront | CDN | Cloud CDN |
| Networking (LB) | ELB | Load Balancer | Cloud Load Balancing |
| Identity (IAM) | IAM | Active Directory | IAM |
| Identity (Directory) | Directory Service | Azure AD | Cloud Identity |
| Security (Firewall) | Security Groups | NSG | Firewall Rules |
| Security (WAF) | WAF | Web Application Firewall | Cloud Armor |
| Logging | CloudTrail | Monitor | Cloud Audit Logs |
| Monitoring | CloudWatch | Monitor | Cloud Monitoring |

### Comparison Dimensions

**Comparable:** Encryption at rest, encryption in transit, access control, audit logging, network isolation, threat detection, compliance certifications, backup/recovery

**Non-Comparable:** Pricing models, performance SLAs, geographic availability, feature release schedules

---

## Data Sources

### AWS

- **AWS Security Hub** — Security control definitions for AWS services
- **AWS Config Rules** — Compliance rules and best practices
- **AWS Documentation** — Official service documentation
- **CIS AWS Benchmarks** — Industry standard security baselines

### Azure

- **Azure Policy** — Built-in policy definitions from GitHub
- **Azure Security Baseline** — Service-specific security recommendations
- **Azure Resource Manager** — API schema with security properties
- **Azure Documentation** — Official service documentation

### GCP

- **GCP Organization Policy** — Constraint definitions
- **Security Command Center** — Security recommendations
- **Cloud Asset Inventory** — Resource metadata
- **GCP Documentation** — Official service documentation

All data sources are **public and free** — no API keys required.

---

## Example Workflows

### Workflow 1: Multi-Cloud Security Audit

**Goal:** Compare encryption settings across object storage services

```bash
# Step 1: Find object storage services
search_cloud_services(query="object storage")

# Step 2: Get detailed security properties
get_cloud_service_security(provider="aws", service="s3")
get_cloud_service_security(provider="azure", service="blob-storage")
get_cloud_service_security(provider="gcp", service="cloud-storage")

# Step 3: Compare services side-by-side
compare_cloud_services(service_category="object_storage")
```

**Result:** Complete encryption comparison with nuanced differences (S3 Object Lock vs Azure Immutable Storage vs GCP Bucket Lock)

---

### Workflow 2: Compliance Scoping

**Goal:** Determine customer vs provider responsibilities for PCI DSS compliance

```bash
# Step 1: Get shared responsibility model
get_shared_responsibility(provider="aws", service="rds")

# Step 2: Extract customer-owned layers
# Result: Data, Identity, Application (shared)

# Step 3: Map to PCI DSS requirements
# Customer must implement: Data encryption key management (Req 3.4)
# Customer must implement: Access control policies (Req 7, 8)
# Customer must implement: Database parameter hardening (Req 2.2)
```

**Result:** Clear accountability mapping for compliance audit

---

### Workflow 3: Cloud Migration Planning

**Goal:** Migrate from AWS S3 to Azure Blob Storage with security parity

```bash
# Step 1: Get current AWS S3 security properties
get_cloud_service_security(provider="aws", service="s3")

# Step 2: Get Azure Blob Storage security properties
get_cloud_service_security(provider="azure", service="blob-storage")

# Step 3: Compare services
compare_cloud_services(service_category="object_storage", providers=["aws", "azure"])

# Step 4: Review nuances
# AWS: S3 Object Lock (WORM compliance mode)
# Azure: Immutable storage with legal hold
# Action: Configure Azure immutable storage to match S3 Object Lock requirements
```

**Result:** Migration plan with feature parity checklist

---

## Performance

| Operation | Avg Latency | Notes |
|-----------|-------------|-------|
| search_cloud_services | <50ms | Indexed search |
| get_cloud_service_security | <80ms | Multiple property types |
| compare_cloud_services | <100ms | Cross-provider join |
| get_shared_responsibility | <60ms | Simple layer lookup |

All queries run against local PostgreSQL with GIN indexes on JSONB columns for fast property value queries.

---

## Future Enhancements

### Planned Features

1. **Real-time API Integration** — Live sync from AWS/Azure/GCP APIs (currently sample data)
2. **Security Posture Scoring** — Aggregate security score across services
3. **Drift Detection** — Alert on security property changes
4. **Compliance Mapping** — Pre-built mappings for ISO 27001, SOC 2, PCI DSS, HIPAA
5. **CVE Impact Analysis** — Link CVEs to affected cloud service properties
6. **Cost-Security Tradeoffs** — Analyze security vs cost implications

### Experimental Features

1. **AI Security Recommendations** — LLM-powered security improvement suggestions
2. **Multi-Cloud Security Posture** — Unified security dashboard across providers
3. **Automated Remediation** — Generate Terraform/CloudFormation for security fixes

---

## Contributing

To add a new cloud service:

1. Add service to `sync_cloud_security.py` with sample data
2. Define property parser in `cloud_security_parser.py`
3. Ensure all quality gates pass (source quote, URL, confidence >0.70)
4. Add service to equivalence mapping if applicable
5. Document shared responsibility model layers

---

## References

- [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [Azure Shared Responsibility](https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility)
- [GCP Shared Responsibility](https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
