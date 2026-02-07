# Cloud Security Production Data Sources - Implementation Handover

**Document Version:** 1.0
**Date:** 2026-02-07
**Status:** Ready for Implementation
**Author:** Platform Engineering Team
**Reviewers:** Security Engineering, DevOps

---

## Executive Summary

The Cloud Security module is currently running with **sample data** for AWS S3, Azure Blob Storage, and GCP Cloud Storage. This handover document provides a complete implementation plan to transition to **production data sources** with real-time API integration for AWS Security Hub, Azure Policy, and GCP Organization Policy.

**Current State:** ✅ Architecture complete, sample data working
**Target State:** 🎯 Production APIs integrated, automated sync, quality gates enforced
**Estimated Effort:** 40-60 hours (1-2 sprint cycles)
**Risk Level:** Medium (requires cloud provider credentials and API access)

---

## Table of Contents

1. [Current State Assessment](#current-state-assessment)
2. [Production Architecture](#production-architecture)
3. [Implementation Roadmap](#implementation-roadmap)
4. [AWS Security Hub Integration](#aws-security-hub-integration)
5. [Azure Policy Integration](#azure-policy-integration)
6. [GCP Organization Policy Integration](#gcp-organization-policy-integration)
7. [Quality Gates & Validation](#quality-gates--validation)
8. [Monitoring & Alerting](#monitoring--alerting)
9. [Rollback Procedures](#rollback-procedures)
10. [Security & Compliance](#security--compliance)
11. [Cost Analysis](#cost-analysis)
12. [Testing Plan](#testing-plan)

---

## Current State Assessment

### What's Working (Sample Data)

✅ **Database Schema:** 9 tables created via migration 011
✅ **Sync Tasks:** 4 Celery tasks scheduled (AWS, Azure, GCP, equivalences)
✅ **Quality Gates:** 5 gates enforced (source quote, URL, confidence, value, name)
✅ **MCP Tools:** 4 tools exposed and working
✅ **Agent Integration:** Ansvar agents can query cloud security data
✅ **Documentation:** Comprehensive module docs complete

### What's Using Sample Data

⚠️ **AWS S3 Sync:** Uses hardcoded sample controls (3 controls)
⚠️ **Azure Blob Sync:** Uses hardcoded sample policies (2 policies)
⚠️ **GCP Storage Sync:** Uses hardcoded sample constraints (3 constraints)
⚠️ **Service Coverage:** Only 3 services (S3, Blob, Cloud Storage) - not comprehensive

**Code Locations:**
```python
# src/cve_mcp/tasks/sync_cloud_security.py
async def _get_aws_s3_sample_controls() -> list[dict[str, Any]]:
    """Get sample AWS Security Hub controls for S3."""
    return [
        # Hardcoded sample data (lines 220-281)
    ]
```

### Production Gaps

| Gap | Impact | Priority |
|-----|--------|----------|
| No AWS API credentials | Can't fetch real Security Hub controls | 🔴 Critical |
| No Azure API integration | Can't fetch Azure Policy definitions | 🔴 Critical |
| No GCP API integration | Can't fetch GCP Organization Policies | 🔴 Critical |
| Limited service coverage | Only 3 services vs 50+ available | 🟡 High |
| No change detection | Can't detect breaking changes in docs | 🟡 High |
| No drift alerting | Silent failures if APIs change | 🟡 High |

---

## Production Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Cloud Provider APIs                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ AWS Security Hub │  │ Azure Policy API │  │ GCP Org Pol  │  │
│  │ ListControls API │  │ GitHub/Azure API │  │ Constraints  │  │
│  └────────┬─────────┘  └────────┬─────────┘  └──────┬───────┘  │
└───────────┼─────────────────────┼────────────────────┼──────────┘
            │                     │                    │
            │ HTTPS + IAM         │ HTTPS + Token      │ HTTPS + SA
            │                     │                    │
            ▼                     ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Celery Workers (cve-mcp-worker)                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ sync_aws_s3_task                                          │   │
│  │  1. Call AWS API (boto3)                                 │   │
│  │  2. Parse JSON response                                  │   │
│  │  3. Apply quality gates                                  │   │
│  │  4. Detect changes                                       │   │
│  │  5. Insert with confidence scores                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ sync_azure_blob_task                                      │   │
│  │  1. Fetch from GitHub OR Azure Resource Manager API     │   │
│  │  2. Parse JSON/YAML                                      │   │
│  │  3. Apply quality gates                                  │   │
│  │  4. Detect changes                                       │   │
│  │  5. Insert with confidence scores                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ sync_gcp_storage_task                                     │   │
│  │  1. Call GCP API (google-cloud-orgpolicy)               │   │
│  │  2. Parse JSON response                                  │   │
│  │  3. Apply quality gates                                  │   │
│  │  4. Detect changes                                       │   │
│  │  5. Insert with confidence scores                        │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  PostgreSQL (cve-mcp-postgres)                                   │
│  - cloud_security_properties (with source URLs & confidence)     │
│  - cloud_security_property_changes (audit trail)                │
└─────────────────────────────────────────────────────────────────┘
```

### Credential Management

**AWS Credentials:**
- IAM Role with `securityhub:ListSecurityControlDefinitions` permission
- Environment: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
- Alternative: EC2 Instance Profile or ECS Task Role

**Azure Credentials:**
- Service Principal with `Reader` role on subscription
- Environment: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- Alternative: Managed Identity

**GCP Credentials:**
- Service Account with `orgpolicy.constraints.list` permission
- Environment: `GOOGLE_APPLICATION_CREDENTIALS` (path to JSON key)
- Alternative: Workload Identity

---

## Implementation Roadmap

### Phase 1: AWS Security Hub Integration (Week 1-2)

**Effort:** 16-20 hours
**Risk:** Medium (AWS API changes require updates)
**Dependencies:** AWS credentials with Security Hub access

**Tasks:**
1. ✅ Add `boto3` to `requirements.txt`
2. ✅ Create AWS credential configuration in `.env`
3. ✅ Implement `fetch_aws_security_hub_controls()` function
4. ✅ Update parser to handle real API responses
5. ✅ Expand service coverage (S3, RDS, EC2, Lambda, etc.)
6. ✅ Add unit tests for AWS integration
7. ✅ Integration test with real AWS account
8. ✅ Update sync task to use real API

**Deliverables:**
- `src/cve_mcp/ingest/aws_api_client.py` (new)
- Updated `sync_aws_s3_task()` in `sync_cloud_security.py`
- Test suite for AWS integration
- Documentation update

---

### Phase 2: Azure Policy Integration (Week 3)

**Effort:** 12-16 hours
**Risk:** Low (GitHub source is stable, Azure API is alternative)
**Dependencies:** Azure credentials OR GitHub access token

**Tasks:**
1. ✅ Implement GitHub fetcher for Azure Policy repo
2. ✅ Add `azure-mgmt-resource` to `requirements.txt` (alternative)
3. ✅ Create Azure credential configuration
4. ✅ Implement `fetch_azure_policy_definitions()` function
5. ✅ Expand service coverage (Blob, SQL, VMs, etc.)
6. ✅ Add unit tests for Azure integration
7. ✅ Integration test with real Azure subscription
8. ✅ Update sync task to use real API/GitHub

**Deliverables:**
- `src/cve_mcp/ingest/azure_api_client.py` (new)
- Updated `sync_azure_blob_task()` in `sync_cloud_security.py`
- Test suite for Azure integration
- Documentation update

---

### Phase 3: GCP Organization Policy Integration (Week 4)

**Effort:** 12-16 hours
**Risk:** Medium (GCP API requires organization-level access)
**Dependencies:** GCP service account with org policy permissions

**Tasks:**
1. ✅ Add `google-cloud-orgpolicy` to `requirements.txt`
2. ✅ Create GCP credential configuration
3. ✅ Implement `fetch_gcp_org_policy_constraints()` function
4. ✅ Expand service coverage (Cloud Storage, Compute, Cloud SQL, etc.)
5. ✅ Add unit tests for GCP integration
6. ✅ Integration test with real GCP organization
7. ✅ Update sync task to use real API

**Deliverables:**
- `src/cve_mcp/ingest/gcp_api_client.py` (new)
- Updated `sync_gcp_storage_task()` in `sync_cloud_security.py`
- Test suite for GCP integration
- Documentation update

---

### Phase 4: Service Expansion (Week 5-6)

**Effort:** 12-20 hours
**Risk:** Low (incremental additions)
**Dependencies:** Phases 1-3 complete

**AWS Services to Add:**
- RDS (database security)
- EC2 (compute security)
- Lambda (serverless security)
- EKS (container security)
- DynamoDB (NoSQL security)

**Azure Services to Add:**
- Azure SQL Database
- Virtual Machines
- Azure Kubernetes Service
- Cosmos DB
- Azure Functions

**GCP Services to Add:**
- Cloud SQL
- Compute Engine
- Google Kubernetes Engine
- Firestore
- Cloud Functions

**Deliverables:**
- 15+ additional services with full security properties
- Service equivalence mappings updated
- Shared responsibility models documented

---

## AWS Security Hub Integration

### Prerequisites

**AWS Account Setup:**
1. Enable AWS Security Hub in target region(s)
2. Create IAM user or role with permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "securityhub:ListSecurityControlDefinitions",
           "securityhub:BatchGetSecurityControls",
           "config:DescribeConfigRules",
           "config:DescribeConformancePacks"
         ],
         "Resource": "*"
       }
     ]
   }
   ```
3. Generate access key or use IAM role assumption

**Environment Variables:**
```bash
# .env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
AWS_SECURITY_HUB_ENABLED=true
```

### Implementation

**File:** `src/cve_mcp/ingest/aws_api_client.py`

```python
"""AWS API client for Security Hub and Config."""

import boto3
from typing import Any, Dict, List
import structlog

logger = structlog.get_logger(__name__)


class AWSSecurityHubClient:
    """Client for AWS Security Hub API."""

    def __init__(
        self,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        region: str = "us-east-1"
    ):
        """Initialize AWS client with credentials."""
        if access_key_id and secret_access_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=region
            )
        else:
            # Use default credential chain (EC2 instance profile, etc.)
            self.session = boto3.Session(region_name=region)

        self.securityhub = self.session.client('securityhub')
        self.config = self.session.client('config')

    def list_security_controls(
        self,
        service_name: str | None = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Fetch Security Hub control definitions.

        Args:
            service_name: Filter by AWS service (e.g., "s3", "rds")
            max_results: Maximum controls to fetch

        Returns:
            List of security control definitions
        """
        try:
            controls = []
            paginator = self.securityhub.get_paginator('list_security_control_definitions')

            for page in paginator.paginate(
                PaginationConfig={'MaxItems': max_results}
            ):
                for control in page.get('SecurityControlDefinitions', []):
                    # Filter by service if specified
                    if service_name:
                        control_id = control.get('SecurityControlId', '')
                        # S3.1, S3.5, etc. start with service prefix
                        if not control_id.upper().startswith(service_name.upper()):
                            continue

                    controls.append(control)

            logger.info(
                "fetched_security_hub_controls",
                service=service_name,
                count=len(controls)
            )
            return controls

        except Exception as e:
            logger.error(
                "failed_to_fetch_security_hub_controls",
                service=service_name,
                error=str(e),
                exc_info=True
            )
            raise

    def get_config_rules(self, prefix: str | None = None) -> List[Dict[str, Any]]:
        """
        Fetch AWS Config rules.

        Args:
            prefix: Filter rules by prefix (e.g., "s3-")

        Returns:
            List of Config rules
        """
        try:
            rules = []
            paginator = self.config.get_paginator('describe_config_rules')

            for page in paginator.paginate():
                for rule in page.get('ConfigRules', []):
                    if prefix:
                        rule_name = rule.get('ConfigRuleName', '')
                        if not rule_name.startswith(prefix):
                            continue

                    rules.append(rule)

            logger.info(
                "fetched_config_rules",
                prefix=prefix,
                count=len(rules)
            )
            return rules

        except Exception as e:
            logger.error(
                "failed_to_fetch_config_rules",
                prefix=prefix,
                error=str(e),
                exc_info=True
            )
            raise


# Factory function for use in sync tasks
def get_aws_client(
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
    region: str = "us-east-1"
) -> AWSSecurityHubClient:
    """Get AWS Security Hub client instance."""
    return AWSSecurityHubClient(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        region=region
    )
```

**Update:** `src/cve_mcp/tasks/sync_cloud_security.py`

```python
# Replace _get_aws_s3_sample_controls() with real API call

from cve_mcp.ingest.aws_api_client import get_aws_client
from cve_mcp.config import get_settings

async def sync_aws_s3_security(
    session: AsyncSession,
    generate_embeddings: bool = False,
    verbose: bool = False,
) -> dict[str, int]:
    """
    Sync AWS S3 security properties from Security Hub.
    """
    start_time = datetime.utcnow()
    stats: dict[str, int] = {
        "services_synced": 0,
        "properties_synced": 0,
        "properties_updated": 0,
        "properties_failed_quality": 0,
        "changes_detected": 0,
    }

    try:
        logger.info("sync_aws_s3_security.started")

        # Get AWS credentials from settings
        settings = get_settings()
        aws_client = get_aws_client(
            access_key_id=settings.aws_access_key_id,
            secret_access_key=settings.aws_secret_access_key,
            region=settings.aws_region
        )

        # Fetch real Security Hub controls for S3
        controls = aws_client.list_security_controls(service_name="s3")

        logger.info(
            "fetched_aws_controls",
            service="s3",
            count=len(controls)
        )

        # Ensure provider and service exist
        await _ensure_provider_exists(session, "aws")
        s3_service = parse_cloud_service(
            provider="aws",
            service_name="S3",
            official_name="Amazon Simple Storage Service",
            service_category="object_storage",
            description="Object storage service with high scalability, data availability, security, and performance",
            documentation_url="https://docs.aws.amazon.com/s3/",
        )
        await _upsert_service(session, s3_service)
        stats["services_synced"] += 1

        # Process each control
        for control_data in controls:
            parsed = parse_aws_security_hub_control(control_data)
            if not parsed:
                continue

            # Apply quality gates
            passes, failures = passes_quality_gates(parsed)
            if not passes:
                logger.warning(
                    "property_failed_quality_gates",
                    service="aws-s3",
                    property=parsed.get("property_name"),
                    failures=failures,
                )
                stats["properties_failed_quality"] += 1
                continue

            # Add service_id
            parsed["service_id"] = "aws-s3"

            # Check for changes and upsert
            change_detected = await _upsert_property_with_change_detection(
                session, parsed, verbose=verbose
            )

            if change_detected:
                stats["changes_detected"] += 1
                stats["properties_updated"] += 1
            else:
                stats["properties_synced"] += 1

        await session.commit()

        # Update sync metadata
        await _update_sync_metadata(
            session,
            source="cloud_security_aws_s3",
            status="success",
            records=stats["properties_synced"] + stats["properties_updated"],
            duration=(datetime.utcnow() - start_time).total_seconds(),
        )

        logger.info("sync_aws_s3_security.completed", stats=stats)
        return stats

    except Exception as e:
        logger.error("sync_aws_s3_security.failed", error=str(e), exc_info=True)
        await session.rollback()

        await _update_sync_metadata(
            session,
            source="cloud_security_aws_s3",
            status="failed",
            error_message=str(e),
        )

        raise
```

**Configuration:** Add to `src/cve_mcp/config.py`

```python
class Settings(BaseSettings):
    # ... existing settings ...

    # AWS Settings
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str = "us-east-1"
    aws_security_hub_enabled: bool = False

    class Config:
        env_file = ".env"
```

### Testing

**Unit Test:** `tests/test_aws_api_client.py`

```python
"""Tests for AWS API client."""

import pytest
from unittest.mock import Mock, patch
from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session."""
    with patch('cve_mcp.ingest.aws_api_client.boto3.Session') as mock:
        yield mock


def test_list_security_controls_s3_filter(mock_boto3_session):
    """Test fetching S3 security controls."""
    # Mock Security Hub client
    mock_client = Mock()
    mock_paginator = Mock()
    mock_paginator.paginate.return_value = [
        {
            'SecurityControlDefinitions': [
                {
                    'SecurityControlId': 'S3.1',
                    'Title': 'S3 Block Public Access',
                    'Description': '...',
                },
                {
                    'SecurityControlId': 'S3.5',
                    'Title': 'S3 buckets should require SSL',
                    'Description': '...',
                },
                {
                    'SecurityControlId': 'EC2.1',  # Should be filtered out
                    'Title': 'EC2 instances should not have public IP',
                    'Description': '...',
                },
            ]
        }
    ]
    mock_client.get_paginator.return_value = mock_paginator

    mock_session = Mock()
    mock_session.client.return_value = mock_client
    mock_boto3_session.return_value = mock_session

    # Test
    client = AWSSecurityHubClient()
    controls = client.list_security_controls(service_name="s3")

    # Assertions
    assert len(controls) == 2
    assert all(c['SecurityControlId'].startswith('S3.') for c in controls)
    assert controls[0]['SecurityControlId'] == 'S3.1'
    assert controls[1]['SecurityControlId'] == 'S3.5'


def test_list_security_controls_no_filter(mock_boto3_session):
    """Test fetching all security controls."""
    mock_client = Mock()
    mock_paginator = Mock()
    mock_paginator.paginate.return_value = [
        {
            'SecurityControlDefinitions': [
                {'SecurityControlId': 'S3.1', 'Title': '...'},
                {'SecurityControlId': 'EC2.1', 'Title': '...'},
                {'SecurityControlId': 'RDS.1', 'Title': '...'},
            ]
        }
    ]
    mock_client.get_paginator.return_value = mock_paginator

    mock_session = Mock()
    mock_session.client.return_value = mock_client
    mock_boto3_session.return_value = mock_session

    client = AWSSecurityHubClient()
    controls = client.list_security_controls()

    assert len(controls) == 3
```

**Integration Test:** `tests/integration/test_aws_sync.py`

```python
"""Integration tests for AWS sync (requires real AWS credentials)."""

import pytest
import os
from cve_mcp.ingest.aws_api_client import get_aws_client

# Skip if no AWS credentials
pytestmark = pytest.mark.skipif(
    not os.getenv('AWS_ACCESS_KEY_ID'),
    reason="AWS credentials not available"
)


@pytest.mark.integration
@pytest.mark.aws
def test_fetch_real_s3_controls():
    """Test fetching real S3 controls from AWS."""
    client = get_aws_client(
        access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region=os.getenv('AWS_REGION', 'us-east-1')
    )

    controls = client.list_security_controls(service_name="s3", max_results=10)

    # Assertions
    assert len(controls) > 0
    assert all(c['SecurityControlId'].startswith('S3.') for c in controls)
    assert all('Title' in c for c in controls)
    assert all('Description' in c for c in controls)

    # Print for manual verification
    print(f"\nFetched {len(controls)} S3 controls:")
    for control in controls[:3]:  # Print first 3
        print(f"  - {control['SecurityControlId']}: {control['Title']}")
```

---

## Azure Policy Integration

### Prerequisites

**Option 1: GitHub Source (Recommended - No Azure credentials needed)**

```bash
# No authentication required - public repo
AZURE_POLICY_SOURCE=github
AZURE_POLICY_REPO_URL=https://github.com/Azure/azure-policy
AZURE_POLICY_BRANCH=master
```

**Option 2: Azure Resource Manager API (Alternative)**

1. Create Service Principal:
   ```bash
   az ad sp create-for-rbac --name "cve-mcp-azure-reader" --role "Reader"
   ```

2. Environment variables:
   ```bash
   AZURE_CLIENT_ID=<appId from above>
   AZURE_CLIENT_SECRET=<password from above>
   AZURE_TENANT_ID=<tenant from above>
   AZURE_SUBSCRIPTION_ID=<your subscription ID>
   AZURE_POLICY_SOURCE=api
   ```

### Implementation

**File:** `src/cve_mcp/ingest/azure_api_client.py`

```python
"""Azure API client for Policy and Security Center."""

import httpx
import json
from typing import Any, Dict, List
import structlog

logger = structlog.get_logger(__name__)


class AzurePolicyClient:
    """Client for Azure Policy definitions."""

    def __init__(
        self,
        source: str = "github",  # "github" or "api"
        repo_url: str = "https://github.com/Azure/azure-policy",
        branch: str = "master",
        client_id: str | None = None,
        client_secret: str | None = None,
        tenant_id: str | None = None,
    ):
        """Initialize Azure client."""
        self.source = source
        self.repo_url = repo_url
        self.branch = branch
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id

    async def fetch_policy_definitions(
        self,
        category: str = "Storage"
    ) -> List[Dict[str, Any]]:
        """
        Fetch Azure Policy definitions.

        Args:
            category: Policy category (Storage, Compute, etc.)

        Returns:
            List of policy definitions
        """
        if self.source == "github":
            return await self._fetch_from_github(category)
        else:
            return await self._fetch_from_api(category)

    async def _fetch_from_github(
        self,
        category: str
    ) -> List[Dict[str, Any]]:
        """Fetch policies from GitHub repo."""
        try:
            # Built-in policies are in built-in-policies/<category>/*.json
            base_url = f"https://raw.githubusercontent.com/Azure/azure-policy/{self.branch}"
            index_url = f"{base_url}/built-in-policies/policyDefinitions/{category}/index.json"

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Fetch index of policies
                response = await client.get(index_url)
                response.raise_for_status()
                index = response.json()

                policies = []
                for policy_ref in index.get('policies', []):
                    policy_file = policy_ref.get('file')
                    if not policy_file:
                        continue

                    # Fetch individual policy definition
                    policy_url = f"{base_url}/built-in-policies/policyDefinitions/{category}/{policy_file}"
                    policy_response = await client.get(policy_url)
                    policy_response.raise_for_status()
                    policy_data = policy_response.json()

                    policies.append(policy_data)

                logger.info(
                    "fetched_azure_policies_from_github",
                    category=category,
                    count=len(policies)
                )
                return policies

        except Exception as e:
            logger.error(
                "failed_to_fetch_azure_policies_from_github",
                category=category,
                error=str(e),
                exc_info=True
            )
            raise

    async def _fetch_from_api(
        self,
        category: str
    ) -> List[Dict[str, Any]]:
        """Fetch policies from Azure Resource Manager API."""
        try:
            # Get OAuth token
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            token_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'https://management.azure.com/.default',
                'grant_type': 'client_credentials'
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                token_response = await client.post(token_url, data=token_data)
                token_response.raise_for_status()
                access_token = token_response.json()['access_token']

                # Fetch policy definitions
                policies_url = "https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions"
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }

                policies_response = await client.get(
                    policies_url,
                    headers=headers,
                    params={'api-version': '2021-06-01', '$filter': f"category eq '{category}'"}
                )
                policies_response.raise_for_status()
                data = policies_response.json()

                policies = data.get('value', [])

                logger.info(
                    "fetched_azure_policies_from_api",
                    category=category,
                    count=len(policies)
                )
                return policies

        except Exception as e:
            logger.error(
                "failed_to_fetch_azure_policies_from_api",
                category=category,
                error=str(e),
                exc_info=True
            )
            raise


# Factory function
def get_azure_client(
    source: str = "github",
    repo_url: str = "https://github.com/Azure/azure-policy",
    branch: str = "master",
    client_id: str | None = None,
    client_secret: str | None = None,
    tenant_id: str | None = None,
) -> AzurePolicyClient:
    """Get Azure Policy client instance."""
    return AzurePolicyClient(
        source=source,
        repo_url=repo_url,
        branch=branch,
        client_id=client_id,
        client_secret=client_secret,
        tenant_id=tenant_id,
    )
```

### Testing

**Integration Test:** `tests/integration/test_azure_sync.py`

```python
"""Integration tests for Azure sync."""

import pytest
from cve_mcp.ingest.azure_api_client import get_azure_client


@pytest.mark.integration
@pytest.mark.azure
@pytest.mark.asyncio
async def test_fetch_storage_policies_from_github():
    """Test fetching Storage policies from GitHub (no auth needed)."""
    client = get_azure_client(source="github")

    policies = await client.fetch_policy_definitions(category="Storage")

    # Assertions
    assert len(policies) > 0
    assert all('properties' in p for p in policies)
    assert all(p['properties'].get('metadata', {}).get('category') == 'Storage' for p in policies)

    # Print for manual verification
    print(f"\nFetched {len(policies)} Storage policies from GitHub:")
    for policy in policies[:3]:  # Print first 3
        props = policy['properties']
        print(f"  - {props.get('displayName')}")
```

---

## GCP Organization Policy Integration

### Prerequisites

**GCP Service Account Setup:**

1. Create service account:
   ```bash
   gcloud iam service-accounts create cve-mcp-reader \
     --display-name="CVE MCP Cloud Security Reader"
   ```

2. Grant permissions:
   ```bash
   gcloud organizations add-iam-policy-binding <ORG_ID> \
     --member="serviceAccount:cve-mcp-reader@<PROJECT_ID>.iam.gserviceaccount.com" \
     --role="roles/orgpolicy.policyViewer"
   ```

3. Create and download key:
   ```bash
   gcloud iam service-accounts keys create ~/gcp-cve-mcp-key.json \
     --iam-account=cve-mcp-reader@<PROJECT_ID>.iam.gserviceaccount.com
   ```

4. Environment variable:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS=/app/secrets/gcp-cve-mcp-key.json
   GCP_ORGANIZATION_ID=<your-org-id>
   ```

### Implementation

**File:** `src/cve_mcp/ingest/gcp_api_client.py`

```python
"""GCP API client for Organization Policy."""

from google.cloud import orgpolicy_v2
from typing import Any, Dict, List
import structlog

logger = structlog.get_logger(__name__)


class GCPOrgPolicyClient:
    """Client for GCP Organization Policy API."""

    def __init__(
        self,
        organization_id: str,
        credentials_path: str | None = None
    ):
        """
        Initialize GCP client.

        Args:
            organization_id: GCP organization ID (e.g., "123456789012")
            credentials_path: Path to service account JSON key
        """
        self.organization_id = organization_id

        if credentials_path:
            import os
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path

        self.client = orgpolicy_v2.OrgPolicyClient()
        self.parent = f"organizations/{organization_id}"

    def list_constraints(
        self,
        service_prefix: str | None = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch organization policy constraints.

        Args:
            service_prefix: Filter by service (e.g., "storage.googleapis.com")

        Returns:
            List of constraint definitions
        """
        try:
            constraints = []

            # List all custom constraints
            request = orgpolicy_v2.ListCustomConstraintsRequest(
                parent=self.parent
            )

            for constraint in self.client.list_custom_constraints(request=request):
                # Convert to dict
                constraint_dict = {
                    'name': constraint.name,
                    'display_name': constraint.display_name,
                    'description': constraint.description,
                    'condition': constraint.condition,
                    'action_type': constraint.action_type.name,
                    'method_types': [mt.name for mt in constraint.method_types],
                    'resource_types': list(constraint.resource_types),
                }

                # Filter by service if specified
                if service_prefix:
                    if not any(service_prefix in rt for rt in constraint.resource_types):
                        continue

                constraints.append(constraint_dict)

            logger.info(
                "fetched_gcp_org_policy_constraints",
                service_prefix=service_prefix,
                count=len(constraints)
            )
            return constraints

        except Exception as e:
            logger.error(
                "failed_to_fetch_gcp_constraints",
                service_prefix=service_prefix,
                error=str(e),
                exc_info=True
            )
            raise


# Factory function
def get_gcp_client(
    organization_id: str,
    credentials_path: str | None = None
) -> GCPOrgPolicyClient:
    """Get GCP Organization Policy client instance."""
    return GCPOrgPolicyClient(
        organization_id=organization_id,
        credentials_path=credentials_path
    )
```

---

## Quality Gates & Validation

### Confidence Scoring

**Scraper Confidence (0.0-1.0):**
- Structured API response (Security Hub JSON): **0.95**
- GitHub JSON policy definition: **0.90**
- HTML documentation scrape with schema: **0.75**
- Plain text documentation scrape: **0.60**
- Inferred from related docs: **0.50**

**LLM Verification Boost:**
- LLM confirms scraper result: **+0.10**
- LLM extracts additional context: **+0.05**

**Human Review (Production Gold Standard):**
- Security engineer reviewed: **1.00**

### Breaking Change Detection

**Heuristics:**

1. **Security Feature Disabled**
   ```python
   if old_value.get("enabled_by_default") is True and \
      new_value.get("enabled_by_default") is False:
       return True  # BREAKING CHANGE
   ```

2. **Encryption Downgraded**
   ```python
   encryption_strength = {"AES-256": 3, "AES-192": 2, "AES-128": 1, "none": 0}
   if encryption_strength[new] < encryption_strength[old]:
       return True  # BREAKING CHANGE
   ```

3. **Access Controls Loosened**
   ```python
   if old_value.get("public_access_blocked") is True and \
      new_value.get("public_access_blocked") is False:
       return True  # BREAKING CHANGE
   ```

### Validation Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  Property Change Detected                                        │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  Is Breaking Change?                                             │
│  - Check heuristics                                              │
│  - Flag if security downgrade                                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
         ┌───────────┴──────────┐
         │                      │
         ▼                      ▼
    Breaking              Non-Breaking
         │                      │
         ▼                      ▼
┌──────────────┐        ┌──────────────┐
│ requires_    │        │ Auto-approve │
│ review=true  │        │ and insert   │
└──────┬───────┘        └──────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ Insert into property_changes table   │
│ Send alert to security team          │
│ Block auto-deployment until reviewed │
└──────────────────────────────────────┘
```

---

## Monitoring & Alerting

### Metrics to Track

**Sync Health:**
- `cloud_security_sync_duration_seconds{provider="aws"}`
- `cloud_security_sync_success_total{provider="aws"}`
- `cloud_security_sync_failure_total{provider="aws"}`
- `cloud_security_properties_synced{provider="aws", service="s3"}`

**Data Quality:**
- `cloud_security_quality_gate_failures{gate="source_quote"}`
- `cloud_security_confidence_score{service="aws-s3"}` (histogram)
- `cloud_security_breaking_changes_total{service="aws-s3"}`

**API Health:**
- `cloud_security_api_latency_seconds{provider="aws", endpoint="list_controls"}`
- `cloud_security_api_errors_total{provider="aws", error_type="rate_limit"}`

### Alerts

**Critical:**
```yaml
- alert: CloudSecuritySyncFailing
  expr: cloud_security_sync_failure_total > 0
  for: 1h
  labels:
    severity: critical
  annotations:
    summary: "Cloud security sync failing for {{ $labels.provider }}"
    description: "Sync has failed {{ $value }} times in the last hour"

- alert: CloudSecurityBreakingChangeDetected
  expr: cloud_security_breaking_changes_total > 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Breaking security change detected in {{ $labels.service }}"
    description: "Review required in cloud_security_property_changes table"
```

**Warning:**
```yaml
- alert: CloudSecurityLowConfidenceData
  expr: avg(cloud_security_confidence_score) < 0.70
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "Low confidence cloud security data"
    description: "Average confidence score below threshold: {{ $value }}"

- alert: CloudSecuritySyncSlow
  expr: cloud_security_sync_duration_seconds > 600
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Cloud security sync taking too long"
    description: "Sync duration: {{ $value }}s (threshold: 600s)"
```

---

## Rollback Procedures

### Emergency Rollback

**Scenario:** Production sync causing data corruption or performance issues

```bash
# 1. Stop Celery beat (prevents new syncs)
docker exec cve-mcp-beat pkill -f celery

# 2. Revert to sample data
docker exec cve-mcp-server alembic downgrade 011

# 3. Re-apply migration with sample data
docker exec cve-mcp-server alembic upgrade 011

# 4. Restart beat with sample data sync
docker restart cve-mcp-beat
```

### Partial Rollback (Single Provider)

**Scenario:** AWS sync broken but Azure/GCP working fine

```python
# Disable AWS sync in celery_app.py beat_schedule
"sync_aws_s3": {
    "task": "cve_mcp.tasks.sync_cloud_security.sync_aws_s3_task",
    "schedule": crontab(hour=3, minute=0),
    "enabled": False,  # ADD THIS
},
```

```bash
# Delete AWS properties
docker exec cve-mcp-postgres psql -U postgres -d cve_mcp -c \
  "DELETE FROM cloud_security_properties WHERE service_id LIKE 'aws-%';"

# Restart workers
docker restart cve-mcp-worker cve-mcp-beat
```

---

## Security & Compliance

### Credential Security

**Required:**
- ✅ Store credentials in `.env` (never commit to git)
- ✅ Use Docker secrets for production deployment
- ✅ Rotate credentials every 90 days
- ✅ Use IAM roles instead of access keys when possible
- ✅ Encrypt credentials at rest

**Docker Secrets Setup:**
```yaml
# docker-compose.prod.yml
services:
  cve-mcp-worker:
    secrets:
      - aws_access_key
      - aws_secret_key
      - gcp_service_account_key

secrets:
  aws_access_key:
    file: ./secrets/aws_access_key.txt
  aws_secret_key:
    file: ./secrets/aws_secret_key.txt
  gcp_service_account_key:
    file: ./secrets/gcp_sa_key.json
```

### Audit Logging

**Log All API Calls:**
```python
logger.info(
    "cloud_security_api_call",
    provider="aws",
    endpoint="list_security_controls",
    service="s3",
    user="cve-mcp-worker",
    timestamp=datetime.utcnow().isoformat(),
    records_fetched=len(controls)
)
```

**Retention:** 90 days minimum (compliance requirement)

---

## Cost Analysis

### AWS Security Hub

**Pricing:**
- Security Hub: $0.0010 per check per month
- Config Rules: $0.003 per rule per month
- API Calls: Free (within limits)

**Estimated Monthly Cost:**
- 50 Security Hub checks × $0.0010 = **$0.05/month**
- 20 Config rules × $0.003 = **$0.06/month**
- **Total: ~$0.11/month** (negligible)

### Azure Policy

**Pricing:**
- GitHub source: **$0/month** (public repo)
- Azure Resource Manager API: **$0/month** (no charge for read operations)

### GCP Organization Policy

**Pricing:**
- Organization Policy API: **$0/month** (no charge)
- Service account: **$0/month**

### Total Estimated Cost

**All Three Providers: ~$0.11/month** (AWS only has charges, minimal)

---

## Testing Plan

### Unit Tests (Week 1)

```bash
# Test AWS client
pytest tests/test_aws_api_client.py -v

# Test Azure client
pytest tests/test_azure_api_client.py -v

# Test GCP client
pytest tests/test_gcp_api_client.py -v

# Test parsers
pytest tests/test_cloud_security_parser.py -v
```

### Integration Tests (Week 2-4)

```bash
# Requires real credentials in .env
pytest tests/integration/test_aws_sync.py -v -m aws
pytest tests/integration/test_azure_sync.py -v -m azure
pytest tests/integration/test_gcp_sync.py -v -m gcp
```

### End-to-End Test (Week 5)

```bash
# 1. Run full sync
docker exec cve-mcp-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_cloud_security.sync_aws_s3_task

# 2. Query via MCP
curl -X POST http://localhost:8307/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_cloud_service_security",
    "arguments": {"provider": "aws", "service": "s3"}
  }'

# 3. Verify response has:
# - Multiple security properties (>10)
# - Real source URLs (not sample data)
# - Confidence scores >0.70
# - Recent last_verified timestamps
```

### Load Testing (Week 6)

```bash
# Test sync performance with production data volume
# Target: <10 minutes for full sync of all services

time docker exec cve-mcp-worker celery -A cve_mcp.tasks.celery_app call \
  cve_mcp.tasks.sync_cloud_security.sync_aws_s3_task
```

---

## Next Steps

### Immediate (Week 1)

1. ✅ Create AWS IAM user with Security Hub access
2. ✅ Add `boto3` to `requirements.txt`
3. ✅ Implement `aws_api_client.py`
4. ✅ Update `sync_aws_s3_task()` to use real API
5. ✅ Run unit tests
6. ✅ Run integration test with real AWS account

### Short-Term (Week 2-4)

7. ✅ Implement Azure Policy GitHub fetcher
8. ✅ Implement GCP Organization Policy client
9. ✅ Expand service coverage (15+ services per provider)
10. ✅ Add monitoring dashboards
11. ✅ Configure alerts for breaking changes

### Long-Term (Month 2-3)

12. ✅ Implement LLM verification for confidence boost
13. ✅ Add human review workflow for breaking changes
14. ✅ Build security posture scoring engine
15. ✅ Implement automated Terraform remediation

---

## Contact & Support

**Primary Contact:** Platform Engineering Team
**Email:** platform-engineering@ansvar.eu
**Slack:** #platform-engineering

**Escalation Path:**
1. Platform Engineering (L1 - implementation)
2. Security Engineering (L2 - security review)
3. DevOps Team (L3 - infrastructure)

**Documentation:**
- README.md (overview)
- docs/modules/cloud_security.md (module details)
- This document (production implementation)

---

## Appendix A: Dependencies

**Python Packages (add to `requirements.txt`):**

```txt
# AWS
boto3>=1.34.0
botocore>=1.34.0

# Azure
azure-identity>=1.15.0
azure-mgmt-resource>=23.0.0
azure-mgmt-security>=6.0.0

# GCP
google-cloud-orgpolicy>=1.10.0
google-auth>=2.27.0

# HTTP clients (already included)
httpx>=0.26.0
```

---

## Appendix B: Sample API Responses

### AWS Security Hub Control

```json
{
  "SecurityControlId": "S3.1",
  "Title": "S3 Block Public Access setting should be enabled",
  "Description": "This control checks whether S3 Block Public Access settings are enabled at the account level.",
  "SeverityRating": "MEDIUM",
  "ControlStatus": "ENABLED",
  "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation",
  "ParameterDefinitions": {},
  "Region": "us-east-1",
  "SecurityControlArn": "arn:aws:securityhub:us-east-1::security-control/S3.1"
}
```

### Azure Policy Definition

```json
{
  "id": "/providers/Microsoft.Authorization/policyDefinitions/...",
  "name": "secure-transfer-required",
  "properties": {
    "displayName": "Secure transfer to storage accounts should be enabled",
    "policyType": "BuiltIn",
    "mode": "All",
    "description": "Audit requirement of Secure transfer in your storage account...",
    "metadata": {
      "category": "Storage",
      "version": "2.0.0"
    },
    "policyRule": { ... }
  }
}
```

### GCP Organization Policy Constraint

```json
{
  "name": "organizations/123456789012/customConstraints/custom.storage.publicAccessPrevention",
  "display_name": "Enforce public access prevention",
  "description": "This constraint enforces public access prevention on Cloud Storage buckets.",
  "condition": "resource.bucket.iamConfiguration.publicAccessPrevention == 'enforced'",
  "action_type": "DENY",
  "resource_types": ["storage.googleapis.com/Bucket"]
}
```

---

**END OF HANDOVER DOCUMENT**

*Ready for production implementation. Estimated 6-week timeline to full production data coverage.*
