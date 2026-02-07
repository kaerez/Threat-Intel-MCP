# Integration Tests for Cloud Provider APIs

This directory contains integration tests that verify real API interactions with AWS, Azure, and GCP cloud providers for the Cloud Security module.

## Overview

These tests are designed to:

1. **Test real API interactions** - Fetch actual data from cloud provider APIs
2. **Verify data structure** - Ensure responses match expected schemas
3. **Validate parsers** - Confirm our parsers handle real API data correctly
4. **Be safely skippable** - Tests skip automatically when credentials are unavailable
5. **Support CI/CD** - Can run in automated pipelines with proper secrets configuration

## Test Files

### `test_aws_sync.py` - AWS Security Hub Tests
Tests AWS Security Hub API for S3 security controls.

**Tests:**
- `test_fetch_aws_security_hub_s3_controls` - Fetch and validate S3 controls
- `test_aws_control_has_compliance_mappings` - Verify compliance framework mappings
- `test_aws_security_hub_api_authentication` - Test authentication
- `test_aws_control_remediation_urls` - Validate remediation URLs
- `test_aws_control_parameters` - Test parameterized controls

**Credentials Required:**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1  # Optional, defaults to us-east-1
```

### `test_azure_sync.py` - Azure Policy Tests
Tests Azure Policy definitions from GitHub (no auth) and Azure API (with auth).

**Tests:**
- `test_fetch_azure_storage_policies_from_github` - Fetch from public GitHub repo (NO AUTH)
- `test_azure_policy_compliance_metadata` - Verify compliance metadata
- `test_azure_policy_rule_structure` - Validate policy rule structure
- `test_azure_policy_parameters` - Test parameterized policies
- `test_fetch_azure_policies_from_api` - Fetch from Azure API (REQUIRES AUTH)
- `test_fetch_azure_arm_storage_schema` - Fetch ARM schemas (NO AUTH)

**Credentials Required (for API tests only):**
```bash
export AZURE_SUBSCRIPTION_ID=your_subscription_id
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET=your_client_secret
```

**Note:** Most Azure tests use public GitHub repositories and require NO credentials!

### `test_gcp_sync.py` - GCP Organization Policy Tests
Tests GCP Organization Policy API for Cloud Storage constraints.

**Tests:**
- `test_fetch_gcp_storage_org_policy_constraints` - Fetch storage constraints
- `test_gcp_constraint_types` - Verify BOOLEAN and LIST constraint types
- `test_gcp_storage_security_constraints` - Check key security constraints
- `test_gcp_credentials_authentication` - Test authentication
- `test_gcp_storage_iam_permissions_structure` - Validate IAM permissions
- `test_gcp_constraint_enforcement_states` - Test enforcement metadata
- `test_gcp_public_documentation_accessible` - Check public docs (NO AUTH)

**Credentials Required:**
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
export GCP_PROJECT_ID=your_project_id  # Optional
export GCP_ORGANIZATION_ID=your_org_id  # Optional
```

## Running the Tests

### Run All Integration Tests
```bash
# With pytest (skips tests without credentials automatically)
pytest tests/integration/ -v -m integration

# Run specific provider
pytest tests/integration/test_aws_sync.py -v
pytest tests/integration/test_azure_sync.py -v
pytest tests/integration/test_gcp_sync.py -v
```

### Run Tests by Marker
```bash
# Run only AWS tests
pytest tests/integration/ -v -m aws

# Run only Azure tests
pytest tests/integration/ -v -m azure

# Run only GCP tests
pytest tests/integration/ -v -m gcp

# Run all integration tests
pytest tests/integration/ -v -m integration
```

### Run Without Credentials (Dry Run)
```bash
# Will show which tests are skipped due to missing credentials
pytest tests/integration/ -v -rs

# Example output:
# SKIPPED [1] test_aws_sync.py:45: AWS credentials not available
# SKIPPED [1] test_gcp_sync.py:67: GCP credentials not available
```

### Manual Test Execution
Each test file can be run standalone for debugging:

```bash
# AWS tests
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
python tests/integration/test_aws_sync.py

# Azure tests (GitHub only, no auth needed)
python tests/integration/test_azure_sync.py

# GCP tests
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
python tests/integration/test_gcp_sync.py
```

## Setting Up Credentials

### AWS Credentials

**Option 1: IAM User (for testing)**
1. Create IAM user with `SecurityHubReadOnlyAccess` policy
2. Generate access keys
3. Set environment variables

**Option 2: AWS CLI Profile**
```bash
aws configure --profile threat-intel-test
# Then use: export AWS_PROFILE=threat-intel-test
```

**Minimal IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:ListSecurityControlDefinitions",
        "securityhub:GetSecurityControlDefinition"
      ],
      "Resource": "*"
    }
  ]
}
```

### Azure Credentials

**Option 1: Service Principal (recommended)**
```bash
# Create service principal
az ad sp create-for-rbac --name threat-intel-test --role Reader

# Output will contain:
# - appId (AZURE_CLIENT_ID)
# - password (AZURE_CLIENT_SECRET)
# - tenant (AZURE_TENANT_ID)

# Get subscription ID
az account show --query id -o tsv
```

**Option 2: Use Public GitHub (no auth needed)**
Most tests fetch from Azure's public GitHub repositories and require no credentials!

### GCP Credentials

**Option 1: Service Account (recommended)**
```bash
# Create service account
gcloud iam service-accounts create threat-intel-test \
    --display-name="Threat Intel Test"

# Grant Organization Policy Viewer role (org-level)
gcloud organizations add-iam-policy-binding YOUR_ORG_ID \
    --member="serviceAccount:threat-intel-test@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/orgpolicy.policyViewer"

# Or grant at project level
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:threat-intel-test@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/orgpolicy.policyViewer"

# Create and download key
gcloud iam service-accounts keys create ~/threat-intel-key.json \
    --iam-account=threat-intel-test@PROJECT_ID.iam.gserviceaccount.com

export GOOGLE_APPLICATION_CREDENTIALS=~/threat-intel-key.json
```

**Minimal Roles Required:**
- `Organization Policy Viewer` (`roles/orgpolicy.policyViewer`)
- Or `Viewer` role at organization/project level

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Cloud Integration Tests

on: [push, pull_request]

jobs:
  test-cloud-apis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e .
          pip install pytest pytest-asyncio httpx

      - name: Run AWS tests
        if: ${{ secrets.AWS_ACCESS_KEY_ID != '' }}
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: us-east-1
        run: pytest tests/integration/test_aws_sync.py -v

      - name: Run Azure tests (GitHub - no auth)
        run: pytest tests/integration/test_azure_sync.py -v -k "github"

      - name: Run GCP tests
        if: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY != '' }}
        env:
          GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
        run: pytest tests/integration/test_gcp_sync.py -v
```

### GitLab CI Example
```yaml
cloud-integration-tests:
  stage: test
  image: python:3.11
  before_script:
    - pip install -e .
    - pip install pytest pytest-asyncio httpx
  script:
    - pytest tests/integration/ -v -m integration
  variables:
    AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
    GOOGLE_APPLICATION_CREDENTIALS: $GOOGLE_APPLICATION_CREDENTIALS
  rules:
    - if: '$AWS_ACCESS_KEY_ID != null || $GOOGLE_APPLICATION_CREDENTIALS != null'
```

## Test Design Principles

### 1. Safe Skipping
Tests automatically skip when credentials are unavailable:
```python
skip_if_no_aws = pytest.mark.skipif(
    not has_aws_credentials(),
    reason="AWS credentials not available"
)
```

### 2. Helpful Output
Tests print detailed progress and results:
```
Testing AWS Security Hub S3 Controls API
======================================================================
Region: us-east-1
Access Key: AKIA1234...

Fetched 3 S3 controls

Control: S3.1
  Title: S3 Block Public Access setting should be enabled
  Severity: MEDIUM
  Status: ENABLED
```

### 3. Realistic Limits
Tests use small result limits to minimize API costs and execution time:
```python
controls = await fetch_aws_security_hub_controls(max_results=10)
```

### 4. Comprehensive Validation
Tests verify:
- Response structure (required fields present)
- Data types (lists, dicts, strings)
- Value constraints (valid enums, formats)
- Business logic (compliance mappings, URL formats)

### 5. Error Handling
Tests handle common failure modes gracefully:
- Network timeouts
- Authentication failures
- Rate limiting
- Invalid responses

## Troubleshooting

### Tests Skip Even With Credentials
```bash
# Verify credentials are set
echo $AWS_ACCESS_KEY_ID
echo $GOOGLE_APPLICATION_CREDENTIALS

# Check file exists (GCP)
ls -l $GOOGLE_APPLICATION_CREDENTIALS

# Test AWS credentials directly
aws sts get-caller-identity

# Test GCP credentials directly
gcloud auth list
```

### Authentication Errors
```bash
# AWS: Verify permissions
aws iam get-user
aws securityhub describe-hub

# Azure: Verify service principal
az login --service-principal \
  --username $AZURE_CLIENT_ID \
  --password $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID

# GCP: Verify service account
gcloud auth activate-service-account \
  --key-file=$GOOGLE_APPLICATION_CREDENTIALS
gcloud auth list
```

### Rate Limiting
If you hit rate limits, reduce `max_results` or add delays:
```python
# In test file
await asyncio.sleep(1)  # Add delay between requests
```

### Network Timeouts
Increase timeout values:
```python
async with httpx.AsyncClient(timeout=30.0) as client:
    ...
```

## Cost Considerations

These tests make READ-ONLY API calls and should incur minimal costs:

- **AWS Security Hub**: Free tier includes 10,000 control findings/month
- **Azure Policy**: Reading policy definitions is FREE
- **GCP Organization Policy**: Reading constraints is FREE

However, be aware of:
- API rate limits
- Potential charges if running at very high frequency
- Costs may apply if testing in production accounts with large datasets

## Security Best Practices

1. **Use dedicated test credentials** with minimal permissions
2. **Rotate credentials regularly** (every 90 days)
3. **Never commit credentials** to version control
4. **Use CI/CD secrets management** for automated testing
5. **Audit API access** regularly
6. **Limit credential scope** to specific resources when possible

## Contributing

When adding new integration tests:

1. Follow the existing pattern (skip conditions, helpful output, assertions)
2. Document required credentials in file docstring
3. Add pytest marks (`@pytest.mark.integration`, `@pytest.mark.provider`)
4. Include manual test runner in `if __name__ == "__main__"`
5. Update this README with new tests and requirements
6. Keep tests fast (< 30 seconds per test) with small result limits

## Related Documentation

- [Cloud Security Module Overview](../../docs/cloud-security.md)
- [Cloud Security Parser](../../src/cve_mcp/ingest/cloud_security_parser.py)
- [Cloud Security Sync Tasks](../../src/cve_mcp/tasks/sync_cloud_security.py)
- [MCP Cloud Security Tools](../../src/cve_mcp/mcp_tools/cloud_security.py)
