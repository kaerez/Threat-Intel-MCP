# Quick Start: Cloud Integration Tests

Fast reference for running cloud provider integration tests.

## TL;DR

```bash
# Run all tests (auto-skips if no credentials)
pytest tests/integration/test_*.py -v

# Run specific provider
pytest tests/integration/test_aws_sync.py -v      # AWS
pytest tests/integration/test_azure_sync.py -v    # Azure (GitHub - no auth!)
pytest tests/integration/test_gcp_sync.py -v      # GCP
```

## Setup Credentials

### AWS (5 minutes)
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

### Azure (0 minutes - uses GitHub!)
```bash
# No credentials needed!
# Most tests fetch from public GitHub repos
```

### GCP (10 minutes)
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
export GCP_PROJECT_ID=my-project
```

## Run Tests

### All Providers
```bash
pytest tests/integration/ -v -m integration
```

### By Provider
```bash
pytest tests/integration/ -v -m aws       # AWS only
pytest tests/integration/ -v -m azure     # Azure only
pytest tests/integration/ -v -m gcp       # GCP only
```

### Show Skipped Tests
```bash
pytest tests/integration/ -v -rs
# -rs = show reasons for skipped tests
```

### Manual Debug Run
```bash
# Run test file directly (shows detailed output)
export AWS_ACCESS_KEY_ID=xxx
python tests/integration/test_aws_sync.py
```

## What Each Test Does

### AWS Tests (`test_aws_sync.py`)
- Fetches S3 security controls from AWS Security Hub API
- Verifies compliance mappings (CIS, NIST, PCI-DSS)
- Validates remediation URLs
- Tests parameterized controls

**Requires:** AWS credentials (IAM user or role with SecurityHub read)

### Azure Tests (`test_azure_sync.py`)
- Fetches Storage policies from GitHub (NO AUTH!)
- Verifies policy rule structure
- Checks compliance metadata
- Tests ARM resource schemas
- Optional: Azure API tests (requires service principal)

**Requires:** NONE for GitHub tests, Azure credentials for API tests

### GCP Tests (`test_gcp_sync.py`)
- Fetches Cloud Storage org policy constraints
- Verifies BOOLEAN and LIST constraint types
- Tests IAM permissions structure
- Validates constraint enforcement metadata
- Public: GCP documentation accessibility (NO AUTH)

**Requires:** GCP service account with Organization Policy Viewer role

## Common Issues

### "Tests are skipped"
✓ This is expected! Tests skip automatically if credentials aren't available.

### "ModuleNotFoundError: No module named 'pytest'"
```bash
pip install -e ".[dev]"
```

### "AWS authentication failed"
```bash
# Verify credentials
aws sts get-caller-identity

# Check Security Hub access
aws securityhub describe-hub
```

### "GCP authentication failed"
```bash
# Verify credentials file exists
ls -l $GOOGLE_APPLICATION_CREDENTIALS

# Test authentication
gcloud auth activate-service-account \
  --key-file=$GOOGLE_APPLICATION_CREDENTIALS
```

## Output Example

```
tests/integration/test_aws_sync.py::test_fetch_aws_security_hub_s3_controls
======================================================================
Testing AWS Security Hub S3 Controls API
======================================================================
Region: us-east-1
Access Key: AKIA1234...

  ✓ Fetched policy: secure-transfer-required
  ✓ Fetched policy: infrastructure-encryption

Fetched 3 S3 controls

Control: S3.1
  Title: S3 Block Public Access setting should be enabled
  Severity: MEDIUM
  Status: ENABLED

======================================================================
✓ AWS Security Hub API test passed
======================================================================
PASSED
```

## Performance

- **AWS tests**: ~5-10 seconds (fetches 5-10 controls)
- **Azure tests**: ~3-5 seconds (fetches from GitHub)
- **GCP tests**: ~5-10 seconds (fetches 5-10 constraints)

All tests use small result limits to minimize API costs and execution time.

## Cost

- **AWS**: FREE tier includes 10,000 control findings/month
- **Azure**: Reading policies is FREE
- **GCP**: Reading constraints is FREE

## Need Help?

1. Check [README.md](README.md) for detailed documentation
2. Run individual test files for debugging: `python tests/integration/test_aws_sync.py`
3. Check pytest output with `-v -rs` flags
4. Verify credentials with cloud provider CLIs (aws, az, gcloud)

## CI/CD

Add to GitHub Actions:
```yaml
- name: Run AWS tests
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: pytest tests/integration/test_aws_sync.py -v
```

See [README.md](README.md) for complete CI/CD examples.
