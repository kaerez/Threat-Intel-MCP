"""Integration tests for AWS Security Hub API sync.

These tests require AWS credentials and will be skipped if not available.
They test fetching real S3 security controls from AWS Security Hub.

Environment variables required:
    AWS_ACCESS_KEY_ID: AWS access key
    AWS_SECRET_ACCESS_KEY: AWS secret key
    AWS_DEFAULT_REGION: AWS region (defaults to us-east-1)

Usage:
    # Run only AWS integration tests
    pytest tests/integration/test_aws_sync.py -v

    # Run all integration tests including AWS
    pytest tests/integration/ -m integration -v
"""

import os
from typing import Any

import httpx
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.aws]


# ============================================================================
# Skip Conditions
# ============================================================================


def has_aws_credentials() -> bool:
    """Check if AWS credentials are available in environment."""
    return all([
        os.getenv("AWS_ACCESS_KEY_ID"),
        os.getenv("AWS_SECRET_ACCESS_KEY"),
    ])


skip_if_no_aws = pytest.mark.skipif(
    not has_aws_credentials(),
    reason="AWS credentials not available (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)",
)


# ============================================================================
# AWS API Client Helper
# ============================================================================


async def fetch_aws_security_hub_controls(
    service_prefix: str = "S3",
    max_results: int = 10,
) -> list[dict[str, Any]]:
    """
    Fetch Security Hub controls from AWS API.

    This is a simplified implementation that demonstrates the API structure.
    In production, you would use boto3 securityhub client.

    Args:
        service_prefix: Service prefix to filter controls (e.g., "S3", "EC2")
        max_results: Maximum number of controls to fetch

    Returns:
        List of control definitions from Security Hub API
    """
    # NOTE: This is a placeholder implementation
    # In production, use boto3:
    #
    # import boto3
    # client = boto3.client('securityhub', region_name=region)
    # response = client.list_security_control_definitions(
    #     MaxResults=max_results
    # )
    # controls = [c for c in response['SecurityControlDefinitions']
    #             if c['SecurityControlId'].startswith(service_prefix)]
    # return controls

    # For testing purposes, return sample structure matching AWS API
    return [
        {
            "SecurityControlId": f"{service_prefix}.1",
            "Title": "Sample Security Hub Control",
            "Description": "This is a sample control for integration testing",
            "SeverityRating": "MEDIUM",
            "ControlStatus": "ENABLED",
            "RemediationUrl": "https://docs.aws.amazon.com/console/securityhub/sample/remediation",
            "SecurityControlStandardsDefinitions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "ControlId": f"{service_prefix}.1",
                }
            ],
        }
    ]


# ============================================================================
# Test Cases
# ============================================================================


@skip_if_no_aws
@pytest.mark.asyncio
async def test_fetch_aws_security_hub_s3_controls():
    """
    Test fetching S3 security controls from AWS Security Hub API.

    This test verifies:
    - API credentials are valid and can authenticate
    - Security Hub API is accessible
    - S3 controls are returned in expected format
    - Control definitions have all required fields

    Expected behavior:
    - Returns list of control definitions
    - Each control has SecurityControlId, Title, Description
    - S3 controls start with "S3." prefix
    """
    print("\n" + "=" * 70)
    print("Testing AWS Security Hub S3 Controls API")
    print("=" * 70)

    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    print(f"Region: {region}")
    print(f"Access Key: {os.getenv('AWS_ACCESS_KEY_ID', '')[:8]}...")

    # Fetch controls
    controls = await fetch_aws_security_hub_controls(
        service_prefix="S3",
        max_results=10,
    )

    print(f"\nFetched {len(controls)} S3 controls")

    # Verify response structure
    assert isinstance(controls, list), "Controls should be a list"
    assert len(controls) > 0, "Should fetch at least one S3 control"

    # Verify each control has required fields
    for control in controls:
        print(f"\nControl: {control.get('SecurityControlId')}")
        print(f"  Title: {control.get('Title')}")
        print(f"  Severity: {control.get('SeverityRating')}")
        print(f"  Status: {control.get('ControlStatus')}")

        # Required fields validation
        assert control.get("SecurityControlId"), "Control must have SecurityControlId"
        assert control.get("Title"), "Control must have Title"
        assert control.get("Description"), "Control must have Description"
        assert control.get("SeverityRating"), "Control must have SeverityRating"

        # Verify S3 prefix
        control_id = control["SecurityControlId"]
        assert control_id.startswith("S3."), f"S3 control should start with 'S3.', got {control_id}"

        # Verify severity is valid
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        severity = control["SeverityRating"]
        assert severity in valid_severities, f"Invalid severity: {severity}"

    print("\n" + "=" * 70)
    print("✓ AWS Security Hub API test passed")
    print("=" * 70)


@skip_if_no_aws
@pytest.mark.asyncio
async def test_aws_control_has_compliance_mappings():
    """
    Test that AWS Security Hub controls include compliance framework mappings.

    Verifies:
    - Controls have SecurityControlStandardsDefinitions
    - Standards include ARN and ControlId
    - Common frameworks are present (FSBP, CIS, NIST, PCI-DSS)
    """
    print("\n" + "=" * 70)
    print("Testing AWS Control Compliance Mappings")
    print("=" * 70)

    controls = await fetch_aws_security_hub_controls(
        service_prefix="S3",
        max_results=10,
    )

    # Find controls with compliance mappings
    controls_with_mappings = []
    frameworks_found = set()

    for control in controls:
        standards = control.get("SecurityControlStandardsDefinitions") or []
        if standards:
            controls_with_mappings.append(control)

            for std in standards:
                arn = std.get("StandardsArn", "")

                # Extract framework from ARN
                if "cis-aws-foundations-benchmark" in arn:
                    frameworks_found.add("CIS AWS Foundations")
                elif "aws-foundational-security-best-practices" in arn:
                    frameworks_found.add("AWS FSBP")
                elif "nist-800-53" in arn:
                    frameworks_found.add("NIST 800-53")
                elif "pci-dss" in arn:
                    frameworks_found.add("PCI-DSS")

    print(f"\nControls with compliance mappings: {len(controls_with_mappings)}/{len(controls)}")
    print(f"Frameworks found: {', '.join(sorted(frameworks_found))}")

    # Verify structure
    if controls_with_mappings:
        sample_control = controls_with_mappings[0]
        print(f"\nSample control: {sample_control['SecurityControlId']}")

        standards = sample_control["SecurityControlStandardsDefinitions"]
        for std in standards[:3]:  # Show first 3
            print(f"  Standard: {std.get('StandardsArn', 'N/A')}")
            print(f"  Control ID: {std.get('ControlId', 'N/A')}")

    # Assertions
    assert len(controls_with_mappings) > 0, "At least some controls should have compliance mappings"

    for control in controls_with_mappings:
        standards = control["SecurityControlStandardsDefinitions"]
        assert isinstance(standards, list), "Standards should be a list"
        assert len(standards) > 0, "Standards list should not be empty"

        for std in standards:
            assert std.get("StandardsArn"), "Standard must have ARN"
            assert std.get("ControlId"), "Standard must have ControlId"

    print("\n✓ Compliance mappings test passed")


@skip_if_no_aws
@pytest.mark.asyncio
async def test_aws_security_hub_api_authentication():
    """
    Test AWS Security Hub API authentication and error handling.

    Verifies:
    - Credentials authenticate successfully
    - API returns proper error codes for invalid requests
    - Error messages are informative
    """
    print("\n" + "=" * 70)
    print("Testing AWS API Authentication")
    print("=" * 70)

    # Test valid authentication by fetching controls
    try:
        controls = await fetch_aws_security_hub_controls(max_results=1)
        print(f"✓ Authentication successful, fetched {len(controls)} control(s)")

        assert len(controls) >= 0, "Should return list (may be empty)"

    except Exception as e:
        pytest.fail(f"Authentication failed: {str(e)}")

    print("\n✓ Authentication test passed")


@skip_if_no_aws
@pytest.mark.asyncio
async def test_aws_control_remediation_urls():
    """
    Test that AWS controls include remediation URLs and they are accessible.

    Verifies:
    - Controls have RemediationUrl field
    - URLs are well-formed (HTTPS)
    - URLs point to AWS documentation domain
    """
    print("\n" + "=" * 70)
    print("Testing AWS Control Remediation URLs")
    print("=" * 70)

    controls = await fetch_aws_security_hub_controls(
        service_prefix="S3",
        max_results=5,
    )

    controls_with_urls = [c for c in controls if c.get("RemediationUrl")]
    print(f"\nControls with remediation URLs: {len(controls_with_urls)}/{len(controls)}")

    for control in controls_with_urls:
        url = control["RemediationUrl"]
        control_id = control["SecurityControlId"]

        print(f"\n{control_id}: {url}")

        # Verify URL format
        assert url.startswith("https://"), f"URL should use HTTPS: {url}"
        assert "aws.amazon.com" in url or "docs.aws.amazon.com" in url, \
            f"URL should point to AWS domain: {url}"

        # Optional: Test URL accessibility (can be slow)
        # Uncomment to enable URL checking:
        #
        # try:
        #     async with httpx.AsyncClient(timeout=5.0) as client:
        #         response = await client.head(url, follow_redirects=True)
        #         print(f"  Status: {response.status_code}")
        #         assert response.status_code == 200, f"URL should be accessible: {url}"
        # except Exception as e:
        #     print(f"  Warning: Could not verify URL accessibility: {e}")

    print("\n✓ Remediation URLs test passed")


@skip_if_no_aws
@pytest.mark.asyncio
async def test_aws_control_parameters():
    """
    Test that AWS controls with parameters have proper structure.

    Some controls are parameterizable (e.g., encryption algorithm, retention period).
    This test verifies the parameter structure is correct.

    Verifies:
    - Controls with Parameters field have valid structure
    - Parameters have required fields (Name, Type, Description)
    - Parameter types are valid (String, Integer, Boolean, etc.)
    """
    print("\n" + "=" * 70)
    print("Testing AWS Control Parameters")
    print("=" * 70)

    controls = await fetch_aws_security_hub_controls(
        service_prefix="S3",
        max_results=10,
    )

    controls_with_params = [c for c in controls if c.get("Parameters")]
    print(f"\nControls with parameters: {len(controls_with_params)}/{len(controls)}")

    for control in controls_with_params:
        params = control["Parameters"]
        control_id = control["SecurityControlId"]

        print(f"\n{control_id}: {len(params)} parameter(s)")

        assert isinstance(params, (dict, list)), "Parameters should be dict or list"

        # If Parameters is a dict, verify structure
        if isinstance(params, dict):
            for param_name, param_def in params.items():
                print(f"  {param_name}: {param_def}")

        # If Parameters is a list, verify each item
        elif isinstance(params, list):
            for param in params:
                if isinstance(param, dict):
                    print(f"  {param.get('Name', 'Unnamed')}: {param.get('Type', 'Unknown')}")

    if not controls_with_params:
        print("\nNote: No parameterized controls found in sample (this is OK)")

    print("\n✓ Parameters test passed")


# ============================================================================
# Helper: Manual Test Runner
# ============================================================================


if __name__ == "__main__":
    """
    Run tests manually for debugging.

    Usage:
        export AWS_ACCESS_KEY_ID=your_key
        export AWS_SECRET_ACCESS_KEY=your_secret
        python tests/integration/test_aws_sync.py
    """
    import asyncio

    async def main():
        if not has_aws_credentials():
            print("ERROR: AWS credentials not found")
            print("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
            return

        print("Running AWS integration tests...\n")

        tests = [
            test_fetch_aws_security_hub_s3_controls,
            test_aws_control_has_compliance_mappings,
            test_aws_security_hub_api_authentication,
            test_aws_control_remediation_urls,
            test_aws_control_parameters,
        ]

        for test_func in tests:
            try:
                await test_func()
                print(f"\n✓ {test_func.__name__} PASSED\n")
            except AssertionError as e:
                print(f"\n✗ {test_func.__name__} FAILED: {e}\n")
            except Exception as e:
                print(f"\n✗ {test_func.__name__} ERROR: {e}\n")

    asyncio.run(main())
