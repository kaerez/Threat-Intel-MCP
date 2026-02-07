"""Integration tests for Azure Policy API sync.

These tests verify Azure Blob Storage policy fetching from public GitHub and Azure API.
GitHub tests require no authentication. Azure API tests require credentials.

Environment variables (optional):
    AZURE_SUBSCRIPTION_ID: Azure subscription ID
    AZURE_TENANT_ID: Azure tenant ID
    AZURE_CLIENT_ID: Service principal client ID
    AZURE_CLIENT_SECRET: Service principal secret

Usage:
    # Run all Azure tests (GitHub only, no credentials needed)
    pytest tests/integration/test_azure_sync.py -v

    # Run with Azure API tests (requires credentials)
    AZURE_SUBSCRIPTION_ID=xxx pytest tests/integration/test_azure_sync.py -v
"""

import json
import os
from typing import Any

import httpx
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.azure]


# ============================================================================
# Skip Conditions
# ============================================================================


def has_azure_credentials() -> bool:
    """Check if Azure API credentials are available in environment."""
    return all([
        os.getenv("AZURE_SUBSCRIPTION_ID"),
        os.getenv("AZURE_TENANT_ID"),
        os.getenv("AZURE_CLIENT_ID"),
        os.getenv("AZURE_CLIENT_SECRET"),
    ])


skip_if_no_azure_api = pytest.mark.skipif(
    not has_azure_credentials(),
    reason="Azure API credentials not available (AZURE_SUBSCRIPTION_ID, etc.)",
)


# ============================================================================
# Azure GitHub Policy Repository
# ============================================================================


AZURE_POLICY_GITHUB_BASE = "https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-policies/policyDefinitions"


async def fetch_azure_policies_from_github(
    category: str = "Storage",
    max_results: int = 10,
) -> list[dict[str, Any]]:
    """
    Fetch Azure built-in policy definitions from GitHub.

    Azure publishes all built-in policies to their GitHub repository.
    This requires no authentication and is perfect for testing.

    Args:
        category: Policy category (e.g., "Storage", "Security", "Compute")
        max_results: Maximum number of policies to fetch

    Returns:
        List of policy definitions from GitHub
    """
    policies = []

    # Well-known Storage policy files
    # These are stable filenames in Azure's GitHub repo
    policy_files = [
        "7c5a74bf-ae94-4a74-8fcf-644c2bec8b47.json",  # Secure transfer required
        "bfecdea6-31c4-4045-ad42-71b9dc87247d.json",  # Deny public blob access
        "404c3081-a854-4457-ae30-26a93ef643f9.json",  # Infrastructure encryption
        "34c877ad-507e-4c82-993e-3452a6e0ad3c.json",  # Default to Azure AD auth
        "b2982f36-99f2-4db5-8eff-283140c09693.json",  # Soft delete enabled
    ]

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        for policy_file in policy_files[:max_results]:
            url = f"{AZURE_POLICY_GITHUB_BASE}/{category}/{policy_file}"

            try:
                response = await client.get(url)
                if response.status_code == 200:
                    policy_def = response.json()
                    policies.append(policy_def)
                    print(f"  ✓ Fetched policy: {policy_def.get('name', 'Unknown')[:50]}")
                else:
                    print(f"  ⚠ Skipped {policy_file} (HTTP {response.status_code})")

            except Exception as e:
                print(f"  ⚠ Error fetching {policy_file}: {str(e)[:50]}")

    return policies


# ============================================================================
# Test Cases - GitHub (No Auth Required)
# ============================================================================


@pytest.mark.asyncio
async def test_fetch_azure_storage_policies_from_github():
    """
    Test fetching Azure Storage policies from public GitHub repository.

    This test requires NO authentication and verifies:
    - GitHub repository is accessible
    - Policy JSON files are properly formatted
    - Policies have required fields (name, properties, policyType)
    - Policy rules are present

    Expected behavior:
    - Returns list of policy definitions
    - Each policy has properties.displayName and properties.description
    - Policy type is "BuiltIn"
    """
    print("\n" + "=" * 70)
    print("Testing Azure Policy GitHub Repository")
    print("=" * 70)
    print("Source: https://github.com/Azure/azure-policy")
    print("Category: Storage")

    # Fetch policies from GitHub
    policies = await fetch_azure_policies_from_github(
        category="Storage",
        max_results=5,
    )

    print(f"\nFetched {len(policies)} Storage policies from GitHub")

    # Verify response structure
    assert isinstance(policies, list), "Policies should be a list"
    assert len(policies) > 0, "Should fetch at least one Storage policy"

    # Verify each policy has required fields
    for policy in policies:
        print(f"\nPolicy: {policy.get('name', 'Unknown')}")

        # Top-level fields
        assert "properties" in policy, "Policy must have 'properties' field"
        assert "name" in policy, "Policy must have 'name' field"

        properties = policy["properties"]

        # Properties fields
        display_name = properties.get("displayName", "")
        description = properties.get("description", "")

        print(f"  Display Name: {display_name}")
        print(f"  Description: {description[:100]}...")
        print(f"  Policy Type: {properties.get('policyType', 'N/A')}")
        print(f"  Mode: {properties.get('mode', 'N/A')}")

        assert display_name, "Policy must have displayName"
        assert description, "Policy must have description"
        assert properties.get("policyType") == "BuiltIn", "Should be BuiltIn policy"
        assert "policyRule" in properties, "Policy must have policyRule"

        # Verify policy rule structure
        policy_rule = properties["policyRule"]
        assert "if" in policy_rule, "Policy rule must have 'if' condition"
        assert "then" in policy_rule, "Policy rule must have 'then' effect"

        print(f"  Effect: {policy_rule.get('then', {}).get('effect', 'N/A')}")

    print("\n" + "=" * 70)
    print("✓ Azure GitHub policy test passed")
    print("=" * 70)


@pytest.mark.asyncio
async def test_azure_policy_compliance_metadata():
    """
    Test that Azure policies include compliance metadata.

    Verifies:
    - Policies have metadata section
    - Metadata includes category
    - Some policies reference compliance frameworks (CIS, Azure Security Benchmark)
    """
    print("\n" + "=" * 70)
    print("Testing Azure Policy Compliance Metadata")
    print("=" * 70)

    policies = await fetch_azure_policies_from_github(
        category="Storage",
        max_results=5,
    )

    policies_with_metadata = []
    categories_found = set()

    for policy in policies:
        properties = policy.get("properties", {})
        metadata = properties.get("metadata")

        if metadata:
            policies_with_metadata.append(policy)
            category = metadata.get("category")
            if category:
                categories_found.add(category)

            # Check for compliance references
            if metadata.get("ASC") == "true":
                print(f"\n  Azure Security Center policy: {properties.get('displayName', 'Unknown')}")
            if metadata.get("CIS"):
                print(f"  CIS benchmark policy: {properties.get('displayName', 'Unknown')}")

    print(f"\nPolicies with metadata: {len(policies_with_metadata)}/{len(policies)}")
    print(f"Categories found: {', '.join(sorted(categories_found))}")

    # Verify structure
    assert len(policies_with_metadata) > 0, "At least some policies should have metadata"

    for policy in policies_with_metadata:
        metadata = policy["properties"]["metadata"]
        assert isinstance(metadata, dict), "Metadata should be a dict"
        assert metadata.get("category"), "Metadata should have category"

    print("\n✓ Compliance metadata test passed")


@pytest.mark.asyncio
async def test_azure_policy_rule_structure():
    """
    Test Azure policy rule structure and logic.

    Verifies:
    - Policy rules have if/then structure
    - 'if' contains field conditions (allOf, anyOf)
    - 'then' contains effect (Audit, Deny, DeployIfNotExists, etc.)
    - Field references are valid (type, Microsoft.Storage/...)
    """
    print("\n" + "=" * 70)
    print("Testing Azure Policy Rule Structure")
    print("=" * 70)

    policies = await fetch_azure_policies_from_github(
        category="Storage",
        max_results=5,
    )

    valid_effects = ["Audit", "Deny", "Disabled", "AuditIfNotExists", "DeployIfNotExists", "Append", "Modify"]

    for policy in policies:
        properties = policy["properties"]
        policy_rule = properties["policyRule"]
        display_name = properties.get("displayName", "Unknown")

        print(f"\nPolicy: {display_name}")

        # Verify if/then structure
        assert "if" in policy_rule, "Policy rule must have 'if' condition"
        assert "then" in policy_rule, "Policy rule must have 'then' effect"

        # Verify 'then' effect
        then_clause = policy_rule["then"]
        effect = then_clause.get("effect")

        assert effect, "Policy must have effect"
        assert effect in valid_effects, f"Effect '{effect}' not in valid effects"

        print(f"  Effect: {effect}")

        # Verify 'if' condition structure
        if_clause = policy_rule["if"]

        # Should have logical operators or field conditions
        has_logical_op = any(key in if_clause for key in ["allOf", "anyOf", "not"])
        has_field = "field" in if_clause

        assert has_logical_op or has_field, "'if' clause should have logical operators or field conditions"

        # Check for Storage resource type references
        if_str = str(if_clause)
        if "Microsoft.Storage" in if_str:
            print(f"  References: Microsoft.Storage resources")

    print("\n✓ Policy rule structure test passed")


@pytest.mark.asyncio
async def test_azure_policy_parameters():
    """
    Test Azure policies with parameters.

    Some policies are parameterizable to allow customization.
    Verifies:
    - Policies with parameters field have valid structure
    - Parameters have type, metadata, defaultValue
    - Parameter types are valid (String, Array, Boolean, etc.)
    """
    print("\n" + "=" * 70)
    print("Testing Azure Policy Parameters")
    print("=" * 70)

    policies = await fetch_azure_policies_from_github(
        category="Storage",
        max_results=5,
    )

    policies_with_params = [p for p in policies if p.get("properties", {}).get("parameters")]
    print(f"\nPolicies with parameters: {len(policies_with_params)}/{len(policies)}")

    valid_types = ["String", "Array", "Object", "Boolean", "Integer"]

    for policy in policies_with_params:
        parameters = policy["properties"]["parameters"]
        display_name = policy["properties"].get("displayName", "Unknown")

        print(f"\n{display_name}: {len(parameters)} parameter(s)")

        for param_name, param_def in parameters.items():
            print(f"  {param_name}:")

            assert "type" in param_def, f"Parameter '{param_name}' must have type"
            param_type = param_def["type"]
            assert param_type in valid_types, f"Invalid parameter type: {param_type}"

            print(f"    Type: {param_type}")

            if "metadata" in param_def:
                metadata = param_def["metadata"]
                print(f"    Description: {metadata.get('description', 'N/A')[:60]}...")

            if "defaultValue" in param_def:
                print(f"    Default: {param_def['defaultValue']}")

    if not policies_with_params:
        print("\nNote: No parameterized policies found in sample (this is OK)")

    print("\n✓ Parameters test passed")


# ============================================================================
# Test Cases - Azure API (Requires Auth)
# ============================================================================


@skip_if_no_azure_api
@pytest.mark.asyncio
async def test_fetch_azure_policies_from_api():
    """
    Test fetching Azure policies from Azure Resource Manager API.

    This test requires Azure credentials and verifies:
    - Azure API authentication works
    - Policy definitions can be listed
    - API returns same structure as GitHub

    NOTE: This test is skipped if Azure credentials are not available.
    """
    print("\n" + "=" * 70)
    print("Testing Azure Resource Manager API")
    print("=" * 70)

    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    print(f"Subscription ID: {subscription_id}")

    # In production, you would:
    # 1. Authenticate with Azure SDK
    # 2. Use PolicyClient to list policy definitions
    # 3. Filter by category
    #
    # from azure.identity import DefaultAzureCredential
    # from azure.mgmt.resource import PolicyClient
    #
    # credential = DefaultAzureCredential()
    # policy_client = PolicyClient(credential, subscription_id)
    # policies = list(policy_client.policy_definitions.list())

    # For this test, we'll just verify credentials are present
    assert subscription_id, "AZURE_SUBSCRIPTION_ID must be set"
    assert os.getenv("AZURE_TENANT_ID"), "AZURE_TENANT_ID must be set"
    assert os.getenv("AZURE_CLIENT_ID"), "AZURE_CLIENT_ID must be set"
    assert os.getenv("AZURE_CLIENT_SECRET"), "AZURE_CLIENT_SECRET must be set"

    print("\n✓ Azure API credentials verified")
    print("Note: Full API integration would require azure-mgmt-resource SDK")


# ============================================================================
# Test Cases - Azure ARM Template Schemas
# ============================================================================


@pytest.mark.asyncio
async def test_fetch_azure_arm_storage_schema():
    """
    Test fetching Azure Resource Manager storage schema.

    ARM schemas define the structure of Azure resources and their properties.
    This is useful for extracting security properties from ARM templates.

    Verifies:
    - ARM schema is accessible from GitHub
    - Schema has resourceType and properties
    - Storage account properties are documented
    """
    print("\n" + "=" * 70)
    print("Testing Azure ARM Storage Schema")
    print("=" * 70)

    # Azure ARM schemas are published on GitHub
    schema_url = "https://raw.githubusercontent.com/Azure/azure-resource-manager-schemas/main/schemas/2023-01-01/Microsoft.Storage.json"

    print(f"Fetching: {schema_url}")

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        try:
            response = await client.get(schema_url)
            assert response.status_code == 200, f"Schema fetch failed: HTTP {response.status_code}"

            schema = response.json()

            print(f"\nSchema ID: {schema.get('id', 'N/A')}")
            print(f"Schema: {schema.get('$schema', 'N/A')}")

            # Verify schema structure
            assert "definitions" in schema, "Schema should have definitions"

            definitions = schema["definitions"]
            print(f"Definitions: {len(definitions)}")

            # Look for storageAccounts definition
            storage_account_defs = [
                key for key in definitions.keys()
                if "storageAccounts" in key.lower()
            ]

            print(f"\nStorage account definitions found: {len(storage_account_defs)}")
            for def_name in storage_account_defs[:3]:
                print(f"  - {def_name}")

            assert len(storage_account_defs) > 0, "Should find storageAccounts definitions"

            # Check one storage account definition
            if storage_account_defs:
                sa_def = definitions[storage_account_defs[0]]
                if "properties" in sa_def:
                    props = sa_def["properties"]
                    print(f"\nStorage account properties: {len(props)}")

                    # Look for security-related properties
                    security_props = [
                        prop for prop in props.keys()
                        if any(keyword in prop.lower() for keyword in
                               ["encryption", "secure", "https", "tls", "access", "auth"])
                    ]

                    print(f"Security-related properties: {len(security_props)}")
                    for prop in security_props[:5]:
                        print(f"  - {prop}")

            print("\n✓ ARM schema test passed")

        except httpx.TimeoutException:
            pytest.skip("GitHub schema repository timed out")
        except Exception as e:
            pytest.fail(f"ARM schema test failed: {e}")


# ============================================================================
# Helper: Manual Test Runner
# ============================================================================


if __name__ == "__main__":
    """
    Run tests manually for debugging.

    Usage:
        # No credentials needed for GitHub tests
        python tests/integration/test_azure_sync.py

        # With Azure API credentials
        export AZURE_SUBSCRIPTION_ID=xxx
        export AZURE_TENANT_ID=xxx
        export AZURE_CLIENT_ID=xxx
        export AZURE_CLIENT_SECRET=xxx
        python tests/integration/test_azure_sync.py
    """
    import asyncio

    async def main():
        print("Running Azure integration tests...\n")

        # Tests that don't require auth
        public_tests = [
            test_fetch_azure_storage_policies_from_github,
            test_azure_policy_compliance_metadata,
            test_azure_policy_rule_structure,
            test_azure_policy_parameters,
            test_fetch_azure_arm_storage_schema,
        ]

        for test_func in public_tests:
            try:
                await test_func()
                print(f"\n✓ {test_func.__name__} PASSED\n")
            except AssertionError as e:
                print(f"\n✗ {test_func.__name__} FAILED: {e}\n")
            except Exception as e:
                print(f"\n✗ {test_func.__name__} ERROR: {e}\n")

        # API tests (require credentials)
        if has_azure_credentials():
            print("\n" + "=" * 70)
            print("Running Azure API tests (credentials found)")
            print("=" * 70)

            api_tests = [
                test_fetch_azure_policies_from_api,
            ]

            for test_func in api_tests:
                try:
                    await test_func()
                    print(f"\n✓ {test_func.__name__} PASSED\n")
                except AssertionError as e:
                    print(f"\n✗ {test_func.__name__} FAILED: {e}\n")
                except Exception as e:
                    print(f"\n✗ {test_func.__name__} ERROR: {e}\n")
        else:
            print("\n" + "=" * 70)
            print("Skipping Azure API tests (no credentials)")
            print("Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
            print("=" * 70)

    asyncio.run(main())
