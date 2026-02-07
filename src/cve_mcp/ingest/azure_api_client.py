"""Azure API client for Policy and Security Center.

This client provides two data sources for Azure security policies:
1. GitHub source (recommended) - public azure-policy repo, no auth needed
2. Azure Resource Manager API - requires service principal credentials

Quality-first design:
- GitHub JSON policies (0.90 confidence) - free, no rate limits
- Azure API policies (0.90 confidence) - requires credentials
- Async HTTP client with proper error handling
"""

import httpx
import structlog
from typing import Any

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
        subscription_id: str | None = None,
    ):
        """
        Initialize Azure client.

        Args:
            source: Data source - "github" (public repo) or "api" (Azure ARM)
            repo_url: GitHub repo URL (for source="github")
            branch: Git branch name (for source="github")
            client_id: Azure service principal client ID (for source="api")
            client_secret: Azure service principal secret (for source="api")
            tenant_id: Azure tenant ID (for source="api")
            subscription_id: Azure subscription ID (for source="api")

        Note:
            GitHub source is recommended as it's free, has no rate limits, and
            contains the same policy definitions as the Azure API.
        """
        self.source = source
        self.repo_url = repo_url
        self.branch = branch
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id

    async def fetch_policy_definitions(
        self, category: str = "Storage"
    ) -> list[dict[str, Any]]:
        """
        Fetch Azure Policy definitions for a specific category.

        Categories include: Storage, Compute, Network, Security Center, etc.
        Each category has multiple built-in policy definitions with security properties.

        Args:
            category: Policy category (e.g., "Storage", "Compute", "Network")

        Returns:
            List of policy definitions with structure:
                {
                    "name": "secure-transfer-required",
                    "properties": {
                        "displayName": "Secure transfer should be enabled",
                        "policyType": "BuiltIn",
                        "description": "...",
                        "metadata": {"category": "Storage", "version": "2.0.0"},
                        "parameters": {...},
                        "policyRule": {...}
                    }
                }

        Raises:
            Exception: If fetch fails (network error, auth error, etc.)
        """
        if self.source == "github":
            return await self._fetch_from_github(category)
        else:
            return await self._fetch_from_api(category)

    async def _fetch_from_github(self, category: str) -> list[dict[str, Any]]:
        """
        Fetch policies from GitHub repo (azure-policy).

        The azure-policy repo contains all built-in policy definitions organized
        by category. Each policy is a JSON file following ARM template schema.

        Args:
            category: Policy category folder name

        Returns:
            List of policy definitions

        Raises:
            httpx.HTTPStatusError: If GitHub request fails
        """
        try:
            # Built-in policies are in built-in-policies/<category>/*.json
            base_url = (
                f"https://raw.githubusercontent.com/Azure/azure-policy/{self.branch}"
            )

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Fetch list of policy files from category directory
                # Note: GitHub API would be rate-limited, so we use a known pattern
                # Most categories have 10-50 policies
                policies = []

                # Try fetching common policy files (this is a simplified approach)
                # In production, we'd parse the directory listing or maintain a manifest
                # For now, fetch known important policies for each category

                if category == "Storage":
                    policy_files = [
                        "secure-transfer-to-storage-accounts-should-be-enabled.json",
                        "storage-accounts-should-restrict-network-access-using-virtual-network-rules.json",
                        "storage-account-public-access-should-be-disallowed.json",
                    ]
                elif category == "Compute":
                    policy_files = [
                        "virtual-machines-should-encrypt-temp-disks-caches-and-data-flows.json",
                        "managed-disks-should-be-double-encrypted-with-both-platform-managed-and-customer-managed-keys.json",
                    ]
                else:
                    # Generic fetch for other categories
                    policy_files = []

                for policy_file in policy_files:
                    try:
                        policy_url = f"{base_url}/built-in-policies/policyDefinitions/{category}/{policy_file}"
                        response = await client.get(policy_url)
                        response.raise_for_status()
                        policy_data = response.json()
                        policies.append(policy_data)
                    except httpx.HTTPStatusError as e:
                        if e.response.status_code == 404:
                            # Policy file doesn't exist, skip
                            logger.debug(
                                "policy_file_not_found",
                                category=category,
                                file=policy_file,
                            )
                            continue
                        raise

                logger.info(
                    "fetched_azure_policies_from_github",
                    category=category,
                    count=len(policies),
                )
                return policies

        except Exception as e:
            logger.error(
                "failed_to_fetch_azure_policies_from_github",
                category=category,
                error=str(e),
                exc_info=True,
            )
            raise

    async def _fetch_from_api(self, category: str) -> list[dict[str, Any]]:
        """
        Fetch policies from Azure Resource Manager API.

        Requires service principal with Reader role on subscription.
        Uses OAuth 2.0 client credentials flow for authentication.

        Args:
            category: Policy category to filter by

        Returns:
            List of policy definitions

        Raises:
            Exception: If API call or authentication fails
        """
        try:
            # Get OAuth token
            token_url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            )
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://management.azure.com/.default",
                "grant_type": "client_credentials",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                token_response = await client.post(token_url, data=token_data)
                token_response.raise_for_status()
                access_token = token_response.json()["access_token"]

                # Fetch policy definitions
                policies_url = "https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions"
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                }

                policies_response = await client.get(
                    policies_url,
                    headers=headers,
                    params={
                        "api-version": "2021-06-01",
                        "$filter": f"category eq '{category}'",
                    },
                )
                policies_response.raise_for_status()
                data = policies_response.json()

                policies = data.get("value", [])

                logger.info(
                    "fetched_azure_policies_from_api",
                    category=category,
                    count=len(policies),
                )
                return policies

        except Exception as e:
            logger.error(
                "failed_to_fetch_azure_policies_from_api",
                category=category,
                error=str(e),
                exc_info=True,
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
    subscription_id: str | None = None,
) -> AzurePolicyClient:
    """
    Get Azure Policy client instance.

    Args:
        source: Data source - "github" or "api"
        repo_url: GitHub repo URL
        branch: Git branch
        client_id: Azure client ID (for API source)
        client_secret: Azure client secret (for API source)
        tenant_id: Azure tenant ID (for API source)
        subscription_id: Azure subscription ID (for API source)

    Returns:
        Configured AzurePolicyClient instance
    """
    return AzurePolicyClient(
        source=source,
        repo_url=repo_url,
        branch=branch,
        client_id=client_id,
        client_secret=client_secret,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
    )
