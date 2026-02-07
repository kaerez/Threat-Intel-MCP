"""Tests for Azure Policy API client."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


class TestAzurePolicyClient:
    """Test AzurePolicyClient initialization and methods."""

    def test_init_github_source(self):
        """Test client initialization with GitHub source."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(
            source="github",
            repo_url="https://github.com/Azure/azure-policy",
            branch="master",
        )

        assert client.source == "github"
        assert client.repo_url == "https://github.com/Azure/azure-policy"
        assert client.branch == "master"
        assert client.client_id is None
        assert client.client_secret is None

    def test_init_api_source(self):
        """Test client initialization with Azure API source."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(
            source="api",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
            subscription_id="test_subscription_id",
        )

        assert client.source == "api"
        assert client.client_id == "test_client_id"
        assert client.client_secret == "test_client_secret"
        assert client.tenant_id == "test_tenant_id"
        assert client.subscription_id == "test_subscription_id"

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_github_storage(self):
        """Test fetching Storage policies from GitHub."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(source="github")

        # Mock httpx.AsyncClient
        mock_response_1 = MagicMock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = {
            "name": "secure-transfer-required",
            "properties": {
                "displayName": "Secure transfer should be enabled",
                "policyType": "BuiltIn",
                "description": "This policy ensures secure transfer is enabled",
                "metadata": {"category": "Storage", "version": "2.0.0"},
                "parameters": {},
                "policyRule": {"if": {}, "then": {"effect": "audit"}},
            },
        }

        mock_response_2 = MagicMock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = {
            "name": "storage-network-rules",
            "properties": {
                "displayName": "Storage accounts should restrict network access",
                "policyType": "BuiltIn",
                "description": "This policy restricts network access to storage accounts",
                "metadata": {"category": "Storage", "version": "1.0.0"},
            },
        }

        mock_response_3 = MagicMock()
        mock_response_3.status_code = 200
        mock_response_3.json.return_value = {
            "name": "storage-public-access",
            "properties": {
                "displayName": "Storage account public access should be disallowed",
                "policyType": "BuiltIn",
                "description": "This policy prevents public access",
                "metadata": {"category": "Storage", "version": "1.0.0"},
            },
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # Simulate successful responses for each policy file
            mock_client.get.side_effect = [
                mock_response_1,
                mock_response_2,
                mock_response_3,
            ]

            result = await client.fetch_policy_definitions(category="Storage")

            assert len(result) == 3
            assert result[0]["name"] == "secure-transfer-required"
            assert result[0]["properties"]["displayName"] == "Secure transfer should be enabled"
            assert result[1]["name"] == "storage-network-rules"
            assert result[2]["name"] == "storage-public-access"

            # Verify correct URLs were called
            assert mock_client.get.call_count == 3
            call_args = [call[0][0] for call in mock_client.get.call_args_list]
            assert all("Azure/azure-policy/master/built-in-policies" in url for url in call_args)

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_github_compute(self):
        """Test fetching Compute policies from GitHub."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(source="github")

        mock_response_1 = MagicMock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = {
            "name": "vm-encrypt-temp-disks",
            "properties": {
                "displayName": "VMs should encrypt temp disks",
                "policyType": "BuiltIn",
                "description": "This policy ensures VMs encrypt temp disks",
                "metadata": {"category": "Compute", "version": "1.0.0"},
            },
        }

        mock_response_2 = MagicMock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = {
            "name": "managed-disk-double-encryption",
            "properties": {
                "displayName": "Managed disks should be double encrypted",
                "policyType": "BuiltIn",
                "description": "This policy ensures double encryption",
                "metadata": {"category": "Compute", "version": "1.0.0"},
            },
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            mock_client.get.side_effect = [mock_response_1, mock_response_2]

            result = await client.fetch_policy_definitions(category="Compute")

            assert len(result) == 2
            assert result[0]["name"] == "vm-encrypt-temp-disks"
            assert result[1]["name"] == "managed-disk-double-encryption"

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_github_404_handling(self):
        """Test handling of 404 errors for missing policy files."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(source="github")

        mock_response_success = MagicMock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            "name": "test-policy",
            "properties": {"displayName": "Test Policy"},
        }

        # Mock 404 response
        mock_response_404 = MagicMock()
        mock_response_404.status_code = 404
        mock_response_404.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found",
            request=MagicMock(),
            response=mock_response_404,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # First file succeeds, second 404s, third succeeds
            mock_client.get.side_effect = [
                mock_response_success,
                mock_response_404,
                mock_response_success,
            ]

            result = await client.fetch_policy_definitions(category="Storage")

            # Should skip the 404 and return only successful fetches
            assert len(result) == 2
            assert all(r["name"] == "test-policy" for r in result)

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_github_other_http_error(self):
        """Test handling of non-404 HTTP errors."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(source="github")

        # Mock 500 response
        mock_response_500 = MagicMock()
        mock_response_500.status_code = 500
        mock_response_500.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Internal Server Error",
            request=MagicMock(),
            response=mock_response_500,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            mock_client.get.return_value = mock_response_500

            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.fetch_policy_definitions(category="Storage")

            assert "Internal Server Error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_github_network_error(self):
        """Test handling of network errors."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(source="github")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            mock_client.get.side_effect = httpx.RequestError("Network error")

            with pytest.raises(httpx.RequestError) as exc_info:
                await client.fetch_policy_definitions(category="Storage")

            assert "Network error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_github_empty_category(self):
        """Test fetching policies for unsupported category."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(source="github")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # For unsupported category, no files are attempted
            result = await client.fetch_policy_definitions(category="UnsupportedCategory")

            assert result == []
            mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_api_success(self):
        """Test fetching policies from Azure API."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(
            source="api",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
            subscription_id="test_subscription_id",
        )

        # Mock token response
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {"access_token": "test_access_token"}

        # Mock policy definitions response
        mock_policies_response = MagicMock()
        mock_policies_response.status_code = 200
        mock_policies_response.json.return_value = {
            "value": [
                {
                    "name": "policy-1",
                    "properties": {
                        "displayName": "Policy 1",
                        "policyType": "BuiltIn",
                        "metadata": {"category": "Storage"},
                    },
                },
                {
                    "name": "policy-2",
                    "properties": {
                        "displayName": "Policy 2",
                        "policyType": "BuiltIn",
                        "metadata": {"category": "Storage"},
                    },
                },
            ]
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            # First call for token, second for policies
            mock_client.post.return_value = mock_token_response
            mock_client.get.return_value = mock_policies_response

            result = await client.fetch_policy_definitions(category="Storage")

            assert len(result) == 2
            assert result[0]["name"] == "policy-1"
            assert result[1]["name"] == "policy-2"

            # Verify token request
            mock_client.post.assert_called_once()
            token_url = mock_client.post.call_args[0][0]
            assert "login.microsoftonline.com" in token_url
            assert "test_tenant_id" in token_url

            # Verify policy request
            mock_client.get.assert_called_once()
            policy_url = mock_client.get.call_args[0][0]
            assert "management.azure.com" in policy_url
            headers = mock_client.get.call_args[1]["headers"]
            assert headers["Authorization"] == "Bearer test_access_token"
            params = mock_client.get.call_args[1]["params"]
            assert params["$filter"] == "category eq 'Storage'"

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_api_auth_failure(self):
        """Test handling of authentication failure."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(
            source="api",
            client_id="invalid_client_id",
            client_secret="invalid_secret",
            tenant_id="test_tenant_id",
        )

        # Mock failed token response
        mock_token_response = MagicMock()
        mock_token_response.status_code = 401
        mock_token_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Unauthorized",
            request=MagicMock(),
            response=mock_token_response,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            mock_client.post.return_value = mock_token_response

            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.fetch_policy_definitions(category="Storage")

            assert "Unauthorized" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_api_policies_error(self):
        """Test handling of policy fetch error after successful auth."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(
            source="api",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )

        # Mock successful token response
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {"access_token": "test_access_token"}

        # Mock failed policies response
        mock_policies_response = MagicMock()
        mock_policies_response.status_code = 403
        mock_policies_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Forbidden",
            request=MagicMock(),
            response=mock_policies_response,
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            mock_client.post.return_value = mock_token_response
            mock_client.get.return_value = mock_policies_response

            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.fetch_policy_definitions(category="Storage")

            assert "Forbidden" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fetch_policy_definitions_from_api_empty_response(self):
        """Test handling of empty policy list from API."""
        from cve_mcp.ingest.azure_api_client import AzurePolicyClient

        client = AzurePolicyClient(
            source="api",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )

        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {"access_token": "test_access_token"}

        mock_policies_response = MagicMock()
        mock_policies_response.status_code = 200
        mock_policies_response.json.return_value = {"value": []}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client_class.return_value = mock_client

            mock_client.post.return_value = mock_token_response
            mock_client.get.return_value = mock_policies_response

            result = await client.fetch_policy_definitions(category="Storage")

            assert result == []


class TestGetAzureClient:
    """Test get_azure_client factory function."""

    def test_get_azure_client_github_source(self):
        """Test factory function with GitHub source."""
        from cve_mcp.ingest.azure_api_client import get_azure_client

        client = get_azure_client(
            source="github",
            repo_url="https://github.com/Azure/azure-policy",
            branch="main",
        )

        assert client.source == "github"
        assert client.repo_url == "https://github.com/Azure/azure-policy"
        assert client.branch == "main"

    def test_get_azure_client_api_source(self):
        """Test factory function with API source."""
        from cve_mcp.ingest.azure_api_client import get_azure_client

        client = get_azure_client(
            source="api",
            client_id="test_id",
            client_secret="test_secret",
            tenant_id="test_tenant",
            subscription_id="test_sub",
        )

        assert client.source == "api"
        assert client.client_id == "test_id"
        assert client.client_secret == "test_secret"
        assert client.tenant_id == "test_tenant"
        assert client.subscription_id == "test_sub"

    def test_get_azure_client_defaults(self):
        """Test factory function with default values."""
        from cve_mcp.ingest.azure_api_client import get_azure_client

        client = get_azure_client()

        assert client.source == "github"
        assert client.repo_url == "https://github.com/Azure/azure-policy"
        assert client.branch == "master"
