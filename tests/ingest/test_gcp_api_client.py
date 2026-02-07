"""Tests for GCP Organization Policy API client."""

from unittest.mock import MagicMock, patch

import pytest
from google.api_core.exceptions import GoogleAPIError, PermissionDenied


class TestGCPOrgPolicyClient:
    """Test GCPOrgPolicyClient initialization and methods."""

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_init_with_credentials_path(self, mock_client_class):
        """Test client initialization with credentials file."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        with patch.dict("os.environ", {}, clear=True):
            client = GCPOrgPolicyClient(
                organization_id="123456789012",
                credentials_path="/path/to/credentials.json",
            )

            assert client.organization_id == "123456789012"
            assert client.parent == "organizations/123456789012"
            mock_client_class.assert_called_once()

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_init_without_credentials_path(self, mock_client_class):
        """Test client initialization using default credentials."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        client = GCPOrgPolicyClient(organization_id="123456789012")

        assert client.organization_id == "123456789012"
        assert client.parent == "organizations/123456789012"
        mock_client_class.assert_called_once()

    def test_init_without_organization_id(self):
        """Test that initialization fails without organization_id."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        with pytest.raises(ValueError) as exc_info:
            GCPOrgPolicyClient(organization_id="")

        assert "organization_id is required" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            GCPOrgPolicyClient(organization_id=None)

        assert "organization_id is required" in str(exc_info.value)

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_with_service_filter(self, mock_client_class):
        """Test fetching constraints filtered by service."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Create mock constraint objects
        mock_constraint_1 = MagicMock()
        mock_constraint_1.name = "organizations/123/customConstraints/custom.storage.publicAccessPrevention"
        mock_constraint_1.display_name = "Enforce public access prevention"
        mock_constraint_1.description = "This constraint enforces public access prevention on buckets"
        mock_constraint_1.condition = "resource.bucket.iamConfiguration.publicAccessPrevention == 'enforced'"
        mock_constraint_1.action_type.name = "DENY"
        mock_constraint_1.method_types = [MagicMock(name="CREATE"), MagicMock(name="UPDATE")]
        mock_constraint_1.resource_types = ["storage.googleapis.com/Bucket"]
        mock_constraint_1.update_time = None

        mock_constraint_2 = MagicMock()
        mock_constraint_2.name = "organizations/123/customConstraints/custom.storage.encryption"
        mock_constraint_2.display_name = "Require encryption at rest"
        mock_constraint_2.description = "This constraint requires encryption at rest"
        mock_constraint_2.condition = "resource.bucket.encryption != null"
        mock_constraint_2.action_type.name = "DENY"
        mock_constraint_2.method_types = [MagicMock(name="CREATE")]
        mock_constraint_2.resource_types = ["storage.googleapis.com/Bucket"]
        mock_constraint_2.update_time = None

        mock_constraint_3 = MagicMock()
        mock_constraint_3.name = "organizations/123/customConstraints/custom.compute.publicIp"
        mock_constraint_3.display_name = "Restrict public IPs"
        mock_constraint_3.description = "This constraint restricts public IPs on VMs"
        mock_constraint_3.condition = "resource.instance.networkInterfaces.accessConfigs == []"
        mock_constraint_3.action_type.name = "DENY"
        mock_constraint_3.method_types = [MagicMock(name="CREATE")]
        mock_constraint_3.resource_types = ["compute.googleapis.com/Instance"]
        mock_constraint_3.update_time = None

        # Mock list_custom_constraints to return the constraints
        mock_client.list_custom_constraints.return_value = [
            mock_constraint_1,
            mock_constraint_2,
            mock_constraint_3,
        ]

        client = GCPOrgPolicyClient(organization_id="123456789012")

        # Test with storage filter
        result = client.list_constraints(service_prefix="storage.googleapis.com")

        assert len(result) == 2
        assert all(
            any("storage.googleapis.com" in rt for rt in constraint["resource_types"])
            for constraint in result
        )
        assert result[0]["name"] == "organizations/123/customConstraints/custom.storage.publicAccessPrevention"
        assert result[0]["display_name"] == "Enforce public access prevention"
        assert result[0]["action_type"] == "DENY"
        assert result[0]["method_types"] == ["CREATE", "UPDATE"]
        assert result[1]["name"] == "organizations/123/customConstraints/custom.storage.encryption"

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_without_filter(self, mock_client_class):
        """Test fetching all constraints without service filter."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_constraint_1 = MagicMock()
        mock_constraint_1.name = "organizations/123/customConstraints/custom.storage.test"
        mock_constraint_1.display_name = "Storage constraint"
        mock_constraint_1.description = "Storage description"
        mock_constraint_1.condition = "test_condition"
        mock_constraint_1.action_type.name = "DENY"
        mock_constraint_1.method_types = [MagicMock(name="CREATE")]
        mock_constraint_1.resource_types = ["storage.googleapis.com/Bucket"]
        mock_constraint_1.update_time = None

        mock_constraint_2 = MagicMock()
        mock_constraint_2.name = "organizations/123/customConstraints/custom.compute.test"
        mock_constraint_2.display_name = "Compute constraint"
        mock_constraint_2.description = "Compute description"
        mock_constraint_2.condition = "test_condition"
        mock_constraint_2.action_type.name = "DENY"
        mock_constraint_2.method_types = [MagicMock(name="CREATE")]
        mock_constraint_2.resource_types = ["compute.googleapis.com/Instance"]
        mock_constraint_2.update_time = None

        mock_client.list_custom_constraints.return_value = [
            mock_constraint_1,
            mock_constraint_2,
        ]

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_constraints()

        assert len(result) == 2
        assert result[0]["display_name"] == "Storage constraint"
        assert result[1]["display_name"] == "Compute constraint"

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_with_update_time(self, mock_client_class):
        """Test constraint serialization with update_time."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient
        from datetime import datetime, timezone

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Create mock timestamp
        mock_timestamp = MagicMock()
        mock_timestamp.isoformat.return_value = "2024-01-15T10:30:00Z"

        mock_constraint = MagicMock()
        mock_constraint.name = "organizations/123/customConstraints/custom.test"
        mock_constraint.display_name = "Test constraint"
        mock_constraint.description = "Test description"
        mock_constraint.condition = "test_condition"
        mock_constraint.action_type.name = "ALLOW"
        mock_constraint.method_types = [MagicMock(name="UPDATE")]
        mock_constraint.resource_types = ["storage.googleapis.com/Bucket"]
        mock_constraint.update_time = mock_timestamp

        mock_client.list_custom_constraints.return_value = [mock_constraint]

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_constraints()

        assert len(result) == 1
        assert result[0]["update_time"] == "2024-01-15T10:30:00Z"

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_empty_response(self, mock_client_class):
        """Test handling of empty constraint list."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_client.list_custom_constraints.return_value = []

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_constraints()

        assert result == []

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_permission_denied(self, mock_client_class):
        """Test handling of permission denied error."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_client.list_custom_constraints.side_effect = PermissionDenied(
            "Permission denied on resource"
        )

        client = GCPOrgPolicyClient(organization_id="123456789012")

        with pytest.raises(PermissionDenied) as exc_info:
            client.list_constraints()

        assert "Permission denied" in str(exc_info.value)

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_api_error(self, mock_client_class):
        """Test handling of generic API error."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_client.list_custom_constraints.side_effect = GoogleAPIError(
            "API error occurred"
        )

        client = GCPOrgPolicyClient(organization_id="123456789012")

        with pytest.raises(GoogleAPIError) as exc_info:
            client.list_constraints()

        assert "API error occurred" in str(exc_info.value)

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_generic_exception(self, mock_client_class):
        """Test handling of generic exception."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_client.list_custom_constraints.side_effect = Exception(
            "Unexpected error"
        )

        client = GCPOrgPolicyClient(organization_id="123456789012")

        with pytest.raises(Exception) as exc_info:
            client.list_constraints()

        assert "Unexpected error" in str(exc_info.value)

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_multiple_method_types(self, mock_client_class):
        """Test constraint with multiple method types."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_constraint = MagicMock()
        mock_constraint.name = "organizations/123/customConstraints/custom.test"
        mock_constraint.display_name = "Test constraint"
        mock_constraint.description = "Test description"
        mock_constraint.condition = "test_condition"
        mock_constraint.action_type.name = "DENY"
        mock_constraint.method_types = [
            MagicMock(name="CREATE"),
            MagicMock(name="UPDATE"),
            MagicMock(name="DELETE"),
        ]
        mock_constraint.resource_types = ["storage.googleapis.com/Bucket"]
        mock_constraint.update_time = None

        mock_client.list_custom_constraints.return_value = [mock_constraint]

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_constraints()

        assert len(result) == 1
        assert result[0]["method_types"] == ["CREATE", "UPDATE", "DELETE"]

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_multiple_resource_types(self, mock_client_class):
        """Test constraint with multiple resource types."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_constraint = MagicMock()
        mock_constraint.name = "organizations/123/customConstraints/custom.test"
        mock_constraint.display_name = "Test constraint"
        mock_constraint.description = "Test description"
        mock_constraint.condition = "test_condition"
        mock_constraint.action_type.name = "DENY"
        mock_constraint.method_types = [MagicMock(name="CREATE")]
        mock_constraint.resource_types = [
            "storage.googleapis.com/Bucket",
            "storage.googleapis.com/Object",
        ]
        mock_constraint.update_time = None

        mock_client.list_custom_constraints.return_value = [mock_constraint]

        client = GCPOrgPolicyClient(organization_id="123456789012")

        # Test with service filter that matches multiple resource types
        result = client.list_constraints(service_prefix="storage.googleapis.com")

        assert len(result) == 1
        assert len(result[0]["resource_types"]) == 2
        assert "storage.googleapis.com/Bucket" in result[0]["resource_types"]
        assert "storage.googleapis.com/Object" in result[0]["resource_types"]

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_built_in_constraints_not_implemented(self, mock_client_class):
        """Test that list_built_in_constraints returns empty list with warning."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_built_in_constraints()

        assert result == []

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_built_in_constraints_with_service_prefix(self, mock_client_class):
        """Test list_built_in_constraints with service prefix still returns empty."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_built_in_constraints(
            service_prefix="storage.googleapis.com"
        )

        assert result == []

    @patch("cve_mcp.ingest.gcp_api_client.orgpolicy_v2.OrgPolicyClient")
    def test_list_constraints_allow_action_type(self, mock_client_class):
        """Test constraint with ALLOW action type."""
        from cve_mcp.ingest.gcp_api_client import GCPOrgPolicyClient

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_constraint = MagicMock()
        mock_constraint.name = "organizations/123/customConstraints/custom.allow.test"
        mock_constraint.display_name = "Allow constraint"
        mock_constraint.description = "This constraint allows specific actions"
        mock_constraint.condition = "test_condition"
        mock_constraint.action_type.name = "ALLOW"
        mock_constraint.method_types = [MagicMock(name="CREATE")]
        mock_constraint.resource_types = ["compute.googleapis.com/Instance"]
        mock_constraint.update_time = None

        mock_client.list_custom_constraints.return_value = [mock_constraint]

        client = GCPOrgPolicyClient(organization_id="123456789012")

        result = client.list_constraints()

        assert len(result) == 1
        assert result[0]["action_type"] == "ALLOW"


class TestGetGCPClient:
    """Test get_gcp_client factory function."""

    @patch("cve_mcp.ingest.gcp_api_client.GCPOrgPolicyClient")
    def test_get_gcp_client_with_credentials(self, mock_client_class):
        """Test factory function with credentials path."""
        from cve_mcp.ingest.gcp_api_client import get_gcp_client

        get_gcp_client(
            organization_id="123456789012",
            credentials_path="/path/to/credentials.json",
        )

        mock_client_class.assert_called_once_with(
            organization_id="123456789012",
            credentials_path="/path/to/credentials.json",
        )

    @patch("cve_mcp.ingest.gcp_api_client.GCPOrgPolicyClient")
    def test_get_gcp_client_without_credentials(self, mock_client_class):
        """Test factory function without credentials path."""
        from cve_mcp.ingest.gcp_api_client import get_gcp_client

        get_gcp_client(organization_id="123456789012")

        mock_client_class.assert_called_once_with(
            organization_id="123456789012",
            credentials_path=None,
        )

    def test_get_gcp_client_raises_on_empty_org_id(self):
        """Test factory function raises ValueError for empty organization_id."""
        from cve_mcp.ingest.gcp_api_client import get_gcp_client

        with pytest.raises(ValueError) as exc_info:
            get_gcp_client(organization_id="")

        assert "organization_id is required" in str(exc_info.value)
