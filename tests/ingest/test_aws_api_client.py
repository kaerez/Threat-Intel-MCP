"""Tests for AWS Security Hub and Config API client."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError


class TestAWSSecurityHubClient:
    """Test AWSSecurityHubClient initialization and methods."""

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_init_with_credentials(self, mock_session):
        """Test client initialization with explicit credentials."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance

        client = AWSSecurityHubClient(
            access_key_id="test_key",
            secret_access_key="test_secret",
            region="us-west-2",
        )

        mock_session.assert_called_once_with(
            aws_access_key_id="test_key",
            aws_secret_access_key="test_secret",
            region_name="us-west-2",
        )
        assert client.region == "us-west-2"
        assert client.session == mock_session_instance
        mock_session_instance.client.assert_any_call("securityhub")
        mock_session_instance.client.assert_any_call("config")

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_init_without_credentials(self, mock_session):
        """Test client initialization using default credential chain."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance

        client = AWSSecurityHubClient(region="us-east-1")

        mock_session.assert_called_once_with(region_name="us-east-1")
        assert client.region == "us-east-1"

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_list_security_controls_with_filter(self, mock_session):
        """Test fetching security controls filtered by service."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        # Mock boto3 session and clients
        mock_session_instance = MagicMock()
        mock_securityhub = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_securityhub

        # Mock paginator
        mock_paginator = MagicMock()
        mock_securityhub.get_paginator.return_value = mock_paginator

        # Mock paginated response
        mock_paginator.paginate.return_value = [
            {
                "SecurityControlDefinitions": [
                    {
                        "SecurityControlId": "S3.1",
                        "Title": "S3 Block Public Access setting should be enabled",
                        "Description": "This control checks if S3 buckets have public access blocked",
                        "SeverityRating": "MEDIUM",
                        "ControlStatus": "ENABLED",
                        "RemediationUrl": "https://docs.aws.amazon.com/s3/public-access",
                        "Parameters": {},
                    },
                    {
                        "SecurityControlId": "S3.5",
                        "Title": "S3 buckets should require SSL",
                        "Description": "This control checks if S3 buckets require SSL",
                        "SeverityRating": "MEDIUM",
                        "ControlStatus": "ENABLED",
                        "RemediationUrl": "https://docs.aws.amazon.com/s3/ssl",
                        "Parameters": {},
                    },
                    {
                        "SecurityControlId": "RDS.1",
                        "Title": "RDS snapshots should be private",
                        "Description": "This control checks RDS snapshot access",
                        "SeverityRating": "HIGH",
                        "ControlStatus": "ENABLED",
                        "RemediationUrl": "https://docs.aws.amazon.com/rds/snapshots",
                        "Parameters": {},
                    },
                ]
            }
        ]

        client = AWSSecurityHubClient()
        client.securityhub = mock_securityhub

        # Test with S3 filter
        result = client.list_security_controls(service_name="s3", max_results=100)

        assert len(result) == 2
        assert all(ctrl["SecurityControlId"].startswith("S3.") for ctrl in result)
        assert result[0]["Title"] == "S3 Block Public Access setting should be enabled"
        assert result[1]["SecurityControlId"] == "S3.5"

        mock_securityhub.get_paginator.assert_called_once_with(
            "list_security_control_definitions"
        )
        mock_paginator.paginate.assert_called_once_with(
            PaginationConfig={"MaxItems": 100}
        )

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_list_security_controls_without_filter(self, mock_session):
        """Test fetching all security controls without service filter."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_securityhub = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_securityhub

        mock_paginator = MagicMock()
        mock_securityhub.get_paginator.return_value = mock_paginator

        mock_paginator.paginate.return_value = [
            {
                "SecurityControlDefinitions": [
                    {
                        "SecurityControlId": "S3.1",
                        "Title": "S3 control",
                        "Description": "S3 description",
                        "SeverityRating": "MEDIUM",
                    },
                    {
                        "SecurityControlId": "EC2.1",
                        "Title": "EC2 control",
                        "Description": "EC2 description",
                        "SeverityRating": "HIGH",
                    },
                ]
            }
        ]

        client = AWSSecurityHubClient()
        client.securityhub = mock_securityhub

        result = client.list_security_controls(max_results=100)

        assert len(result) == 2
        assert result[0]["SecurityControlId"] == "S3.1"
        assert result[1]["SecurityControlId"] == "EC2.1"

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_list_security_controls_case_insensitive_filter(self, mock_session):
        """Test that service filter is case-insensitive."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_securityhub = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_securityhub

        mock_paginator = MagicMock()
        mock_securityhub.get_paginator.return_value = mock_paginator

        mock_paginator.paginate.return_value = [
            {
                "SecurityControlDefinitions": [
                    {"SecurityControlId": "S3.1", "Title": "Test"},
                    {"SecurityControlId": "EC2.1", "Title": "Test"},
                ]
            }
        ]

        client = AWSSecurityHubClient()
        client.securityhub = mock_securityhub

        # Test with lowercase filter
        result = client.list_security_controls(service_name="s3")
        assert len(result) == 1
        assert result[0]["SecurityControlId"] == "S3.1"

        # Test with uppercase filter
        mock_paginator.paginate.return_value = [
            {
                "SecurityControlDefinitions": [
                    {"SecurityControlId": "S3.1", "Title": "Test"},
                    {"SecurityControlId": "EC2.1", "Title": "Test"},
                ]
            }
        ]
        result = client.list_security_controls(service_name="S3")
        assert len(result) == 1
        assert result[0]["SecurityControlId"] == "S3.1"

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_list_security_controls_error_handling(self, mock_session):
        """Test error handling in list_security_controls."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_securityhub = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_securityhub

        mock_paginator = MagicMock()
        mock_securityhub.get_paginator.return_value = mock_paginator

        # Mock ClientError
        error_response = {
            "Error": {"Code": "AccessDeniedException", "Message": "Access denied"}
        }
        mock_paginator.paginate.side_effect = ClientError(
            error_response, "ListSecurityControlDefinitions"
        )

        client = AWSSecurityHubClient()
        client.securityhub = mock_securityhub

        with pytest.raises(ClientError) as exc_info:
            client.list_security_controls(service_name="s3")

        assert "AccessDeniedException" in str(exc_info.value)

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_list_security_controls_empty_response(self, mock_session):
        """Test handling of empty response from API."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_securityhub = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_session_instance.client.return_value = mock_securityhub

        mock_paginator = MagicMock()
        mock_securityhub.get_paginator.return_value = mock_paginator

        # Empty response
        mock_paginator.paginate.return_value = [{"SecurityControlDefinitions": []}]

        client = AWSSecurityHubClient()
        client.securityhub = mock_securityhub

        result = client.list_security_controls(service_name="s3")

        assert result == []

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_get_config_rules_with_prefix(self, mock_session):
        """Test fetching Config rules with prefix filter."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_config = MagicMock()
        mock_session.return_value = mock_session_instance

        # Need to handle both securityhub and config client calls
        def client_side_effect(service_name):
            if service_name == "config":
                return mock_config
            return MagicMock()

        mock_session_instance.client.side_effect = client_side_effect

        mock_paginator = MagicMock()
        mock_config.get_paginator.return_value = mock_paginator

        mock_paginator.paginate.return_value = [
            {
                "ConfigRules": [
                    {
                        "ConfigRuleName": "s3-bucket-public-read-prohibited",
                        "ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/test",
                        "Description": "Checks if S3 buckets allow public read access",
                        "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
                    },
                    {
                        "ConfigRuleName": "s3-bucket-ssl-requests-only",
                        "ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/test2",
                        "Description": "Checks if S3 buckets have SSL-only policies",
                        "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
                    },
                    {
                        "ConfigRuleName": "rds-snapshot-encrypted",
                        "ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/test3",
                        "Description": "Checks if RDS snapshots are encrypted",
                        "Scope": {
                            "ComplianceResourceTypes": ["AWS::RDS::DBSnapshot"]
                        },
                    },
                ]
            }
        ]

        client = AWSSecurityHubClient()
        client.config = mock_config

        result = client.get_config_rules(prefix="s3-")

        assert len(result) == 2
        assert all(rule["ConfigRuleName"].startswith("s3-") for rule in result)
        assert result[0]["ConfigRuleName"] == "s3-bucket-public-read-prohibited"
        assert result[1]["ConfigRuleName"] == "s3-bucket-ssl-requests-only"

        mock_config.get_paginator.assert_called_once_with("describe_config_rules")

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_get_config_rules_without_prefix(self, mock_session):
        """Test fetching all Config rules without prefix filter."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_config = MagicMock()
        mock_session.return_value = mock_session_instance

        def client_side_effect(service_name):
            if service_name == "config":
                return mock_config
            return MagicMock()

        mock_session_instance.client.side_effect = client_side_effect

        mock_paginator = MagicMock()
        mock_config.get_paginator.return_value = mock_paginator

        mock_paginator.paginate.return_value = [
            {
                "ConfigRules": [
                    {
                        "ConfigRuleName": "s3-bucket-public-read-prohibited",
                        "Description": "S3 rule",
                    },
                    {
                        "ConfigRuleName": "ec2-instance-managed-by-ssm",
                        "Description": "EC2 rule",
                    },
                ]
            }
        ]

        client = AWSSecurityHubClient()
        client.config = mock_config

        result = client.get_config_rules()

        assert len(result) == 2
        assert result[0]["ConfigRuleName"] == "s3-bucket-public-read-prohibited"
        assert result[1]["ConfigRuleName"] == "ec2-instance-managed-by-ssm"

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_get_config_rules_error_handling(self, mock_session):
        """Test error handling in get_config_rules."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_config = MagicMock()
        mock_session.return_value = mock_session_instance

        def client_side_effect(service_name):
            if service_name == "config":
                return mock_config
            return MagicMock()

        mock_session_instance.client.side_effect = client_side_effect

        mock_paginator = MagicMock()
        mock_config.get_paginator.return_value = mock_paginator

        # Mock ClientError
        error_response = {
            "Error": {
                "Code": "NoSuchConfigRuleException",
                "Message": "Config rule not found",
            }
        }
        mock_paginator.paginate.side_effect = ClientError(
            error_response, "DescribeConfigRules"
        )

        client = AWSSecurityHubClient()
        client.config = mock_config

        with pytest.raises(ClientError) as exc_info:
            client.get_config_rules(prefix="s3-")

        assert "NoSuchConfigRuleException" in str(exc_info.value)

    @patch("cve_mcp.ingest.aws_api_client.boto3.Session")
    def test_get_config_rules_no_credentials_error(self, mock_session):
        """Test handling of missing AWS credentials."""
        from cve_mcp.ingest.aws_api_client import AWSSecurityHubClient

        mock_session_instance = MagicMock()
        mock_config = MagicMock()
        mock_session.return_value = mock_session_instance

        def client_side_effect(service_name):
            if service_name == "config":
                return mock_config
            return MagicMock()

        mock_session_instance.client.side_effect = client_side_effect

        mock_paginator = MagicMock()
        mock_config.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = NoCredentialsError()

        client = AWSSecurityHubClient()
        client.config = mock_config

        with pytest.raises(NoCredentialsError):
            client.get_config_rules()


class TestGetAWSClient:
    """Test get_aws_client factory function."""

    @patch("cve_mcp.ingest.aws_api_client.AWSSecurityHubClient")
    def test_get_aws_client_with_credentials(self, mock_client_class):
        """Test factory function with explicit credentials."""
        from cve_mcp.ingest.aws_api_client import get_aws_client

        get_aws_client(
            access_key_id="test_key",
            secret_access_key="test_secret",
            region="eu-west-1",
        )

        mock_client_class.assert_called_once_with(
            access_key_id="test_key",
            secret_access_key="test_secret",
            region="eu-west-1",
        )

    @patch("cve_mcp.ingest.aws_api_client.AWSSecurityHubClient")
    def test_get_aws_client_default_region(self, mock_client_class):
        """Test factory function with default region."""
        from cve_mcp.ingest.aws_api_client import get_aws_client

        get_aws_client()

        mock_client_class.assert_called_once_with(
            access_key_id=None,
            secret_access_key=None,
            region="us-east-1",
        )
