"""AWS API client for Security Hub and Config.

This client provides production-ready integration with AWS Security Hub to fetch
real security control definitions for cloud services like S3, RDS, EC2, etc.

Quality-first design:
- Structured JSON responses from Security Hub API (0.95 confidence)
- Pagination support for large result sets
- Error handling with detailed logging
- Optional credential chain for IAM roles
"""

import boto3
import structlog
from typing import Any

logger = structlog.get_logger(__name__)


class AWSSecurityHubClient:
    """Client for AWS Security Hub API."""

    def __init__(
        self,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        region: str = "us-east-1",
    ):
        """
        Initialize AWS client with credentials.

        Args:
            access_key_id: AWS access key ID (optional if using IAM role)
            secret_access_key: AWS secret access key (optional if using IAM role)
            region: AWS region for Security Hub API

        Note:
            If credentials are not provided, boto3 will use the default credential
            chain (environment variables, EC2 instance profile, ECS task role, etc.)
        """
        if access_key_id and secret_access_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=region,
            )
        else:
            # Use default credential chain (EC2 instance profile, etc.)
            self.session = boto3.Session(region_name=region)

        self.securityhub = self.session.client("securityhub")
        self.config = self.session.client("config")
        self.region = region

    def list_security_controls(
        self, service_name: str | None = None, max_results: int = 100
    ) -> list[dict[str, Any]]:
        """
        Fetch Security Hub control definitions.

        Control IDs follow the pattern "{Service}.{Number}" (e.g., "S3.1", "RDS.5").
        We filter by service prefix to get only relevant controls.

        Args:
            service_name: Filter by AWS service (e.g., "s3", "rds", "ec2")
            max_results: Maximum controls to fetch per service

        Returns:
            List of security control definitions with structure:
                {
                    "SecurityControlId": "S3.1",
                    "Title": "S3 Block Public Access setting should be enabled",
                    "Description": "This control checks...",
                    "SeverityRating": "MEDIUM",
                    "ControlStatus": "ENABLED",
                    "RemediationUrl": "https://docs.aws.amazon.com/...",
                    "Parameters": {},
                    ...
                }

        Raises:
            Exception: If API call fails (logged with details)
        """
        try:
            controls = []
            paginator = self.securityhub.get_paginator("list_security_control_definitions")

            for page in paginator.paginate(PaginationConfig={"MaxItems": max_results}):
                for control in page.get("SecurityControlDefinitions", []):
                    # Filter by service if specified
                    if service_name:
                        control_id = control.get("SecurityControlId", "")
                        # S3.1, S3.5, etc. start with service prefix
                        if not control_id.upper().startswith(service_name.upper() + "."):
                            continue

                    controls.append(control)

            logger.info(
                "fetched_security_hub_controls",
                service=service_name,
                count=len(controls),
                region=self.region,
            )
            return controls

        except Exception as e:
            logger.error(
                "failed_to_fetch_security_hub_controls",
                service=service_name,
                error=str(e),
                region=self.region,
                exc_info=True,
            )
            raise

    def get_config_rules(self, prefix: str | None = None) -> list[dict[str, Any]]:
        """
        Fetch AWS Config rules.

        Config rules provide additional security checks that complement Security Hub.
        Many rules have a naming convention like "{service}-{check-name}".

        Args:
            prefix: Filter rules by prefix (e.g., "s3-", "rds-")

        Returns:
            List of Config rules with structure:
                {
                    "ConfigRuleName": "s3-bucket-public-read-prohibited",
                    "ConfigRuleArn": "arn:aws:config:us-east-1:...",
                    "Description": "Checks if S3 buckets allow public read access",
                    "Scope": {...},
                    "Source": {...},
                    ...
                }

        Raises:
            Exception: If API call fails (logged with details)
        """
        try:
            rules = []
            paginator = self.config.get_paginator("describe_config_rules")

            for page in paginator.paginate():
                for rule in page.get("ConfigRules", []):
                    if prefix:
                        rule_name = rule.get("ConfigRuleName", "")
                        if not rule_name.startswith(prefix):
                            continue

                    rules.append(rule)

            logger.info(
                "fetched_config_rules",
                prefix=prefix,
                count=len(rules),
                region=self.region,
            )
            return rules

        except Exception as e:
            logger.error(
                "failed_to_fetch_config_rules",
                prefix=prefix,
                error=str(e),
                region=self.region,
                exc_info=True,
            )
            raise


# Factory function for use in sync tasks
def get_aws_client(
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
    region: str = "us-east-1",
) -> AWSSecurityHubClient:
    """
    Get AWS Security Hub client instance.

    This factory function is used by Celery sync tasks to create client instances
    with credentials from settings.

    Args:
        access_key_id: AWS access key ID (optional)
        secret_access_key: AWS secret access key (optional)
        region: AWS region

    Returns:
        Configured AWSSecurityHubClient instance
    """
    return AWSSecurityHubClient(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        region=region,
    )
