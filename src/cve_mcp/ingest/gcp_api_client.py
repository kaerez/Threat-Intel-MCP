"""GCP API client for Organization Policy.

This client provides production-ready integration with GCP Organization Policy API
to fetch constraint definitions for cloud services like Cloud Storage, Compute Engine, etc.

Quality-first design:
- Structured JSON responses from Organization Policy API (0.95 confidence)
- Support for both custom and built-in constraints
- Service account authentication with proper error handling
"""

import os
import structlog
from google.cloud.orgpolicy_v2 import OrgPolicyClient
from google.cloud.orgpolicy_v2.types import ListCustomConstraintsRequest
from typing import Any

logger = structlog.get_logger(__name__)


class GCPOrgPolicyClient:
    """Client for GCP Organization Policy API."""

    def __init__(
        self, organization_id: str, credentials_path: str | None = None
    ):
        """
        Initialize GCP client.

        Args:
            organization_id: GCP organization ID (e.g., "123456789012")
            credentials_path: Path to service account JSON key file

        Note:
            If credentials_path is not provided, the client will use the default
            credentials from GOOGLE_APPLICATION_CREDENTIALS environment variable
            or Application Default Credentials (ADC).

            The API client is initialized lazily only when needed (e.g., for
            custom constraints). Built-in constraints do not require API access.

        Raises:
            ValueError: If organization_id is not provided
        """
        if not organization_id:
            raise ValueError("organization_id is required")

        self.organization_id = organization_id
        self.credentials_path = credentials_path
        self._client = None  # Lazy-loaded
        self.parent = f"organizations/{organization_id}"

    @property
    def client(self):
        """Lazy-load the OrgPolicyClient only when needed."""
        if self._client is None:
            if self.credentials_path:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials_path
            self._client = OrgPolicyClient()
        return self._client

    def list_constraints(
        self, service_prefix: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Fetch organization policy constraints.

        Constraints define what restrictions can be applied to GCP resources.
        They can be custom (organization-defined) or built-in (Google-provided).

        Args:
            service_prefix: Filter by service (e.g., "storage.googleapis.com",
                          "compute.googleapis.com")

        Returns:
            List of constraint definitions with structure:
                {
                    "name": "organizations/.../customConstraints/custom.storage.publicAccessPrevention",
                    "displayName": "Enforce public access prevention",
                    "description": "This constraint enforces public access prevention...",
                    "condition": "resource.bucket.iamConfiguration.publicAccessPrevention == 'enforced'",
                    "action_type": "DENY",
                    "method_types": ["CREATE", "UPDATE"],
                    "resource_types": ["storage.googleapis.com/Bucket"]
                }

        Raises:
            Exception: If API call fails (permission error, network error, etc.)

        Note:
            Custom constraints require orgpolicy.constraints.list permission.
            For built-in constraints, use list_built_in_constraints() instead.
        """
        try:
            constraints = []

            # List custom constraints (organization-defined)
            request = ListCustomConstraintsRequest(parent=self.parent)

            for constraint in self.client.list_custom_constraints(request=request):
                # Convert protobuf to dict
                constraint_dict = {
                    "name": constraint.name,
                    "displayName": constraint.display_name,
                    "description": constraint.description,
                    "condition": constraint.condition,
                    "action_type": constraint.action_type.name,
                    "method_types": [mt.name for mt in constraint.method_types],
                    "resource_types": list(constraint.resource_types),
                    "update_time": (
                        constraint.update_time.isoformat()
                        if constraint.update_time
                        else None
                    ),
                    "constraintType": "CUSTOM",  # Custom constraints don't have a boolean/list distinction in the API
                }

                # Filter by service if specified
                if service_prefix:
                    if not any(
                        service_prefix in rt for rt in constraint.resource_types
                    ):
                        continue

                constraints.append(constraint_dict)

            logger.info(
                "fetched_gcp_org_policy_constraints",
                organization_id=self.organization_id,
                service_prefix=service_prefix,
                count=len(constraints),
            )
            return constraints

        except Exception as e:
            logger.error(
                "failed_to_fetch_gcp_constraints",
                organization_id=self.organization_id,
                service_prefix=service_prefix,
                error=str(e),
                exc_info=True,
            )
            raise

    def list_built_in_constraints(
        self, service_prefix: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Fetch built-in organization policy constraints.

        Built-in constraints are provided by Google and cover common security
        and compliance scenarios (e.g., restrict public IPs, require encryption).

        This method returns GCP's official built-in constraints based on
        public documentation. These constraints are available to all GCP
        organizations without requiring API calls (FREE).

        Args:
            service_prefix: Filter by service (e.g., "storage.googleapis.com")

        Returns:
            List of built-in constraint definitions

        Note:
            This uses a curated manifest of GCP's official built-in constraints
            from https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
        """
        # GCP Official Built-in Constraints (curated from public documentation)
        # Source: https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
        all_constraints = [
            # Storage Constraints
            {
                "name": "constraints/storage.publicAccessPrevention",
                "displayName": "Enforce public access prevention",
                "description": "This constraint enforces public access prevention on Cloud Storage buckets. When enforced, buckets cannot be made publicly accessible via IAM policies or ACLs.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["storage.googleapis.com/Bucket"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/storage/docs/public-access-prevention",
            },
            {
                "name": "constraints/storage.uniformBucketLevelAccess",
                "displayName": "Enforce uniform bucket-level access",
                "description": "This constraint requires uniform bucket-level access to be enabled on Cloud Storage buckets. Uniform bucket-level access disables ACLs for the bucket and uses only IAM for access control.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["storage.googleapis.com/Bucket"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/storage/docs/uniform-bucket-level-access",
            },
            {
                "name": "constraints/storage.restrictAuthTypes",
                "displayName": "Restrict authentication types for Cloud Storage",
                "description": "This constraint restricts which authentication types can be used to access Cloud Storage resources. Can be used to enforce OAuth-only access.",
                "condition": None,
                "action_type": "ALLOW",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["storage.googleapis.com/Bucket"],
                "update_time": None,
                "constraint_type": "LIST",
                "documentation_url": "https://cloud.google.com/storage/docs/authentication",
            },
            {
                "name": "constraints/gcp.restrictNonCmekServices",
                "displayName": "Restrict which services may create resources without CMEK",
                "description": "This list constraint defines the set of Google Cloud services that can be used without customer-managed encryption keys (CMEK). Use this to enforce encryption at rest with customer-managed keys.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE"],
                "resource_types": ["storage.googleapis.com/Bucket", "compute.googleapis.com/Disk"],
                "update_time": None,
                "constraint_type": "LIST",
                "documentation_url": "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-resources",
            },
            {
                "name": "constraints/storage.retentionPolicySeconds",
                "displayName": "Set minimum retention policy duration for Cloud Storage",
                "description": "This constraint sets the minimum retention policy duration (in seconds) for Cloud Storage buckets. Helps ensure compliance with data retention requirements.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["storage.googleapis.com/Bucket"],
                "update_time": None,
                "constraint_type": "LIST",
                "documentation_url": "https://cloud.google.com/storage/docs/bucket-lock",
            },
            # Compute Constraints
            {
                "name": "constraints/compute.disableSerialPortAccess",
                "displayName": "Disable VM serial port access",
                "description": "This constraint disables serial port access to Compute Engine VMs. Serial port access can be a security risk as it provides console access to VMs.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["compute.googleapis.com/Instance"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/compute/docs/instances/interacting-with-serial-console",
            },
            {
                "name": "constraints/compute.requireShieldedVm",
                "displayName": "Require Shielded VM",
                "description": "This constraint requires that Compute Engine VMs use Shielded VM features (Secure Boot, vTPM, integrity monitoring). Shielded VMs protect against rootkits and bootkits.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE"],
                "resource_types": ["compute.googleapis.com/Instance"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",
            },
            {
                "name": "constraints/compute.vmExternalIpAccess",
                "displayName": "Define allowed external IPs for VM instances",
                "description": "This constraint defines which Compute Engine VM instances are allowed to have external IP addresses. Use to enforce network isolation.",
                "condition": None,
                "action_type": "ALLOW",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["compute.googleapis.com/Instance"],
                "update_time": None,
                "constraint_type": "LIST",
                "documentation_url": "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
            },
            {
                "name": "constraints/compute.restrictSharedVpcSubnetworks",
                "displayName": "Restrict Shared VPC subnetworks",
                "description": "This constraint restricts which Shared VPC subnetworks can be used for Compute Engine resources in service projects.",
                "condition": None,
                "action_type": "ALLOW",
                "method_types": ["CREATE"],
                "resource_types": ["compute.googleapis.com/Instance"],
                "update_type": None,
                "constraint_type": "LIST",
                "documentation_url": "https://cloud.google.com/vpc/docs/shared-vpc",
            },
            {
                "name": "constraints/compute.requireOsLogin",
                "displayName": "Require OS Login for VM access",
                "description": "This constraint requires OS Login to be enabled for Compute Engine VMs. OS Login uses IAM to manage SSH access instead of metadata-based keys.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["compute.googleapis.com/Instance"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/compute/docs/oslogin",
            },
            # IAM Constraints
            {
                "name": "constraints/iam.disableServiceAccountKeyCreation",
                "displayName": "Disable service account key creation",
                "description": "This constraint prevents the creation of service account keys. Service account keys are a security risk; use workload identity or short-lived tokens instead.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE"],
                "resource_types": ["iam.googleapis.com/ServiceAccountKey"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/iam/docs/best-practices-service-accounts",
            },
            {
                "name": "constraints/iam.allowedPolicyMemberDomains",
                "displayName": "Restrict IAM policy members by domain",
                "description": "This constraint restricts which domains can be added as members in IAM policies. Use to prevent accidental sharing with external users.",
                "condition": None,
                "action_type": "ALLOW",
                "method_types": ["UPDATE"],
                "resource_types": ["*"],
                "update_time": None,
                "constraint_type": "LIST",
                "documentation_url": "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains",
            },
            {
                "name": "constraints/iam.disableServiceAccountCreation",
                "displayName": "Disable service account creation",
                "description": "This constraint prevents the creation of new service accounts. Use to centralize service account management.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE"],
                "resource_types": ["iam.googleapis.com/ServiceAccount"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/iam/docs/service-accounts",
            },
            # SQL Constraints
            {
                "name": "constraints/sql.restrictPublicIp",
                "displayName": "Restrict public IP on Cloud SQL instances",
                "description": "This constraint prevents Cloud SQL instances from being assigned public IP addresses. Use to enforce private connectivity only.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["sqladmin.googleapis.com/Instance"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/sql/docs/mysql/configure-private-ip",
            },
            {
                "name": "constraints/sql.requireAutomatedBackups",
                "displayName": "Require automated backups for Cloud SQL",
                "description": "This constraint requires automated backups to be enabled for Cloud SQL instances. Ensures data can be recovered in case of failure.",
                "condition": None,
                "action_type": "DENY",
                "method_types": ["CREATE", "UPDATE"],
                "resource_types": ["sqladmin.googleapis.com/Instance"],
                "update_time": None,
                "constraint_type": "BOOLEAN",
                "documentation_url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
            },
        ]

        # Filter by service prefix if specified
        if service_prefix:
            filtered = []
            for constraint in all_constraints:
                if any(
                    service_prefix in rt
                    for rt in constraint.get("resource_types", [])
                ):
                    filtered.append(constraint)
            all_constraints = filtered

        logger.info(
            "fetched_gcp_built_in_constraints",
            organization_id=self.organization_id,
            service_prefix=service_prefix,
            count=len(all_constraints),
            source="curated_manifest",
        )
        return all_constraints


# Factory function
def get_gcp_client(
    organization_id: str, credentials_path: str | None = None
) -> GCPOrgPolicyClient:
    """
    Get GCP Organization Policy client instance.

    Args:
        organization_id: GCP organization ID
        credentials_path: Path to service account JSON key

    Returns:
        Configured GCPOrgPolicyClient instance

    Raises:
        ValueError: If organization_id is not provided
    """
    return GCPOrgPolicyClient(
        organization_id=organization_id, credentials_path=credentials_path
    )
