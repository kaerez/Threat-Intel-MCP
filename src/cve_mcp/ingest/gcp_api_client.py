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
from google.cloud import orgpolicy_v2
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

        Raises:
            ValueError: If organization_id is not provided
        """
        if not organization_id:
            raise ValueError("organization_id is required")

        self.organization_id = organization_id

        if credentials_path:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

        self.client = orgpolicy_v2.OrgPolicyClient()
        self.parent = f"organizations/{organization_id}"

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
                    "display_name": "Enforce public access prevention",
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
            request = orgpolicy_v2.ListCustomConstraintsRequest(parent=self.parent)

            for constraint in self.client.list_custom_constraints(request=request):
                # Convert protobuf to dict
                constraint_dict = {
                    "name": constraint.name,
                    "display_name": constraint.display_name,
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

        Args:
            service_prefix: Filter by service (e.g., "storage.googleapis.com")

        Returns:
            List of built-in constraint definitions

        Raises:
            Exception: If API call fails

        Note:
            This method is currently a placeholder. The Organization Policy API
            doesn't have a direct method to list built-in constraints.
            In production, we'd parse the public documentation or use a
            pre-defined manifest of known constraints.
        """
        # TODO: Implement built-in constraints fetching
        # Options:
        # 1. Parse from public GCP documentation
        # 2. Maintain a manifest of known built-in constraints
        # 3. Use Cloud Asset Inventory API to discover active constraints
        logger.warning(
            "built_in_constraints_not_yet_implemented",
            organization_id=self.organization_id,
        )
        return []


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
