"""Cloud IAM Security Analyzer - Detect overly permissive roles in AWS and GCP."""

import os
import logging
from typing import Optional
from langchain_core.tools import tool

logger = logging.getLogger(__name__)


@tool
def aws_iam_audit(check_type: str = "all") -> str:
    """Audit AWS IAM for security misconfigurations.

    Args:
        check_type: Type of check - "all", "admin_users", "mfa", "access_keys", "policies".

    Returns:
        List of IAM security issues found (overpermissive policies, missing MFA, stale keys).
    """
    try:
        import boto3
    except ImportError:
        return "boto3 is required: pip install boto3"

    try:
        iam = boto3.client("iam")
        issues = []

        # Check for users with admin access
        if check_type in ("all", "admin_users"):
            users = iam.list_users()["Users"]
            for user in users:
                policies = iam.list_attached_user_policies(UserName=user["UserName"])
                for pol in policies.get("AttachedPolicies", []):
                    if "AdministratorAccess" in pol["PolicyArn"]:
                        issues.append(
                            f"[HIGH] User '{user['UserName']}' has AdministratorAccess attached directly"
                        )

                groups = iam.list_groups_for_user(UserName=user["UserName"])
                for group in groups.get("Groups", []):
                    group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])
                    for pol in group_policies.get("AttachedPolicies", []):
                        if "AdministratorAccess" in pol["PolicyArn"]:
                            issues.append(
                                f"[MEDIUM] User '{user['UserName']}' has admin via group '{group['GroupName']}'"
                            )

        # Check MFA status
        if check_type in ("all", "mfa"):
            users = iam.list_users()["Users"]
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
                if not mfa_devices.get("MFADevices"):
                    issues.append(
                        f"[HIGH] User '{user['UserName']}' does not have MFA enabled"
                    )

        # Check for old access keys
        if check_type in ("all", "access_keys"):
            from datetime import datetime, timezone, timedelta
            users = iam.list_users()["Users"]
            for user in users:
                keys = iam.list_access_keys(UserName=user["UserName"])
                for key in keys.get("AccessKeyMetadata", []):
                    if key["Status"] == "Active":
                        age = datetime.now(timezone.utc) - key["CreateDate"]
                        if age > timedelta(days=90):
                            issues.append(
                                f"[MEDIUM] User '{user['UserName']}' has access key "
                                f"older than 90 days ({age.days} days)"
                            )

        # Check for overly permissive policies
        if check_type in ("all", "policies"):
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local", OnlyAttached=True):
                for policy in page["Policies"]:
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    doc = version["PolicyVersion"]["Document"]
                    statements = doc.get("Statement", [])
                    for stmt in statements:
                        if (
                            stmt.get("Effect") == "Allow"
                            and stmt.get("Action") == "*"
                            and stmt.get("Resource") == "*"
                        ):
                            issues.append(
                                f"[CRITICAL] Policy '{policy['PolicyName']}' grants "
                                f"Allow * on * (full admin)"
                            )

        if not issues:
            return f"AWS IAM audit ({check_type}): No significant issues found."

        header = f"AWS IAM Audit Results: {len(issues)} issues\n{'='*50}\n"
        return header + "\n".join(issues)

    except Exception as e:
        return f"Error auditing AWS IAM: {str(e)}"


@tool
def gcp_iam_audit(project_id: Optional[str] = None) -> str:
    """Audit GCP IAM bindings for overly permissive roles.

    Args:
        project_id: GCP project ID. Falls back to GCP_PROJECT_ID env var.

    Returns:
        List of IAM security issues (primitive roles, external members, service account misuse).
    """
    try:
        from google.cloud import resourcemanager_v3
        from google.iam.v1 import iam_policy_pb2
    except ImportError:
        return "google-cloud-resource-manager is required: pip install google-cloud-resource-manager"

    try:
        proj = project_id or os.getenv("GCP_PROJECT_ID", "")
        if not proj:
            return "Set GCP_PROJECT_ID environment variable."

        client = resourcemanager_v3.ProjectsClient()
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{proj}",
        )
        policy = client.get_iam_policy(request=request)

        issues = []
        primitive_roles = ["roles/owner", "roles/editor"]
        sensitive_roles = [
            "roles/iam.securityAdmin",
            "roles/iam.serviceAccountAdmin",
            "roles/iam.serviceAccountKeyAdmin",
        ]

        for binding in policy.bindings:
            role = binding.role

            # Primitive roles (owner/editor)
            if role in primitive_roles:
                for member in binding.members:
                    if not member.startswith("serviceAccount:"):
                        issues.append(
                            f"[HIGH] '{member}' has primitive role '{role}' "
                            f"(use custom roles instead)"
                        )

            # External users with sensitive roles
            if role in sensitive_roles:
                for member in binding.members:
                    if "gserviceaccount.com" not in member:
                        issues.append(
                            f"[MEDIUM] '{member}' has sensitive role '{role}'"
                        )

            # allUsers or allAuthenticatedUsers
            for member in binding.members:
                if member in ("allUsers", "allAuthenticatedUsers"):
                    issues.append(
                        f"[CRITICAL] Public access granted via '{member}' for role '{role}'"
                    )

            # Service accounts with owner/editor
            if role in primitive_roles:
                for member in binding.members:
                    if member.startswith("serviceAccount:") and "compute@developer" not in member:
                        issues.append(
                            f"[HIGH] Service account '{member}' has primitive role '{role}'"
                        )

        if not issues:
            return f"GCP IAM audit for project '{proj}': No significant issues found."

        header = f"GCP IAM Audit [{proj}]: {len(issues)} issues\n{'='*50}\n"
        return header + "\n".join(issues)

    except Exception as e:
        return f"Error auditing GCP IAM: {str(e)}"


@tool
def cloud_iam_comparison() -> str:
    """Run IAM audit on both AWS and GCP and provide a combined security posture summary.

    Returns:
        Combined IAM security findings from both AWS and GCP with prioritized recommendations.
    """
    results = []

    # AWS audit
    results.append("=" * 60)
    results.append("AWS IAM AUDIT")
    results.append("=" * 60)
    aws_result = aws_iam_audit.invoke({"check_type": "all"})
    results.append(aws_result)

    # GCP audit
    results.append("\n" + "=" * 60)
    results.append("GCP IAM AUDIT")
    results.append("=" * 60)
    gcp_result = gcp_iam_audit.invoke({})
    results.append(gcp_result)

    # Summary
    results.append("\n" + "=" * 60)
    results.append("RECOMMENDATIONS")
    results.append("=" * 60)
    results.append("1. Replace primitive/broad roles with least-privilege custom roles")
    results.append("2. Enable MFA for all human users (AWS) and enforce 2FA (GCP)")
    results.append("3. Rotate access keys older than 90 days")
    results.append("4. Remove public access bindings (allUsers/allAuthenticatedUsers)")
    results.append("5. Use workload identity (GKE) or IRSA (EKS) instead of static keys")

    return "\n".join(results)
