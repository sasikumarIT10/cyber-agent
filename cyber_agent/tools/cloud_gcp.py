"""GCP Security Tools - Security Command Center findings and asset inventory."""

import os
import logging
from typing import Optional
from langchain_core.tools import tool

logger = logging.getLogger(__name__)


def _get_scc_client():
    """Create a GCP Security Command Center client."""
    try:
        from google.cloud import securitycenter_v1
    except ImportError:
        raise RuntimeError(
            "google-cloud-securitycenter is required: pip install google-cloud-securitycenter"
        )
    return securitycenter_v1.SecurityCenterClient()


@tool
def gcp_scc_list_findings(
    severity: str = "HIGH",
    max_results: int = 20,
    project_id: Optional[str] = None,
) -> str:
    """List GCP Security Command Center findings filtered by severity.

    Args:
        severity: Minimum severity level (CRITICAL, HIGH, MEDIUM, LOW).
        max_results: Maximum number of findings.
        project_id: GCP project ID override.

    Returns:
        Formatted list of SCC findings with category, severity, and resource.
    """
    try:
        client = _get_scc_client()
        org_id = os.getenv("GCP_ORGANIZATION_ID", "")
        proj = project_id or os.getenv("GCP_PROJECT_ID", "")

        if org_id:
            parent = f"organizations/{org_id}/sources/-"
        elif proj:
            parent = f"projects/{proj}/sources/-"
        else:
            return "Set GCP_ORGANIZATION_ID or GCP_PROJECT_ID environment variable."

        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sev_value = severity_map.get(severity.upper(), 3)

        filter_str = f'severity >= "{severity.upper()}" AND state = "ACTIVE"'

        request = {
            "parent": parent,
            "filter": filter_str,
            "page_size": max_results,
            "order_by": "severity desc",
        }

        results = []
        for i, finding_result in enumerate(client.list_findings(request=request)):
            if i >= max_results:
                break
            f = finding_result.finding
            results.append(
                f"[{f.severity.name}] {f.category}\n"
                f"  Resource: {f.resource_name}\n"
                f"  State: {f.state.name}\n"
                f"  Created: {f.create_time}\n"
                f"  Description: {f.description[:200] if f.description else 'N/A'}\n"
            )

        if not results:
            return f"No SCC findings with severity >= {severity}."

        header = f"GCP Security Command Center Findings ({len(results)}):\n{'='*60}\n"
        return header + "\n".join(results)

    except Exception as e:
        return f"Error querying GCP SCC: {str(e)}"


@tool
def gcp_scc_vulnerability_report(project_id: Optional[str] = None) -> str:
    """Generate a vulnerability summary from GCP Security Command Center.

    Args:
        project_id: GCP project ID override.

    Returns:
        Summary of vulnerabilities grouped by severity with remediation guidance.
    """
    try:
        client = _get_scc_client()
        proj = project_id or os.getenv("GCP_PROJECT_ID", "")

        if not proj:
            return "Set GCP_PROJECT_ID environment variable."

        parent = f"projects/{proj}/sources/-"
        filter_str = 'category = "VULNERABILITY" AND state = "ACTIVE"'

        request = {
            "parent": parent,
            "filter": filter_str,
            "page_size": 100,
        }

        severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for finding_result in client.list_findings(request=request):
            f = finding_result.finding
            sev = f.severity.name if f.severity else "LOW"
            if sev in severity_groups:
                severity_groups[sev].append({
                    "category": f.category,
                    "resource": f.resource_name.split("/")[-1] if f.resource_name else "unknown",
                    "description": f.description[:150] if f.description else "",
                })

        lines = ["GCP Vulnerability Report", "=" * 50]
        total = sum(len(v) for v in severity_groups.values())
        lines.append(f"Total active vulnerabilities: {total}\n")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            vulns = severity_groups[sev]
            if vulns:
                lines.append(f"\n{sev} ({len(vulns)}):")
                for v in vulns[:10]:
                    lines.append(f"  - [{v['category']}] {v['resource']}")
                    if v["description"]:
                        lines.append(f"    {v['description']}")

        return "\n".join(lines)

    except Exception as e:
        return f"Error generating vulnerability report: {str(e)}"


@tool
def gcp_asset_inventory(
    asset_type: str = "compute.googleapis.com/Instance",
    project_id: Optional[str] = None,
) -> str:
    """Query GCP Cloud Asset Inventory for resources of a given type.

    Args:
        asset_type: GCP asset type (e.g., compute.googleapis.com/Instance, container.googleapis.com/Cluster).
        project_id: GCP project ID override.

    Returns:
        List of assets with their properties and security-relevant metadata.
    """
    try:
        from google.cloud import asset_v1
    except ImportError:
        return "google-cloud-asset is required: pip install google-cloud-asset"

    try:
        proj = project_id or os.getenv("GCP_PROJECT_ID", "")
        if not proj:
            return "Set GCP_PROJECT_ID environment variable."

        client = asset_v1.AssetServiceClient()
        parent = f"projects/{proj}"

        request = asset_v1.ListAssetsRequest(
            parent=parent,
            asset_types=[asset_type],
            page_size=50,
        )

        results = []
        for asset in client.list_assets(request=request):
            name = asset.name.split("/")[-1] if asset.name else "unknown"
            results.append(
                f"  - {name}\n"
                f"    Type: {asset.asset_type}\n"
                f"    Location: {asset.resource.location if asset.resource else 'N/A'}\n"
                f"    Updated: {asset.update_time}\n"
            )

        if not results:
            return f"No assets found of type: {asset_type}"

        header = f"GCP Asset Inventory ({asset_type}): {len(results)} found\n{'='*60}\n"
        return header + "\n".join(results)

    except Exception as e:
        return f"Error querying asset inventory: {str(e)}"
