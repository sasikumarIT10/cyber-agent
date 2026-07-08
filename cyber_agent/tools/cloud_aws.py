"""AWS Security Tools - GuardDuty findings and threat intelligence."""

import os
import logging
from typing import Optional
from langchain_core.tools import tool

logger = logging.getLogger(__name__)


def _get_boto3_client(service: str, region: Optional[str] = None):
    """Create a boto3 client with optional region override."""
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 is required: pip install boto3")

    return boto3.client(
        service,
        region_name=region or os.getenv("AWS_REGION", "us-east-1"),
    )


@tool
def guardduty_list_findings(
    severity_min: float = 4.0,
    max_results: int = 20,
    region: Optional[str] = None,
) -> str:
    """List AWS GuardDuty findings filtered by minimum severity.

    Args:
        severity_min: Minimum severity threshold (0-10). Default 4.0 (medium+).
        max_results: Maximum number of findings to return.
        region: AWS region override.

    Returns:
        Formatted list of GuardDuty findings with severity, type, and affected resources.
    """
    try:
        client = _get_boto3_client("guardduty", region)

        detectors = client.list_detectors()
        if not detectors.get("DetectorIds"):
            return "No GuardDuty detectors found. GuardDuty may not be enabled in this region."

        detector_id = detectors["DetectorIds"][0]

        finding_criteria = {
            "Criterion": {
                "severity": {
                    "Gte": int(severity_min),
                }
            }
        }

        findings_response = client.list_findings(
            DetectorId=detector_id,
            FindingCriteria=finding_criteria,
            MaxResults=max_results,
            SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
        )

        finding_ids = findings_response.get("FindingIds", [])
        if not finding_ids:
            return f"No GuardDuty findings with severity >= {severity_min}."

        details = client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids,
        )

        results = []
        for f in details.get("Findings", []):
            resource = f.get("Resource", {})
            resource_type = resource.get("ResourceType", "Unknown")
            instance_id = ""
            if resource_type == "Instance":
                instance_id = resource.get("InstanceDetails", {}).get("InstanceId", "")

            results.append(
                f"[Severity {f['Severity']}] {f['Type']}\n"
                f"  Title: {f.get('Title', 'N/A')}\n"
                f"  Resource: {resource_type} {instance_id}\n"
                f"  Region: {f.get('Region', 'N/A')}\n"
                f"  First seen: {f.get('CreatedAt', 'N/A')}\n"
                f"  Description: {f.get('Description', 'N/A')[:200]}\n"
            )

        header = f"GuardDuty Findings (severity >= {severity_min}): {len(results)} found\n{'='*60}\n"
        return header + "\n".join(results)

    except Exception as e:
        return f"Error querying GuardDuty: {str(e)}"


@tool
def guardduty_get_threat_intel(
    ip_address: Optional[str] = None,
    domain: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Check if an IP or domain has been flagged in AWS GuardDuty threat intelligence.

    Args:
        ip_address: IP address to check.
        domain: Domain name to check.
        region: AWS region override.

    Returns:
        GuardDuty findings associated with the given IP or domain.
    """
    if not ip_address and not domain:
        return "Provide either ip_address or domain to check."

    try:
        client = _get_boto3_client("guardduty", region)

        detectors = client.list_detectors()
        if not detectors.get("DetectorIds"):
            return "No GuardDuty detectors found."

        detector_id = detectors["DetectorIds"][0]

        criterion = {}
        if ip_address:
            criterion["service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"] = {
                "Eq": [ip_address]
            }
        if domain:
            criterion["service.action.dnsRequestAction.domain"] = {
                "Eq": [domain]
            }

        findings_response = client.list_findings(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": criterion},
            MaxResults=10,
        )

        finding_ids = findings_response.get("FindingIds", [])
        if not finding_ids:
            target = ip_address or domain
            return f"No GuardDuty findings associated with {target}."

        details = client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids,
        )

        results = []
        for f in details.get("Findings", []):
            results.append(
                f"[Severity {f['Severity']}] {f['Type']}\n"
                f"  {f.get('Title', 'N/A')}\n"
                f"  Created: {f.get('CreatedAt', 'N/A')}\n"
            )

        target = ip_address or domain
        header = f"Threat Intel for {target}: {len(results)} findings\n{'='*50}\n"
        return header + "\n".join(results)

    except Exception as e:
        return f"Error checking threat intel: {str(e)}"


@tool
def aws_security_hub_summary(region: Optional[str] = None) -> str:
    """Get a summary of AWS Security Hub findings grouped by severity.

    Args:
        region: AWS region override.

    Returns:
        Summary of Security Hub findings counts by severity and compliance status.
    """
    try:
        client = _get_boto3_client("securityhub", region)

        response = client.get_findings(
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            },
            MaxResults=100,
        )

        findings = response.get("Findings", [])
        if not findings:
            return "No active Security Hub findings."

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in findings:
            sev = f.get("Severity", {}).get("Label", "INFORMATIONAL")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines = [
            f"AWS Security Hub Summary ({len(findings)} active findings)",
            "=" * 50,
        ]
        for sev, count in severity_counts.items():
            if count > 0:
                lines.append(f"  {sev}: {count}")

        critical = [f for f in findings if f.get("Severity", {}).get("Label") == "CRITICAL"]
        if critical:
            lines.append(f"\nTop Critical Findings:")
            for f in critical[:5]:
                lines.append(f"  - {f.get('Title', 'N/A')} ({f.get('ProductName', '')})")

        return "\n".join(lines)

    except Exception as e:
        return f"Error querying Security Hub: {str(e)}"
