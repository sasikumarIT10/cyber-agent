"""Cybersecurity tools for the AI Agent."""

from tools.cve_lookup import cve_search, cve_details
from tools.port_scanner import scan_ports
from tools.dns_recon import dns_lookup, reverse_dns, dns_zone_info
from tools.ip_reputation import check_ip_reputation, check_domain_reputation
from tools.log_analyzer import analyze_logs
from tools.hash_checker import check_file_hash
from tools.network_utils import whois_lookup, geolocation_lookup
from tools.cloud_aws import guardduty_list_findings, guardduty_get_threat_intel, aws_security_hub_summary
from tools.cloud_gcp import gcp_scc_list_findings, gcp_scc_vulnerability_report, gcp_asset_inventory
from tools.cloud_k8s import k8s_rbac_audit, k8s_pod_security_audit, k8s_exposed_services, k8s_image_vulnerability_check
from tools.cloud_iam import aws_iam_audit, gcp_iam_audit, cloud_iam_comparison

ALL_TOOLS = [
    # Core security tools
    cve_search,
    cve_details,
    scan_ports,
    dns_lookup,
    reverse_dns,
    dns_zone_info,
    check_ip_reputation,
    check_domain_reputation,
    analyze_logs,
    check_file_hash,
    whois_lookup,
    geolocation_lookup,
    # Cloud security tools - AWS
    guardduty_list_findings,
    guardduty_get_threat_intel,
    aws_security_hub_summary,
    # Cloud security tools - GCP
    gcp_scc_list_findings,
    gcp_scc_vulnerability_report,
    gcp_asset_inventory,
    # Cloud security tools - Kubernetes
    k8s_rbac_audit,
    k8s_pod_security_audit,
    k8s_exposed_services,
    k8s_image_vulnerability_check,
    # Cloud IAM
    aws_iam_audit,
    gcp_iam_audit,
    cloud_iam_comparison,
]
