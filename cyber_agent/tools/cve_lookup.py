"""CVE vulnerability lookup using NIST NVD API."""

import httpx
from langchain_core.tools import tool


@tool
def cve_search(keyword: str, max_results: int = 5) -> str:
    """Search for CVE vulnerabilities by keyword (e.g., 'apache log4j', 'windows smb').
    
    Returns a list of matching CVEs with severity scores and descriptions.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"No CVEs found for keyword: '{keyword}'"

        results = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "N/A")
                    break

            results.append(
                f"**{cve_id}** | CVSS: {cvss_score} ({severity})\n"
                f"  {desc[:200]}..."
            )

        return f"Found {len(results)} CVEs for '{keyword}':\n\n" + "\n\n".join(results)

    except httpx.HTTPStatusError as e:
        return f"NVD API error: {e.response.status_code}"
    except Exception as e:
        return f"CVE search failed: {str(e)}"


@tool
def cve_details(cve_id: str) -> str:
    """Get detailed information about a specific CVE by its ID (e.g., 'CVE-2021-44228').
    
    Returns full details including CVSS score, affected products, and references.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"CVE {cve_id} not found"

        cve = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        metrics = cve.get("metrics", {})
        cvss_info = "No CVSS data available"
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_info = (
                    f"CVSS {cvss_data.get('version', 'N/A')}: {cvss_data.get('baseScore', 'N/A')} "
                    f"({cvss_data.get('baseSeverity', 'N/A')})\n"
                    f"  Attack Vector: {cvss_data.get('attackVector', 'N/A')}\n"
                    f"  Attack Complexity: {cvss_data.get('attackComplexity', 'N/A')}\n"
                    f"  Privileges Required: {cvss_data.get('privilegesRequired', 'N/A')}\n"
                    f"  User Interaction: {cvss_data.get('userInteraction', 'N/A')}"
                )
                break

        references = cve.get("references", [])
        ref_links = "\n".join(f"  - {r.get('url', '')}" for r in references[:5])

        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    cwe_ids.append(d.get("value", ""))

        return (
            f"## {cve_id}\n\n"
            f"**Description:** {desc}\n\n"
            f"**CVSS:** {cvss_info}\n\n"
            f"**CWE:** {', '.join(cwe_ids) if cwe_ids else 'N/A'}\n\n"
            f"**References:**\n{ref_links if ref_links else '  None'}\n\n"
            f"**Published:** {cve.get('published', 'N/A')}\n"
            f"**Last Modified:** {cve.get('lastModified', 'N/A')}"
        )

    except Exception as e:
        return f"CVE lookup failed: {str(e)}"
