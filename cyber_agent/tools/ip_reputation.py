"""IP and domain reputation checking tools."""

import httpx
from langchain_core.tools import tool

import config


@tool
def check_ip_reputation(ip_address: str) -> str:
    """Check the reputation of an IP address using AbuseIPDB and other sources.
    
    Returns abuse confidence score, reports count, and associated threat categories.
    """
    results = [f"## IP Reputation Report: {ip_address}\n"]

    # AbuseIPDB check
    if config.ABUSEIPDB_API_KEY:
        try:
            with httpx.Client(timeout=15) as client:
                response = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""},
                    headers={
                        "Key": config.ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                data = response.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            domain = data.get("domain", "Unknown")
            is_tor = data.get("isTor", False)

            if score >= 75:
                verdict = "MALICIOUS (High Confidence)"
            elif score >= 40:
                verdict = "SUSPICIOUS"
            elif score > 0:
                verdict = "LOW RISK"
            else:
                verdict = "CLEAN"

            results.append(f"**Verdict:** {verdict}")
            results.append(f"**Abuse Confidence Score:** {score}/100")
            results.append(f"**Total Reports:** {total_reports}")
            results.append(f"**Country:** {country}")
            results.append(f"**ISP:** {isp}")
            results.append(f"**Domain:** {domain}")
            results.append(f"**TOR Exit Node:** {'Yes [!]' if is_tor else 'No'}")

            if data.get("reports"):
                results.append("\n**Recent Reports:**")
                for report in data["reports"][:3]:
                    categories = report.get("categories", [])
                    comment = report.get("comment", "No comment")[:100]
                    results.append(f"  - Categories: {categories} | {comment}")

        except httpx.HTTPStatusError as e:
            results.append(f"AbuseIPDB API error: {e.response.status_code}")
        except Exception as e:
            results.append(f"AbuseIPDB check failed: {str(e)}")
    else:
        results.append("**AbuseIPDB:** API key not configured")
        results.append("  Set ABUSEIPDB_API_KEY in .env for IP reputation checks")

    # VirusTotal check
    if config.VIRUSTOTAL_API_KEY:
        try:
            with httpx.Client(timeout=15) as client:
                response = client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                    headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
                )
                if response.status_code == 200:
                    vt_data = response.json().get("data", {}).get("attributes", {})
                    stats = vt_data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    results.append(f"\n**VirusTotal:** {malicious}/{total} vendors flagged as malicious")
        except:
            pass

    return "\n".join(results)


@tool
def check_domain_reputation(domain: str) -> str:
    """Check the reputation of a domain using VirusTotal.
    
    Returns detection ratio, categories, and registration information.
    """
    results = [f"## Domain Reputation: {domain}\n"]

    if not config.VIRUSTOTAL_API_KEY:
        return (
            f"## Domain Reputation: {domain}\n\n"
            "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env"
        )

    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        clean = stats.get("harmless", 0) + stats.get("undetected", 0)
        total = sum(stats.values())

        if malicious >= 5:
            verdict = "MALICIOUS"
        elif malicious > 0 or suspicious > 2:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        results.append(f"**Verdict:** {verdict}")
        results.append(f"**Detection:** {malicious}/{total} malicious, {suspicious} suspicious")
        results.append(f"**Categories:** {data.get('categories', {})}")
        results.append(f"**Registrar:** {data.get('registrar', 'Unknown')}")
        results.append(f"**Creation Date:** {data.get('creation_date', 'Unknown')}")
        results.append(f"**Reputation Score:** {data.get('reputation', 'N/A')}")

        dns_records = data.get("last_dns_records", [])
        if dns_records:
            results.append("\n**DNS Records:**")
            for record in dns_records[:5]:
                results.append(f"  - {record.get('type', '?')}: {record.get('value', '?')}")

    except httpx.HTTPStatusError as e:
        results.append(f"VirusTotal API error: {e.response.status_code}")
    except Exception as e:
        results.append(f"Domain reputation check failed: {str(e)}")

    return "\n".join(results)
