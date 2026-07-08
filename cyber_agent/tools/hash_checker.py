"""File hash checking against malware databases."""

import hashlib
from pathlib import Path

import httpx
from langchain_core.tools import tool

import config


@tool
def check_file_hash(hash_value: str) -> str:
    """Check a file hash (MD5, SHA-1, or SHA-256) against VirusTotal's malware database.
    
    Args:
        hash_value: MD5, SHA-1, or SHA-256 hash of the file to check
    
    Returns detection results from multiple antivirus engines.
    """
    hash_value = hash_value.strip().lower()

    hash_lengths = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
    hash_type = hash_lengths.get(len(hash_value))
    if not hash_type:
        return "Invalid hash format. Provide MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars)."

    results = [f"## File Hash Analysis\n"]
    results.append(f"**Hash ({hash_type}):** `{hash_value}`\n")

    if not config.VIRUSTOTAL_API_KEY:
        results.append("VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env")
        return "\n".join(results)

    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/files/{hash_value}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )

        if response.status_code == 404:
            results.append("**Status:** Not found in VirusTotal database")
            results.append("This file has not been previously submitted for analysis.")
            return "\n".join(results)

        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values())

        if malicious >= 10:
            verdict = "MALICIOUS (High Confidence)"
        elif malicious >= 3:
            verdict = "LIKELY MALICIOUS"
        elif malicious > 0 or suspicious > 2:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        results.append(f"**Verdict:** {verdict}")
        results.append(f"**Detection:** {malicious}/{total} engines detected as malicious")
        results.append(f"**Suspicious:** {suspicious} engines flagged as suspicious")
        results.append(f"**File Name:** {data.get('meaningful_name', 'Unknown')}")
        results.append(f"**File Type:** {data.get('type_description', 'Unknown')}")
        results.append(f"**File Size:** {data.get('size', 'Unknown')} bytes")
        results.append(f"**First Seen:** {data.get('first_submission_date', 'Unknown')}")

        tags = data.get("tags", [])
        if tags:
            results.append(f"**Tags:** {', '.join(tags[:10])}")

        popular_threat = data.get("popular_threat_classification", {})
        if popular_threat:
            label = popular_threat.get("suggested_threat_label", "")
            results.append(f"**Threat Classification:** {label}")

        if malicious > 0:
            results.append("\n**Top Detections:**")
            analysis = data.get("last_analysis_results", {})
            detections = [(k, v) for k, v in analysis.items()
                        if v.get("category") == "malicious"]
            for engine, det in detections[:8]:
                results.append(f"  - {engine}: {det.get('result', 'Detected')}")

    except httpx.HTTPStatusError as e:
        results.append(f"VirusTotal API error: {e.response.status_code}")
    except Exception as e:
        results.append(f"Hash check failed: {str(e)}")

    return "\n".join(results)
