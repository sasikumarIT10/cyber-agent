"""Security log analysis tool."""

import re
from collections import Counter
from langchain_core.tools import tool


SUSPICIOUS_PATTERNS = {
    "brute_force": r"(?i)(failed|invalid)\s+(login|password|auth)",
    "sql_injection": r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*--)",
    "xss_attempt": r"(?i)(<script|javascript:|on\w+\s*=)",
    "path_traversal": r"(?:\.\./|\.\.\\){2,}",
    "command_injection": r"(?i)(;\s*(?:cat|ls|whoami|id|pwd|wget|curl)\s|`.*`|\$\(.*\))",
    "privilege_escalation": r"(?i)(sudo|su\s+root|chmod\s+[47]77|setuid)",
    "data_exfiltration": r"(?i)(curl.*-d|wget.*post|nc\s+-e|/dev/tcp/)",
    "malware_indicators": r"(?i)(powershell.*-enc|certutil.*decode|bitsadmin.*transfer)",
    "suspicious_user_agent": r"(?i)(nikto|sqlmap|nmap|masscan|burp|dirbuster)",
    "encoded_payload": r"(?:[A-Za-z0-9+/]{40,}={0,2})",
}

SEVERITY_MAP = {
    "brute_force": "MEDIUM",
    "sql_injection": "HIGH",
    "xss_attempt": "MEDIUM",
    "path_traversal": "HIGH",
    "command_injection": "CRITICAL",
    "privilege_escalation": "CRITICAL",
    "data_exfiltration": "CRITICAL",
    "malware_indicators": "CRITICAL",
    "suspicious_user_agent": "LOW",
    "encoded_payload": "MEDIUM",
}


@tool
def analyze_logs(log_content: str, log_type: str = "generic") -> str:
    """Analyze security logs for suspicious patterns and potential threats.
    
    Args:
        log_content: The log content to analyze (paste log entries directly)
        log_type: Type of log - 'generic', 'apache', 'auth', 'windows'
    
    Detects: brute force, SQL injection, XSS, path traversal, command injection,
    privilege escalation, data exfiltration, malware indicators.
    """
    lines = log_content.strip().split("\n")
    findings = []
    ip_counter = Counter()
    severity_counter = Counter()

    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    for i, line in enumerate(lines, 1):
        ips = ip_pattern.findall(line)
        for match in ip_pattern.finditer(line):
            ip_counter[match.group()] += 1

        for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, line):
                severity = SEVERITY_MAP[pattern_name]
                severity_counter[severity] += 1
                findings.append({
                    "line": i,
                    "type": pattern_name,
                    "severity": severity,
                    "content": line.strip()[:150],
                })

    if not findings:
        return (
            f"## Log Analysis Results\n\n"
            f"Analyzed {len(lines)} log lines.\n"
            f"**No suspicious patterns detected.**\n\n"
            f"Top source IPs: {dict(ip_counter.most_common(5))}"
        )

    results = [f"## Log Analysis Results\n"]
    results.append(f"**Lines Analyzed:** {len(lines)}")
    results.append(f"**Threats Detected:** {len(findings)}")
    results.append(f"**Severity Breakdown:** {dict(severity_counter)}\n")

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] in ("MEDIUM", "LOW")]

    if critical:
        results.append("### CRITICAL Findings")
        for f in critical[:10]:
            results.append(
                f"- **[Line {f['line']}] {f['type'].replace('_', ' ').title()}**\n"
                f"  `{f['content']}`"
            )

    if high:
        results.append("\n### HIGH Findings")
        for f in high[:10]:
            results.append(
                f"- **[Line {f['line']}] {f['type'].replace('_', ' ').title()}**\n"
                f"  `{f['content']}`"
            )

    if medium:
        results.append(f"\n### MEDIUM/LOW Findings ({len(medium)} total)")
        for f in medium[:5]:
            results.append(f"- [Line {f['line']}] {f['type'].replace('_', ' ').title()}")

    if ip_counter:
        results.append("\n### Top Source IPs")
        for ip, count in ip_counter.most_common(10):
            results.append(f"  - {ip}: {count} occurrences")

    results.append("\n### Recommendations")
    if critical:
        results.append("- **IMMEDIATE ACTION REQUIRED** - Critical threats detected")
        results.append("- Isolate affected systems and investigate command injection/exfiltration")
    if high:
        results.append("- Block identified malicious IPs at firewall level")
        results.append("- Review WAF rules for SQL injection and path traversal")
    results.append("- Correlate source IPs with threat intelligence feeds")

    return "\n".join(results)
