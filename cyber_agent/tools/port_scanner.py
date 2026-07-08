"""Network port scanning tool."""

import ipaddress
import logging
import socket
import concurrent.futures
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch",
}

# Private/reserved ranges that should not be scanned from an external tool
_BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),   # multicast
    ipaddress.ip_network("240.0.0.0/4"),   # reserved
]


def _is_safe_target(ip_str: str) -> bool:
    """Check if target IP is safe to scan (not localhost/link-local/multicast)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _BLOCKED_RANGES:
            if addr in net:
                return False
        return True
    except ValueError:
        return False


def _check_port(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """Check if a single port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:100]
                except (socket.timeout, ConnectionError, OSError):
                    pass
                return {"port": port, "service": service, "banner": banner}
    except (socket.timeout, ConnectionError, OSError) as e:
        logger.debug("Port %d check failed on %s: %s", port, host, e)
    return None


@tool
def scan_ports(target: str, port_range: str = "common") -> str:
    """Scan a target host for open ports. Use for network reconnaissance and security assessment.

    Args:
        target: IP address or hostname to scan
        port_range: 'common' for top 25 ports, or a range like '1-1024'

    WARNING: Only scan systems you have explicit authorization to test.
    """
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return f"Cannot resolve hostname: {target}"

    # SSRF protection
    if not _is_safe_target(ip):
        return f"Refused to scan {target} ({ip}): target is localhost, link-local, or reserved."

    if port_range == "common":
        ports_to_scan = list(COMMON_PORTS.keys())
    else:
        try:
            start, end = port_range.split("-")
            ports_to_scan = list(range(int(start), int(end) + 1))
            if len(ports_to_scan) > 1024:
                ports_to_scan = ports_to_scan[:1024]
        except ValueError:
            return "Invalid port range. Use 'common' or 'start-end' format (e.g., '1-1024')"

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_check_port, ip, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    open_ports.sort(key=lambda x: x["port"])

    if not open_ports:
        return f"## Port Scan: {target} ({ip})\n\nNo open ports found among {len(ports_to_scan)} scanned."

    results = [f"## Port Scan: {target} ({ip})\n"]
    results.append(f"**Scanned:** {len(ports_to_scan)} ports")
    results.append(f"**Open:** {len(open_ports)} ports\n")

    results.append("| Port | Service | Banner |")
    results.append("|------|---------|--------|")
    for p in open_ports:
        banner_text = p["banner"][:60] if p["banner"] else "—"
        results.append(f"| {p['port']} | {p['service']} | {banner_text} |")

    # Security observations
    risky_ports = {23: "Telnet (unencrypted)", 21: "FTP (unencrypted)", 135: "MSRPC", 445: "SMB", 3389: "RDP"}
    found_risky = [f"{port}: {risky_ports[port]}" for port in [p["port"] for p in open_ports] if port in risky_ports]
    if found_risky:
        results.append("\n**Security Concerns:**")
        for concern in found_risky:
            results.append(f"  - {concern}")

    return "\n".join(results)
