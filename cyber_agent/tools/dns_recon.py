"""DNS reconnaissance tools."""

import socket
import dns.resolver
import dns.reversename
from langchain_core.tools import tool


@tool
def dns_lookup(domain: str, record_types: str = "A,AAAA,MX,NS,TXT") -> str:
    """Perform DNS lookups for a domain across multiple record types.
    
    Args:
        domain: The domain name to query
        record_types: Comma-separated DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA)
    """
    types = [t.strip().upper() for t in record_types.split(",")]
    results = []
    results.append(f"## DNS Records for {domain}\n")

    for rtype in types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append(f"  Priority {rdata.preference}: {rdata.exchange}")
                elif rtype == "SOA":
                    records.append(
                        f"  Primary NS: {rdata.mname}\n"
                        f"  Admin: {rdata.rname}\n"
                        f"  Serial: {rdata.serial}"
                    )
                else:
                    records.append(f"  {rdata.to_text()}")
            results.append(f"**{rtype} Records:**\n" + "\n".join(records))
        except dns.resolver.NoAnswer:
            results.append(f"**{rtype}:** No records found")
        except dns.resolver.NXDOMAIN:
            return f"Domain {domain} does not exist (NXDOMAIN)"
        except Exception as e:
            results.append(f"**{rtype}:** Query failed - {str(e)}")

    return "\n\n".join(results)


@tool
def reverse_dns(ip_address: str) -> str:
    """Perform reverse DNS lookup on an IP address to find associated hostnames.
    
    Args:
        ip_address: The IP address to reverse-lookup
    """
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, "PTR")
        hostnames = [str(rdata) for rdata in answers]
        result = f"## Reverse DNS: {ip_address}\n\n"
        result += "**PTR Records:**\n"
        result += "\n".join(f"  - {h}" for h in hostnames)

        for hostname in hostnames:
            hostname = hostname.rstrip(".")
            try:
                forward = dns.resolver.resolve(hostname, "A")
                forward_ips = [str(r) for r in forward]
                result += f"\n\n**Forward verification ({hostname}):** {', '.join(forward_ips)}"
                if ip_address in forward_ips:
                    result += " [MATCH]"
                else:
                    result += " [MISMATCH] (possible DNS misconfiguration)"
            except:
                pass

        return result
    except dns.resolver.NXDOMAIN:
        return f"No PTR record found for {ip_address}"
    except Exception as e:
        return f"Reverse DNS lookup failed: {str(e)}"


@tool
def dns_zone_info(domain: str) -> str:
    """Gather comprehensive DNS zone information for security assessment.
    
    Checks for SPF, DMARC, DKIM indicators, and nameserver configuration.
    """
    results = [f"## DNS Security Assessment: {domain}\n"]

    # SPF check
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        spf_records = [str(r) for r in txt_records if "v=spf1" in str(r)]
        if spf_records:
            results.append(f"**SPF Record:** {spf_records[0]}")
            if "-all" in spf_records[0]:
                results.append("  [PASS] Strict SPF (hard fail for unauthorized senders)")
            elif "~all" in spf_records[0]:
                results.append("  [WARN] Soft SPF (soft fail - emails may still be delivered)")
            elif "+all" in spf_records[0]:
                results.append("  [FAIL] Permissive SPF (allows all senders - INSECURE)")
        else:
            results.append("**SPF:** [FAIL] No SPF record found (email spoofing risk)")
    except:
        results.append("**SPF:** Unable to check")

    # DMARC check
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r) for r in dmarc if "v=DMARC1" in str(r)]
        if dmarc_records:
            results.append(f"\n**DMARC Record:** {dmarc_records[0]}")
            if "p=reject" in dmarc_records[0]:
                results.append("  [PASS] Policy: reject (strongest protection)")
            elif "p=quarantine" in dmarc_records[0]:
                results.append("  [WARN] Policy: quarantine (moderate protection)")
            elif "p=none" in dmarc_records[0]:
                results.append("  [FAIL] Policy: none (monitoring only - no protection)")
        else:
            results.append("\n**DMARC:** [FAIL] No DMARC record (email spoofing risk)")
    except:
        results.append("\n**DMARC:** [FAIL] No DMARC record found")

    # Nameservers
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        ns_list = [str(r) for r in ns_records]
        results.append(f"\n**Nameservers ({len(ns_list)}):**")
        for ns in ns_list:
            results.append(f"  - {ns}")
        if len(ns_list) < 2:
            results.append("  [WARN] Only one nameserver (single point of failure)")
    except:
        results.append("\n**Nameservers:** Unable to query")

    # MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        results.append(f"\n**Mail Servers:**")
        for mx in sorted(mx_records, key=lambda x: x.preference):
            results.append(f"  - [{mx.preference}] {mx.exchange}")
    except:
        results.append("\n**Mail Servers:** None found")

    return "\n".join(results)
