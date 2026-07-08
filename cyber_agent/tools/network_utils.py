"""Network utility tools - WHOIS and geolocation."""

import httpx
from langchain_core.tools import tool


@tool
def whois_lookup(target: str) -> str:
    """Perform a WHOIS lookup on a domain or IP address.

    Returns registration details, nameservers, and ownership information.
    """
    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(f"https://rdap.org/domain/{target}")

            if response.status_code == 200:
                data = response.json()
                results = [f"## WHOIS: {target}\n"]

                results.append(f"**Name:** {data.get('ldhName', target)}")
                results.append(f"**Status:** {', '.join(data.get('status', ['Unknown']))}")

                events = data.get("events", [])
                for event in events:
                    action = event.get("eventAction", "")
                    date = event.get("eventDate", "")
                    if action in ("registration", "expiration", "last changed"):
                        results.append(f"**{action.title()}:** {date}")

                nameservers = data.get("nameservers", [])
                if nameservers:
                    results.append("\n**Nameservers:**")
                    for ns in nameservers:
                        results.append(f"  - {ns.get('ldhName', 'Unknown')}")

                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [None, []])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                results.append(f"\n**{', '.join(roles).title()}:** {field[3]}")
                                break

                return "\n".join(results)

            response = client.get(f"https://rdap.org/ip/{target}")
            if response.status_code == 200:
                data = response.json()
                results = [f"## WHOIS: {target}\n"]
                results.append(f"**Network:** {data.get('name', 'Unknown')}")
                results.append(f"**Handle:** {data.get('handle', 'Unknown')}")

                cidrs = data.get("cidr0_cidrs", [{}])
                if cidrs:
                    prefix = cidrs[0].get("v4prefix", "N/A")
                    length = cidrs[0].get("length", "N/A")
                    results.append(f"**CIDR:** {prefix}/{length}")

                results.append(f"**Country:** {data.get('country', 'Unknown')}")
                results.append(f"**Type:** {data.get('type', 'Unknown')}")

                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [None, []])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                results.append(f"**{', '.join(roles).title()}:** {field[3]}")
                                break

                return "\n".join(results)

    except Exception as e:
        return f"WHOIS lookup failed for {target}: {str(e)}"

    return f"No WHOIS data found for {target}"


@tool
def geolocation_lookup(ip_address: str) -> str:
    """Get geolocation information for an IP address.

    Returns country, city, ISP, organization, and coordinates.
    """
    try:
        with httpx.Client(timeout=10) as client:
            # ip-api.com free tier only supports HTTP; paid plans support HTTPS
            response = client.get(
                f"http://ip-api.com/json/{ip_address}",
                params={"fields": "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,proxy"},
            )
            response.raise_for_status()
            data = response.json()

        if data.get("status") == "fail":
            return f"Geolocation lookup failed for {ip_address}: {data.get('message', 'Unknown error')}"

        results = [f"## Geolocation: {ip_address}\n"]
        results.append(f"**Country:** {data.get('country', 'Unknown')} ({data.get('countryCode', '')})")
        results.append(f"**Region:** {data.get('regionName', 'Unknown')}")
        results.append(f"**City:** {data.get('city', 'Unknown')}")
        results.append(f"**ZIP:** {data.get('zip', 'Unknown')}")
        results.append(f"**Coordinates:** {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
        results.append(f"**Timezone:** {data.get('timezone', 'Unknown')}")
        results.append(f"**ISP:** {data.get('isp', 'Unknown')}")
        results.append(f"**Organization:** {data.get('org', 'Unknown')}")
        results.append(f"**AS Number:** {data.get('as', 'Unknown')}")

        hosting_indicators = []
        org = data.get("org", "").lower()
        isp = data.get("isp", "").lower()
        cloud_keywords = ["amazon", "aws", "google", "azure", "digital ocean", "linode"]
        if any(kw in org or kw in isp for kw in cloud_keywords):
            hosting_indicators.append("Cloud/Hosting provider detected")
        if data.get("hosting"):
            hosting_indicators.append("Identified as hosting/datacenter IP")
        if data.get("proxy"):
            hosting_indicators.append("Proxy/VPN detected")

        if hosting_indicators:
            results.append(f"\n**Indicators:** {'; '.join(hosting_indicators)}")

        return "\n".join(results)

    except Exception as e:
        return f"Geolocation lookup failed for {ip_address}: {str(e)}"
