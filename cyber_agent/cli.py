"""Command-line interface for the Cybersecurity AI Agent."""

import sys
import ipaddress
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme

import config
from agent.graph import run_agent

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green",
})

console = Console(theme=custom_theme)
app = typer.Typer(
    name="cyberagent",
    help="Cybersecurity AI Agent - Powered by Claude & LangGraph",
    add_completion=False,
)


def print_banner():
    banner = """
 ===================================================
           CYBERSECURITY AI AGENT v2.0
           Powered by Claude + LangGraph
 ===================================================
  Commands:
    Type your security question or task
    'help'  - Show available capabilities
    'clear' - Clear conversation history
    'exit'  - Quit the agent
 ==================================================="""
    console.print(Panel(banner, style="bold cyan", border_style="cyan"))


HELP_TEXT = """
## Available Capabilities

### Vulnerability Research
- "Search for CVEs related to Apache Log4j"
- "Get details on CVE-2021-44228"

### Network Reconnaissance
- "Scan ports on 192.168.1.1"
- "Do a DNS lookup for example.com"
- "Reverse DNS lookup for 8.8.8.8"

### Threat Intelligence
- "Check reputation of IP 45.33.32.156"
- "Is this domain malicious: suspicious-site.com"
- "Check this file hash: abc123..."

### Log Analysis
- "Analyze these auth logs for brute force attempts"
- Paste log entries directly for analysis

### Security Assessment
- "Assess email security for example.com"
- "WHOIS lookup for example.com"
- "Geolocate IP 1.1.1.1"

### General Security
- "Explain how SQL injection works"
- "What are the MITRE ATT&CK tactics for lateral movement?"
- "How to respond to a ransomware incident?"
"""


@app.command()
def chat():
    """Start an interactive chat session with the cybersecurity agent."""
    if not config.ANTHROPIC_API_KEY:
        console.print(
            "[danger]Error: ANTHROPIC_API_KEY not set![/danger]\n"
            "Create a .env file with your API key. See .env.example"
        )
        raise typer.Exit(1)

    print_banner()
    history = []

    while True:
        try:
            query = Prompt.ask("\n[bold cyan]You[/bold cyan]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[info]Goodbye![/info]")
            break

        if not query.strip():
            continue

        if query.lower() in ("exit", "quit", "q"):
            console.print("[info]Goodbye![/info]")
            break

        if query.lower() == "clear":
            history = []
            console.print("[success]Conversation cleared.[/success]")
            continue

        if query.lower() == "help":
            console.print(Markdown(HELP_TEXT))
            continue

        history.append({"role": "user", "content": query})

        with console.status("[bold cyan]Analyzing...[/bold cyan]", spinner="dots"):
            try:
                response = run_agent(query, history)
                history.append({"role": "assistant", "content": response})
            except Exception as e:
                console.print(f"[danger]Error: {str(e)}[/danger]")
                continue

        console.print()
        console.print(Panel(Markdown(response), title="[bold green]Agent[/bold green]", border_style="green"))


@app.command()
def query(
    question: str = typer.Argument(..., help="Security question or task"),
):
    """Run a single query and exit."""
    if not config.ANTHROPIC_API_KEY:
        console.print("[danger]Error: ANTHROPIC_API_KEY not set![/danger]")
        raise typer.Exit(1)

    with console.status("[bold cyan]Analyzing...[/bold cyan]", spinner="dots"):
        try:
            response = run_agent(question)
        except Exception as e:
            console.print(f"[danger]Error: {str(e)}[/danger]")
            raise typer.Exit(1)

    console.print(Markdown(response))


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    ports: str = typer.Option("common", help="Port range: 'common' or 'start-end'"),
):
    """Quick port scan on a target."""
    from tools.port_scanner import scan_ports as _scan

    with console.status(f"[bold cyan]Scanning {target}...[/bold cyan]", spinner="dots"):
        result = _scan.invoke({"target": target, "port_range": ports})

    console.print(Markdown(result))


@app.command()
def cve(
    keyword: str = typer.Argument(..., help="CVE search keyword or CVE ID"),
):
    """Search for CVE vulnerabilities."""
    from tools.cve_lookup import cve_search as _search, cve_details as _details

    with console.status("[bold cyan]Searching NVD...[/bold cyan]", spinner="dots"):
        if keyword.upper().startswith("CVE-"):
            result = _details.invoke({"cve_id": keyword.upper()})
        else:
            result = _search.invoke({"keyword": keyword})

    console.print(Markdown(result))


@app.command()
def dns(
    domain: str = typer.Argument(..., help="Domain to investigate"),
    security: bool = typer.Option(False, "--security", "-s", help="Include security assessment"),
):
    """DNS reconnaissance on a domain."""
    from tools.dns_recon import dns_lookup as _lookup, dns_zone_info as _zone

    with console.status(f"[bold cyan]Querying DNS for {domain}...[/bold cyan]", spinner="dots"):
        result = _lookup.invoke({"domain": domain})
        if security:
            result += "\n\n" + _zone.invoke({"domain": domain})

    console.print(Markdown(result))


@app.command()
def reputation(
    target: str = typer.Argument(..., help="IP address or domain to check"),
):
    """Check IP or domain reputation."""
    from tools.ip_reputation import check_ip_reputation as _ip, check_domain_reputation as _domain

    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    with console.status(f"[bold cyan]Checking reputation...[/bold cyan]", spinner="dots"):
        if is_ip:
            result = _ip.invoke({"ip_address": target})
        else:
            result = _domain.invoke({"domain": target})

    console.print(Markdown(result))


if __name__ == "__main__":
    app()
