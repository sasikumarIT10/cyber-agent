"""Configuration management for the Cybersecurity AI Agent."""

import os
import sys
import ctypes
import socket
import secrets
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent


# ---- Privilege detection ----
def is_admin() -> bool:
    """Check if the current process is running with admin/elevated privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        # Not on Windows or ctypes unavailable — assume non-admin
        return False


def is_port_available(host: str, port: int) -> bool:
    """Check if a TCP port is available to bind."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.bind((host, port))
            return True
    except OSError:
        return False


IS_ADMIN = is_admin()
PRIVILEGE_LEVEL = "admin" if IS_ADMIN else "standard"

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# LLM Configuration
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
AGENT_MODEL = os.getenv("AGENT_MODEL", "claude-sonnet-4-20250514")
AGENT_MAX_TOKENS = int(os.getenv("AGENT_MAX_TOKENS", "4096"))
AGENT_TEMPERATURE = float(os.getenv("AGENT_TEMPERATURE", "0.1"))

# External API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# API Server
API_HOST = os.getenv("API_HOST", "127.0.0.1")
_requested_port = int(os.getenv("API_PORT", "8000"))

# Auto-detect port availability; fall back to alternative if taken
if is_port_available(API_HOST, _requested_port):
    API_PORT = _requested_port
else:
    # Try a few fallback ports
    _fallbacks = [8001, 8080, 8443, 9000]
    API_PORT = _requested_port  # default
    for _fb in _fallbacks:
        if is_port_available(API_HOST, _fb):
            API_PORT = _fb
            print(f"\n[!] Port {_requested_port} is in use. Falling back to port {_fb}.")
            break
    else:
        print(f"\n[!] Port {_requested_port} and all fallbacks in use. Will attempt {_requested_port} anyway.")

# TLS / HTTPS (for remote deployment)
SSL_ENABLED = os.getenv("SSL_ENABLED", "false").lower() == "true"
SSL_CERTFILE = os.getenv("SSL_CERTFILE", str(BASE_DIR / "certs" / "server.crt"))
SSL_KEYFILE = os.getenv("SSL_KEYFILE", str(BASE_DIR / "certs" / "server.key"))

# API Security
API_KEY = os.getenv("API_KEY", "")
if not API_KEY:
    API_KEY = secrets.token_urlsafe(32)
    print(f"\n[!] No API_KEY set. Generated temporary key: {API_KEY}")
    print("    Set API_KEY in .env to make it persistent.\n")

# Rate limiting (requests per minute per IP)
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "30"))

# Brute-force lockout: max failed auth attempts before IP is blocked
AUTH_LOCKOUT_ATTEMPTS = int(os.getenv("AUTH_LOCKOUT_ATTEMPTS", "10"))
AUTH_LOCKOUT_MINUTES = int(os.getenv("AUTH_LOCKOUT_MINUTES", "15"))

# IP Allowlist (comma-separated, empty = allow all authenticated requests)
IP_ALLOWLIST = os.getenv("IP_ALLOWLIST", "")
ALLOWED_IPS = [ip.strip() for ip in IP_ALLOWLIST.split(",") if ip.strip()] if IP_ALLOWLIST else []

# CORS — restrict in production; add your server IP/domain
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")

# Skills library path
SKILLS_PATH = BASE_DIR.parent / "Anthropic-Cybersecurity-Skills" / "skills"

# Audit log
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", str(BASE_DIR / "audit.log"))

# Data directory (for SQLite persistence)
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
