"""FastAPI REST API for the Cybersecurity AI Agent — hardened for multi-device deployment.

v2.2.0 — Adds restart resilience:
  - SQLite-backed persistence for conversations, rate limits, lockouts
  - Graceful shutdown handler (saves state)
  - Automatic recovery on startup
  - Session-based conversation history
"""

import sys
import signal
import time
import uuid
import ipaddress
import logging
from pathlib import Path
from contextlib import asynccontextmanager

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse
from pydantic import BaseModel, Field
import uvicorn

import config
from agent.graph import run_agent, run_agent_stream
from tools.cve_lookup import cve_search, cve_details
from tools.port_scanner import scan_ports
from tools.dns_recon import dns_lookup, reverse_dns, dns_zone_info
from tools.ip_reputation import check_ip_reputation, check_domain_reputation
from tools.log_analyzer import analyze_logs
from tools.hash_checker import check_file_hash
from tools.network_utils import whois_lookup, geolocation_lookup
from report_generator import generate_report, generate_multi_report, list_reports
import persistence

logger = logging.getLogger(__name__)

# --- Audit logger (separate file for forensic trail) ---
audit_logger = logging.getLogger("audit")
_audit_handler = logging.FileHandler(config.AUDIT_LOG_FILE, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
audit_logger.addHandler(_audit_handler)
audit_logger.setLevel(logging.INFO)


# ===================== LIFESPAN (startup + shutdown) =====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup initialization and graceful shutdown."""
    # --- STARTUP ---
    logger.info("Agent starting up...")
    persistence.init_db()
    persistence.startup_recovery()
    logger.info("Persistence layer ready. Previous shutdown was %s.",
                "clean" if persistence.was_clean_shutdown() else "UNCLEAN")
    
    yield  # App runs here
    
    # --- SHUTDOWN ---
    logger.info("Graceful shutdown initiated...")
    persistence.mark_clean_shutdown()
    audit_logger.info("SERVER_SHUTDOWN | graceful=true")
    logger.info("Shutdown complete. State saved to SQLite.")


app = FastAPI(
    title="Cybersecurity AI Agent API",
    description="AI-powered cybersecurity analysis — hardened for multi-device deployment",
    version="2.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)


# ===================== SECURITY MIDDLEWARE =====================

def _get_client_ip(request: Request) -> str:
    """Get real client IP, handling reverse proxies safely."""
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request):
    """Persistent rate limiter per client IP — survives restarts."""
    client_ip = _get_client_ip(request)
    count = persistence.get_rate_count(client_ip, window_seconds=60)
    if count >= config.RATE_LIMIT_RPM:
        audit_logger.warning("RATE_LIMIT | ip=%s | blocked (>%d rpm)", client_ip, config.RATE_LIMIT_RPM)
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    persistence.increment_rate_count(client_ip, window_seconds=60)


async def check_ip_allowlist(request: Request):
    """Block requests from IPs not in the allowlist (if configured)."""
    if not config.ALLOWED_IPS:
        return
    client_ip = _get_client_ip(request)
    if client_ip not in config.ALLOWED_IPS:
        audit_logger.warning("IP_BLOCKED | ip=%s | not in allowlist", client_ip)
        raise HTTPException(status_code=403, detail="Access denied.")


async def verify_api_key(request: Request, x_api_key: str = Header(None)):
    """Verify API key with persistent brute-force lockout protection."""
    client_ip = _get_client_ip(request)

    if persistence.is_locked_out(client_ip):
        audit_logger.warning("AUTH_LOCKOUT | ip=%s | locked out", client_ip)
        raise HTTPException(status_code=403, detail="Too many failed attempts. Try again later.")

    if not x_api_key or x_api_key != config.API_KEY:
        persistence.record_failed_auth(client_ip, lockout_duration=config.AUTH_LOCKOUT_MINUTES * 60)
        audit_logger.warning("AUTH_FAIL | ip=%s | invalid API key", client_ip)
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

    audit_logger.info("AUTH_OK | ip=%s | endpoint=%s", client_ip, request.url.path)


def api_auth():
    return [Depends(rate_limit), Depends(check_ip_allowlist), Depends(verify_api_key)]


def _safe_error(e: Exception) -> str:
    """Return a safe error message without leaking stack traces or internals."""
    msg = str(e)
    if "Traceback" in msg or "/" in msg or "\\" in msg:
        return "An internal error occurred. Check server logs for details."
    if len(msg) > 200:
        return msg[:200] + "..."
    return msg


# ===================== MODELS =====================

class ChatRequest(BaseModel):
    query: str = Field(..., description="Security question or task", max_length=10000)
    history: list[dict] | None = Field(None, description="Conversation history")
    session_id: str | None = Field(None, description="Session ID for persistent conversation history")
    stream: bool = Field(False, description="Stream the response")

class ChatResponse(BaseModel):
    response: str
    session_id: str
    status: str = "success"

class ScanRequest(BaseModel):
    target: str = Field(..., description="IP or hostname", max_length=255)
    port_range: str = Field("common", description="'common' or 'start-end'", max_length=20)

class CVERequest(BaseModel):
    keyword: str = Field(..., description="Search keyword or CVE ID", max_length=200)
    max_results: int = Field(5, ge=1, le=20)

class DNSRequest(BaseModel):
    domain: str = Field(..., description="Domain to query", max_length=255)
    record_types: str = Field("A,AAAA,MX,NS,TXT", max_length=100)
    include_security: bool = Field(False)

class ReputationRequest(BaseModel):
    target: str = Field(..., description="IP address or domain", max_length=255)

class LogRequest(BaseModel):
    log_content: str = Field(..., description="Log entries to analyze", max_length=100000)
    log_type: str = Field("generic", max_length=20)

class HashRequest(BaseModel):
    hash_value: str = Field(..., description="MD5/SHA-1/SHA-256 hash", max_length=64)

class WhoisRequest(BaseModel):
    target: str = Field(..., description="Domain or IP", max_length=255)

class GeoRequest(BaseModel):
    ip_address: str = Field(..., description="IP to geolocate", max_length=45)

class ToolResponse(BaseModel):
    result: str
    status: str = "success"


# ===================== WEB UI =====================

@app.get("/", response_class=HTMLResponse)
async def web_ui():
    """Serve the web dashboard."""
    ui_path = Path(__file__).parent / "web" / "index.html"
    if ui_path.exists():
        return HTMLResponse(content=ui_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Cybersecurity AI Agent API v2.2</h1><p>Visit <a href='/docs'>/docs</a></p>")


@app.get("/health")
async def health():
    clean = persistence.was_clean_shutdown()
    return {
        "status": "healthy",
        "api_key_configured": bool(config.ANTHROPIC_API_KEY),
        "ssl_enabled": config.SSL_ENABLED,
        "version": "2.2.0",
        "privilege_level": config.PRIVILEGE_LEVEL,
        "persistence": "active",
        "last_shutdown": "clean" if clean else "unclean",
    }


@app.get("/api/info")
async def api_info():
    return {
        "name": "Cybersecurity AI Agent API",
        "version": "2.2.0",
        "features": {
            "persistence": "SQLite-backed — conversations, rate limits, lockouts survive restarts",
            "auto_recovery": "Automatic state recovery on startup",
        },
        "security": {
            "auth": "X-API-Key header required",
            "rate_limit": f"{config.RATE_LIMIT_RPM} req/min",
            "ip_allowlist": "enabled" if config.ALLOWED_IPS else "disabled",
            "tls": "enabled" if config.SSL_ENABLED else "disabled",
        },
        "endpoints": ["/api/chat", "/api/scan", "/api/cve", "/api/dns",
                       "/api/reputation", "/api/logs/analyze", "/api/hash/check",
                       "/api/whois", "/api/geolocate", "/api/sessions"],
    }


# ===================== SESSION ENDPOINTS =====================

@app.get("/api/sessions", dependencies=api_auth())
async def sessions_list():
    """List recent conversation sessions."""
    return {"sessions": persistence.list_sessions(limit=20)}


@app.get("/api/sessions/{session_id}", dependencies=api_auth())
async def session_history(session_id: str):
    """Get full conversation history for a session."""
    messages = persistence.load_conversation(session_id)
    return {"session_id": session_id, "messages": messages}


# ===================== API ENDPOINTS =====================

@app.post("/api/chat", response_model=ChatResponse, dependencies=api_auth())
async def chat_endpoint(request: ChatRequest):
    if not config.ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="LLM API key not configured on server.")

    # Use provided session_id or create a new one
    session_id = request.session_id or str(uuid.uuid4())

    # Build history: merge persisted + request-provided history
    history = []
    if request.session_id:
        history = persistence.load_conversation(session_id)
    if request.history:
        history.extend(request.history)

    # Save user message
    persistence.save_message(session_id, "user", request.query)

    if request.stream:
        async def gen():
            full_response = []
            async for chunk in run_agent_stream(request.query, history):
                full_response.append(chunk)
                yield chunk
            # Save assistant response after stream completes
            persistence.save_message(session_id, "assistant", "".join(full_response))
        return StreamingResponse(gen(), media_type="text/plain",
                                 headers={"X-Session-ID": session_id})
    try:
        response = run_agent(request.query, history)
        # Save assistant response
        persistence.save_message(session_id, "assistant", response)
        return ChatResponse(response=response, session_id=session_id)
    except Exception as e:
        logger.error("Chat error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/scan", response_model=ToolResponse, dependencies=api_auth())
async def scan_endpoint(request: ScanRequest):
    try:
        result = scan_ports.invoke({"target": request.target, "port_range": request.port_range})
        generate_report("Port Scanner", result, target=request.target,
                        parameters={"port_range": request.port_range})
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/cve", response_model=ToolResponse, dependencies=api_auth())
async def cve_endpoint(request: CVERequest):
    try:
        if request.keyword.upper().startswith("CVE-"):
            result = cve_details.invoke({"cve_id": request.keyword.upper()})
        else:
            result = cve_search.invoke({"keyword": request.keyword, "max_results": request.max_results})
        generate_report("CVE Lookup", result, target=request.keyword,
                        parameters={"max_results": request.max_results})
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/dns", response_model=ToolResponse, dependencies=api_auth())
async def dns_endpoint(request: DNSRequest):
    try:
        result = dns_lookup.invoke({"domain": request.domain, "record_types": request.record_types})
        if request.include_security:
            result += "\n\n" + dns_zone_info.invoke({"domain": request.domain})
        generate_report("DNS Reconnaissance", result, target=request.domain,
                        parameters={"record_types": request.record_types, "security": request.include_security})
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/reputation", response_model=ToolResponse, dependencies=api_auth())
async def reputation_endpoint(request: ReputationRequest):
    try:
        target = request.target.strip()
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass
        if is_ip:
            result = check_ip_reputation.invoke({"ip_address": target})
        else:
            result = check_domain_reputation.invoke({"domain": target})
        generate_report("IP/Domain Reputation", result, target=target)
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/logs/analyze", response_model=ToolResponse, dependencies=api_auth())
async def logs_endpoint(request: LogRequest):
    try:
        result = analyze_logs.invoke({"log_content": request.log_content, "log_type": request.log_type})
        generate_report("Log Analysis", result, target=request.log_type,
                        parameters={"log_type": request.log_type, "lines": str(request.log_content.count(chr(10)) + 1)})
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/hash/check", response_model=ToolResponse, dependencies=api_auth())
async def hash_endpoint(request: HashRequest):
    try:
        result = check_file_hash.invoke({"hash_value": request.hash_value})
        generate_report("Hash Check", result, target=request.hash_value)
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/whois", response_model=ToolResponse, dependencies=api_auth())
async def whois_endpoint(request: WhoisRequest):
    try:
        result = whois_lookup.invoke({"target": request.target})
        generate_report("WHOIS Lookup", result, target=request.target)
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


@app.post("/api/geolocate", response_model=ToolResponse, dependencies=api_auth())
async def geolocate_endpoint(request: GeoRequest):
    try:
        result = geolocation_lookup.invoke({"ip_address": request.ip_address})
        generate_report("IP Geolocation", result, target=request.ip_address)
        return ToolResponse(result=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=_safe_error(e))


# ===================== REPORT ENDPOINTS =====================

@app.get("/api/reports", dependencies=api_auth())
async def reports_list():
    """List all saved HTML reports."""
    return {"reports": list_reports()}


@app.get("/api/reports/{filename}")
async def report_download(filename: str):
    """Download/view a saved HTML report (no auth — shareable link)."""
    safe_name = Path(filename).name
    report_path = Path(__file__).parent / "reports" / safe_name
    if not report_path.exists() or not safe_name.endswith(".html"):
        raise HTTPException(status_code=404, detail="Report not found.")
    return HTMLResponse(content=report_path.read_text(encoding="utf-8"))


@app.post("/api/reports/generate", dependencies=api_auth())
async def report_generate_on_demand(request: ChatRequest):
    """Run a chat query and generate an HTML report from the response."""
    if not config.ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="LLM API key not configured on server.")
    try:
        response = run_agent(request.query, request.history)
        _, filepath = generate_report("AI Analysis", response, target=request.query[:80])
        return {"response": response, "report_path": filepath, "report_url": f"/api/reports/{Path(filepath).name}"}
    except Exception as e:
        logger.error("Report generation error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=_safe_error(e))


# ===================== SERVER START =====================

def start():
    """Start the API server with restart resilience."""
    protocol = "https" if config.SSL_ENABLED else "http"
    priv = "ADMIN" if config.IS_ADMIN else "STANDARD USER"
    print(f"\n  Cybersecurity AI Agent API v2.2.0")
    print(f"  Privilege:   {priv}")
    print(f"  Web UI:      {protocol}://{config.API_HOST}:{config.API_PORT}/")
    print(f"  API Docs:    {protocol}://{config.API_HOST}:{config.API_PORT}/docs")
    key = config.API_KEY
    print(f"  API Key:     {key[:8]}...{key[-4:]}")
    print(f"  TLS:         {'ENABLED' if config.SSL_ENABLED else 'DISABLED (use --ssl for remote access)'}")
    if config.ALLOWED_IPS:
        print(f"  IP Allow:    {', '.join(config.ALLOWED_IPS)}")
    print(f"  Reports:     {Path(__file__).parent / 'reports'}/")
    print(f"  Persistence: SQLite ({Path(__file__).parent / 'data' / 'agent_state.db'})")
    print(f"  Recovery:    Automatic on startup")
    if not config.IS_ADMIN:
        print(f"  Note:        Running as standard user — some ports may be restricted")
    print()

    kwargs = {
        "app": "api:app",
        "host": config.API_HOST,
        "port": config.API_PORT,
        "reload": False,
        "access_log": True,
    }

    if config.SSL_ENABLED:
        cert = Path(config.SSL_CERTFILE)
        key_file = Path(config.SSL_KEYFILE)
        if not cert.exists() or not key_file.exists():
            print(f"  [ERROR] SSL cert/key not found!")
            print(f"  Run: python generate_certs.py")
            print(f"  Expected: {cert} and {key_file}")
            return
        kwargs["ssl_certfile"] = str(cert)
        kwargs["ssl_keyfile"] = str(key_file)

    uvicorn.run(**kwargs)


if __name__ == "__main__":
    start()
