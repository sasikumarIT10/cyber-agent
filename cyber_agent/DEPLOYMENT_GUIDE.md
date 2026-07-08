# Cybersecurity AI Agent — Deployment Guide

A complete step-by-step guide to deploy and run the Cybersecurity AI Agent on any device.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Project Overview](#2-project-overview)
3. [How the Agent Works](#3-how-the-agent-works)
4. [First-Time Setup (Any Device)](#4-first-time-setup-any-device)
5. [Running the Agent](#5-running-the-agent)
6. [Deploying as a Server (Multi-Device Access)](#6-deploying-as-a-server-multi-device-access)
7. [Connecting Client Devices](#7-connecting-client-devices)
8. [Cloud/VPS Deployment](#8-cloudvps-deployment)
9. [Configuration Reference](#9-configuration-reference)
10. [API Endpoints Reference](#10-api-endpoints-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [Security Considerations](#12-security-considerations)

---

## 1. System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10/11, Windows Server 2019+, Ubuntu 20.04+, macOS 12+ |
| **Python** | 3.11 or higher |
| **RAM** | 2 GB minimum (4 GB recommended) |
| **Disk** | 500 MB free space |
| **Network** | Internet access (for API calls to Claude, NVD, VirusTotal, etc.) |

### Required API Keys

| Key | Required? | Purpose | Get it from |
|-----|-----------|---------|-------------|
| `ANTHROPIC_API_KEY` | **Yes** | Powers the AI reasoning (Claude) | https://console.anthropic.com |
| `VIRUSTOTAL_API_KEY` | Optional | File hash & domain reputation checks | https://www.virustotal.com (free tier available) |
| `ABUSEIPDB_API_KEY` | Optional | IP reputation scoring | https://www.abuseipdb.com (free tier available) |
| `SHODAN_API_KEY` | Optional | Internet-wide device scanning | https://account.shodan.io |

---

## 2. Project Overview

### Folder Structure

```
cyber_agent/
├── agent/                    # AI Agent core
│   ├── graph.py              # LangGraph orchestration engine
│   ├── state.py              # Agent state management
│   ├── prompts.py            # System prompt (security expert persona)
│   └── skills_loader.py      # Loads relevant skills from the library
│
├── tools/                    # 12 cybersecurity tools
│   ├── cve_lookup.py         # CVE vulnerability search (NIST NVD)
│   ├── port_scanner.py       # Network port scanner
│   ├── dns_recon.py          # DNS reconnaissance & email security
│   ├── ip_reputation.py      # IP/Domain reputation (AbuseIPDB + VirusTotal)
│   ├── log_analyzer.py       # Security log threat detection
│   ├── hash_checker.py       # Malware hash lookup
│   └── network_utils.py      # WHOIS & Geolocation
│
├── web/                      # Web UI (browser-based dashboard)
│   └── index.html            # Single-page dark-themed interface
│
├── reports/                  # Auto-generated HTML security reports
├── data/                     # SQLite database (conversations, state)
├── certs/                    # TLS certificates (generated for HTTPS)
│
├── api.py                    # FastAPI REST API server
├── cli.py                    # Command-line interface
├── config.py                 # Configuration management
├── persistence.py            # SQLite state persistence
├── report_generator.py       # HTML report generation
├── generate_certs.py         # TLS certificate generator
│
├── setup.bat                 # Windows: First-time setup
├── start-cli.bat             # Windows: Launch CLI
├── start-web.bat             # Windows: Launch Web UI + API
├── deploy-server.bat         # Windows: Deploy as network server
├── deploy-client.bat         # Windows: Configure as client device
├── test-tools.bat            # Windows: Test all tools
│
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
└── README.md                 # Quick-start readme
```

### What Each Component Does

| Component | Role |
|-----------|------|
| **LangGraph Agent** | Orchestrates tool calls in a loop — Claude decides which tools to use based on the query |
| **Skills Loader** | Searches 754 cybersecurity skills from the library and injects relevant ones into Claude's context |
| **Tools** | Execute actual security operations (API calls, port scans, log parsing) |
| **Persistence** | SQLite database stores conversations, rate limits, and lockout state — survives restarts |
| **Report Generator** | Creates professional HTML reports from any tool output |
| **Web UI** | Browser-based dashboard with chat, tool panels, and API key management |
| **CLI** | Rich terminal interface with colored output and interactive chat |

---

## 3. How the Agent Works

### Workflow (What Happens When You Ask a Question)

```
Step 1: You type "Check if IP 45.33.32.156 is malicious"
            │
Step 2: Skills Loader searches 754 skills → finds "analyzing-ip-reputation"
            │
Step 3: Claude receives your query + relevant skill context
            │
Step 4: Claude decides: "I should use check_ip_reputation tool"
            │
Step 5: Tool calls AbuseIPDB + VirusTotal APIs
            │
Step 6: Results returned to Claude
            │
Step 7: Claude decides: "I should also geolocate this IP"
            │
Step 8: geolocation_lookup tool runs
            │
Step 9: Claude has enough data → generates final analysis
            │
Step 10: Response with verdict, risk score, recommendations
            │
Step 11: HTML report auto-saved to reports/ folder
```

### The Tool-Calling Loop

The agent uses LangGraph's **conditional edges**:

1. **Agent Node** → Claude thinks and may request tool calls
2. If tools requested → **Tools Node** executes them → returns to Agent
3. If no tools needed → Agent produces final answer → **END**

This loop can iterate multiple times (Claude may call 1-5 tools per query).

---

## 4. First-Time Setup (Any Device)

### Windows Setup

**Option A: Using the setup script (recommended)**

```
1. Copy the entire cyber_agent/ folder to the target device
2. Double-click setup.bat
3. When Notepad opens .env, add your ANTHROPIC_API_KEY
4. Save and close
5. Done!
```

**Option B: Manual setup**

Open PowerShell or Command Prompt:

```powershell
# Navigate to the project folder
cd "path\to\cyber_agent"

# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create your .env file
copy .env.example .env

# Edit .env and add your API key
notepad .env
```

Add this line to `.env`:
```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### Linux / macOS Setup

```bash
# Navigate to the project folder
cd /path/to/cyber_agent

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create your .env file
cp .env.example .env

# Edit .env and add your API key
nano .env
```

Add this line to `.env`:
```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### Verify Installation

```bash
# Activate venv first, then:
python -c "from agent.graph import create_agent, ALL_TOOLS; print(f'OK: {len(ALL_TOOLS)} tools loaded')"
```

Expected output: `OK: 12 tools loaded`

---

## 5. Running the Agent

### Option 1: Interactive CLI Chat

```bash
# Windows
start-cli.bat

# Linux/macOS (or manual)
python cli.py chat
```

You'll see a cybersecurity terminal prompt. Type questions like:
- "Search for CVEs related to Apache Log4j"
- "Scan ports on 192.168.1.1"
- "Analyze these logs: Failed password for root from 10.0.0.1"

Commands inside the chat:
- `help` — Show all capabilities
- `clear` — Clear conversation history
- `exit` — Quit

### Option 2: Single Query (No Interactive Mode)

```bash
python cli.py query "Get details on CVE-2021-44228"
python cli.py scan 192.168.1.1 --ports common
python cli.py dns example.com --security
python cli.py cve "openssl"
python cli.py reputation 45.33.32.156
```

### Option 3: Web UI (Browser Dashboard)

```bash
# Windows
start-web.bat

# Linux/macOS
python api.py
```

Then open your browser to: **http://localhost:8000**

The Web UI provides:
- Chat interface with the AI agent
- Tool-specific panels (Port Scan, CVE, DNS, etc.)
- API key configuration
- Real-time results

### Option 4: REST API (For Integration)

Start the server:
```bash
python api.py
```

API documentation available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## 6. Deploying as a Server (Multi-Device Access)

This lets other devices on your network (or the internet) access the agent via browser or API.

### Step-by-Step Server Deployment (Windows)

```
1. Double-click deploy-server.bat
2. It will:
   - Generate TLS certificates (HTTPS)
   - Enable SSL in .env
   - Add Windows Firewall rule for port 8000
   - Display connection info for clients
3. Press any key to start the server
```

### Manual Server Deployment (Any OS)

```bash
# 1. Install TLS dependency
pip install cryptography

# 2. Generate self-signed certificate
python generate_certs.py --ip YOUR_SERVER_IP

# 3. Configure .env for server mode
# Add/update these lines in .env:
SSL_ENABLED=true
API_HOST=0.0.0.0
API_KEY=choose-a-strong-secret-key-here

# Optional: Restrict to specific client IPs
# IP_ALLOWLIST=192.168.1.10,192.168.1.20

# 4. Open firewall port (Linux)
sudo ufw allow 8000/tcp

# 4. Open firewall port (Windows PowerShell as Admin)
netsh advfirewall firewall add rule name="CyberAgent" dir=in action=allow protocol=tcp localport=8000

# 5. Start the server
python api.py
```

### What to Give Each Client Device

| Item | How to get it |
|------|---------------|
| Server IP address | Run `ipconfig` (Windows) or `ip addr` (Linux) on the server |
| API Key | The key shown in terminal when server starts, or your `API_KEY` from `.env` |
| TLS Certificate | `certs/server.crt` file (for trusting the self-signed cert) |

### Find Your Server IP

```bash
# Windows
ipconfig | findstr "IPv4"

# Linux
hostname -I

# macOS
ifconfig | grep "inet " | grep -v 127.0.0.1
```

---

## 7. Connecting Client Devices

### Method 1: Web Browser (Easiest)

On any device on the same network:

1. Open a browser (Chrome, Firefox, Edge)
2. Go to: `https://<server-ip>:8000`
3. Accept the self-signed certificate warning
4. Enter the API key in the top bar
5. Start using the agent!

### Method 2: Client Setup Script (Windows)

```
1. Copy the cyber_agent folder to the client device
2. Double-click deploy-client.bat
3. Enter the server IP when prompted
4. Enter the API key when prompted
5. It will test the connection automatically
```

### Method 3: API Calls (For Scripts/Automation)

From any device with `curl` or Python:

```bash
# Chat with the agent
curl -k -X POST https://<server-ip>:8000/api/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"query": "Search for CVEs related to OpenSSL"}'

# Port scan
curl -k -X POST https://<server-ip>:8000/api/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "192.168.1.1", "port_range": "common"}'

# DNS lookup
curl -k -X POST https://<server-ip>:8000/api/dns \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"domain": "example.com", "include_security": true}'
```

### Method 4: Python Client Script

```python
import httpx

SERVER = "https://192.168.1.100:8000"
API_KEY = "your-api-key-here"

headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# Ask the AI agent
response = httpx.post(
    f"{SERVER}/api/chat",
    headers=headers,
    json={"query": "Analyze CVE-2021-44228 and recommend mitigations"},
    verify=False,  # for self-signed cert
    timeout=60,
)

print(response.json()["response"])
```

---

## 8. Cloud/VPS Deployment

### Deploy to a Linux VPS (AWS, DigitalOcean, Linode, etc.)

```bash
# 1. SSH into your VPS
ssh user@your-server-ip

# 2. Install Python 3.11+
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip -y

# 3. Upload the project (from your local machine)
# Option A: Git
git clone <your-repo-url>
cd cyber_agent

# Option B: SCP
scp -r cyber_agent/ user@server-ip:/home/user/

# 4. Setup
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 5. Configure
cp .env.example .env
nano .env
# Add:
#   ANTHROPIC_API_KEY=sk-ant-xxxxx
#   SSL_ENABLED=true
#   API_HOST=0.0.0.0
#   API_KEY=your-strong-secret-key
#   CORS_ORIGINS=https://yourdomain.com

# 6. Generate TLS cert (use your public IP or domain)
pip install cryptography
python generate_certs.py --ip YOUR_PUBLIC_IP

# 7. Open firewall
sudo ufw allow 8000/tcp

# 8. Run (foreground — for testing)
python api.py

# 9. Run as background service (production)
# Create systemd service:
sudo nano /etc/systemd/system/cyberagent.service
```

### Systemd Service File (Linux Production)

Create `/etc/systemd/system/cyberagent.service`:

```ini
[Unit]
Description=Cybersecurity AI Agent API
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/home/your-username/cyber_agent
Environment="PATH=/home/your-username/cyber_agent/venv/bin"
ExecStart=/home/your-username/cyber_agent/venv/bin/python api.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cyberagent
sudo systemctl start cyberagent

# Check status
sudo systemctl status cyberagent

# View logs
sudo journalctl -u cyberagent -f
```

### Using a Real Domain + Let's Encrypt (Production HTTPS)

Instead of self-signed certs, use Nginx as a reverse proxy with Let's Encrypt:

```bash
# 1. Install Nginx and Certbot
sudo apt install nginx certbot python3-certbot-nginx -y

# 2. Configure Nginx
sudo nano /etc/nginx/sites-available/cyberagent
```

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
```

```bash
# 3. Enable site
sudo ln -s /etc/nginx/sites-available/cyberagent /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# 4. Get SSL certificate
sudo certbot --nginx -d yourdomain.com

# 5. In .env, disable internal SSL (Nginx handles it):
SSL_ENABLED=false
API_HOST=127.0.0.1
```

---

## 9. Configuration Reference

### Complete `.env` File Options

```bash
# ============ REQUIRED ============
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# ============ LLM SETTINGS ============
AGENT_MODEL=claude-sonnet-4-20250514     # Claude model to use
AGENT_MAX_TOKENS=4096                     # Max response length
AGENT_TEMPERATURE=0.1                     # Lower = more focused

# ============ OPTIONAL API KEYS ============
VIRUSTOTAL_API_KEY=your-vt-key            # For hash/domain/IP checks
ABUSEIPDB_API_KEY=your-abuse-key          # For IP reputation
SHODAN_API_KEY=your-shodan-key            # For internet scanning

# ============ SERVER SETTINGS ============
API_HOST=127.0.0.1                        # 0.0.0.0 for network access
API_PORT=8000                             # Server port
API_KEY=your-secret-api-key               # Auth key for API access

# ============ SECURITY ============
SSL_ENABLED=false                         # true for HTTPS
SSL_CERTFILE=certs/server.crt             # Path to TLS certificate
SSL_KEYFILE=certs/server.key              # Path to TLS private key
RATE_LIMIT_RPM=30                         # Requests per minute per IP
AUTH_LOCKOUT_ATTEMPTS=10                  # Failed auths before lockout
AUTH_LOCKOUT_MINUTES=15                   # Lockout duration
IP_ALLOWLIST=                             # Comma-separated allowed IPs
CORS_ORIGINS=http://localhost:8000        # Allowed CORS origins

# ============ LOGGING ============
LOG_LEVEL=INFO                            # DEBUG, INFO, WARNING, ERROR
AUDIT_LOG_FILE=audit.log                  # Audit trail file
```

---

## 10. API Endpoints Reference

All endpoints (except `/health` and `/`) require the `X-API-Key` header.

| Method | Endpoint | Description | Body |
|--------|----------|-------------|------|
| GET | `/` | Web UI dashboard | — |
| GET | `/health` | Health check (no auth needed) | — |
| GET | `/api/info` | API info + security status | — |
| POST | `/api/chat` | Chat with the AI agent | `{"query": "...", "session_id": "..."}` |
| POST | `/api/scan` | Port scan | `{"target": "IP", "port_range": "common"}` |
| POST | `/api/cve` | CVE search | `{"keyword": "log4j", "max_results": 5}` |
| POST | `/api/dns` | DNS recon | `{"domain": "...", "include_security": true}` |
| POST | `/api/reputation` | IP/Domain reputation | `{"target": "IP or domain"}` |
| POST | `/api/logs/analyze` | Log analysis | `{"log_content": "...", "log_type": "generic"}` |
| POST | `/api/hash/check` | Malware hash check | `{"hash_value": "sha256..."}` |
| POST | `/api/whois` | WHOIS lookup | `{"target": "domain or IP"}` |
| POST | `/api/geolocate` | IP geolocation | `{"ip_address": "..."}` |
| GET | `/api/sessions` | List conversation sessions | — |
| GET | `/api/sessions/{id}` | Get session history | — |
| GET | `/api/reports` | List generated reports | — |
| GET | `/api/reports/{file}` | View/download a report | — |
| POST | `/api/reports/generate` | Run query + generate report | `{"query": "..."}` |

### Example API Calls

```bash
# Chat
curl -k -X POST https://server:8000/api/chat \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the latest critical CVEs for Windows?"}'

# Scan ports
curl -k -X POST https://server:8000/api/scan \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "10.0.0.1", "port_range": "1-1024"}'

# Analyze logs
curl -k -X POST https://server:8000/api/logs/analyze \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"log_content": "Failed password for root from 192.168.1.50 port 22\nFailed password for root from 192.168.1.50 port 22\nFailed password for root from 192.168.1.50 port 22"}'
```

---

## 11. Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `ANTHROPIC_API_KEY not set` | Add your key to `.env` file |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` inside the venv |
| `Port 8000 already in use` | The agent auto-detects and uses 8001/8080. Or set `API_PORT=9000` in `.env` |
| `Connection refused` (from client) | Check firewall rules, ensure server uses `API_HOST=0.0.0.0` |
| `SSL certificate error` (client) | Use `-k` flag with curl, or import `certs/server.crt` into the client |
| `Rate limit exceeded` | Wait 60 seconds, or increase `RATE_LIMIT_RPM` in `.env` |
| `CVE search timeout` | NIST NVD API can be slow — retry after a minute |
| `UnicodeEncodeError` (Windows) | Already fixed in this version with ASCII-safe characters |
| Agent gives empty response | Check your `ANTHROPIC_API_KEY` is valid and has credits |

### Check if Everything is Working

```bash
# Test tools without needing an API key
python -c "
import sys; sys.path.insert(0, '.')
from tools.log_analyzer import analyze_logs
result = analyze_logs.invoke({'log_content': 'Failed password for root from 1.2.3.4'})
print(result)
"
```

### View Logs

```bash
# Application logs (printed to terminal)
# Audit logs (security events)
type audit.log        # Windows
cat audit.log         # Linux/macOS
```

---

## 12. Security Considerations

### For Production Deployment

1. **Use a strong API key** — Set `API_KEY` in `.env` (don't use the auto-generated one)
2. **Enable IP allowlist** — Add `IP_ALLOWLIST=trusted-ip-1,trusted-ip-2`
3. **Use proper TLS** — For internet-facing, use Let's Encrypt (not self-signed)
4. **Restrict CORS** — Set `CORS_ORIGINS` to your actual domain
5. **Monitor audit.log** — All auth attempts are logged
6. **Keep API keys secret** — Never commit `.env` to version control
7. **Update regularly** — `pip install -r requirements.txt --upgrade`

### What the Agent Can and Cannot Do

| CAN do | CANNOT do |
|--------|-----------|
| Scan ports on authorized targets | Execute exploits or attacks |
| Look up CVE vulnerabilities | Modify target systems |
| Analyze logs you provide | Access your local files automatically |
| Check IP/domain reputation | Bypass authentication |
| Generate security reports | Store data outside the project folder |
| Provide incident response guidance | Make decisions without your input |

### Legal Notice

This tool is for **authorized security testing and research only**. Always ensure you have explicit written permission before scanning or testing any systems you do not own. Unauthorized computer access is illegal in most jurisdictions.

---

## Quick Start Summary

```bash
# 1. Copy cyber_agent/ to new device
# 2. Install Python 3.11+
# 3. Run setup:
python -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
.\venv\Scripts\activate   # Windows

pip install -r requirements.txt

# 4. Configure:
cp .env.example .env
# Add ANTHROPIC_API_KEY=sk-ant-xxxxx

# 5. Run:
python cli.py chat        # Terminal
python api.py             # Web UI at http://localhost:8000
```

---

## 13. Cloud-Native Deployment (Kubernetes)

### Prerequisites

- Docker installed locally
- Terraform >= 1.5.0
- Helm >= 3.0
- AWS CLI configured (for EKS) and/or `gcloud` CLI configured (for GKE)
- kubectl installed

### Option A: Docker (Local/Single Server)

```bash
# Build and run with docker-compose
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs cyber-agent
```

### Option B: Deploy to AWS EKS

```bash
# 1. Provision infrastructure
cd infrastructure/environments/aws
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your AWS account details
terraform init
terraform plan
terraform apply

# 2. Connect to cluster
aws eks update-kubeconfig --region us-east-1 --name cyber-agent-prod

# 3. Deploy application
helm upgrade --install cyber-agent ../../../k8s/helm-chart \
  -f ../../../k8s/helm-chart/values.yaml \
  -f ../../../k8s/helm-chart/values-aws.yaml \
  --set secrets.anthropicApiKey="sk-ant-your-key" \
  --set secrets.virustotalApiKey="your-vt-key"

# 4. Verify
kubectl get pods
kubectl get ingress
```

### Option C: Deploy to GCP GKE

```bash
# 1. Provision infrastructure
cd infrastructure/environments/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your GCP project details
terraform init
terraform plan
terraform apply

# 2. Connect to cluster
gcloud container clusters get-credentials cyber-agent-prod \
  --region us-central1 --project your-project-id

# 3. Deploy application
helm upgrade --install cyber-agent ../../../k8s/helm-chart \
  -f ../../../k8s/helm-chart/values.yaml \
  -f ../../../k8s/helm-chart/values-gcp.yaml \
  --set secrets.anthropicApiKey="sk-ant-your-key"

# 4. Verify
kubectl get pods
kubectl get ingress
```

### Scaling & Monitoring

The Helm chart includes:
- **HPA**: Auto-scales pods based on CPU (70%) and memory (80%) utilization
- **PDB**: Ensures at least 1 pod is always available during disruptions
- **Network Policies**: Restricts traffic to HTTPS egress and HTTP ingress only
- **Resource Limits**: CPU 1 core max, 1Gi memory max per pod

### CI/CD Pipeline

The included GitHub Actions workflow (`.github/workflows/deploy.yml`) automates:
1. Lint and test on every PR
2. Build Docker image and push to both ECR and Artifact Registry
3. Terraform plan on PRs, apply on merge to main
4. Helm deploy to both EKS and GKE
5. Smoke test with automatic rollback on failure

Required GitHub Secrets:
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- `GCP_SA_KEY`, `GCP_PROJECT_ID`
- `ANTHROPIC_API_KEY`

### Teardown

```bash
# Remove Kubernetes deployment
helm uninstall cyber-agent

# Destroy infrastructure
cd infrastructure/environments/aws  # or gcp
terraform destroy
```

---

*Document Version: 3.0.0 | Last Updated: July 2026*
