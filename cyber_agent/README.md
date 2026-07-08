# Cybersecurity AI Agent

[![Build & Deploy](https://github.com/YOUR_USERNAME/cyber-agent/actions/workflows/deploy.yml/badge.svg)](https://github.com/YOUR_USERNAME/cyber-agent/actions/workflows/deploy.yml)

An AI-powered cybersecurity automation agent built with **LangGraph**, **Anthropic Claude**, and **FastAPI**. Deployed on **AWS EKS** and **GCP GKE** with full Infrastructure-as-Code (Terraform), Kubernetes Helm charts, and CI/CD pipelines.

It provides a CLI, REST API, and web dashboard for security analysis — including cloud-native security scanning for AWS GuardDuty, GCP Security Command Center, Kubernetes RBAC auditing, and IAM posture analysis.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **AI/LLM** | LangGraph, Anthropic Claude, LangChain |
| **Backend** | FastAPI, Python 3.11, Uvicorn |
| **Cloud** | AWS (EKS, ECR, VPC, GuardDuty), GCP (GKE, Artifact Registry, Cloud Armor, SCC) |
| **IaC** | Terraform (modular, dual-cloud) |
| **Orchestration** | Kubernetes, Helm, HPA, Network Policies |
| **CI/CD** | GitHub Actions (build → push → terraform → helm → smoke test) |
| **Containerization** | Docker (multi-stage, non-root) |
| **Monitoring** | CloudWatch, GCP Cloud Monitoring, Prometheus |

## Features

| Tool | Description |
|------|-------------|
| **CVE Search** | Search NIST NVD for vulnerabilities by keyword or CVE ID |
| **Port Scanner** | Scan targets for open ports with service detection |
| **DNS Recon** | DNS lookups, reverse DNS, SPF/DMARC security checks |
| **IP Reputation** | Check IPs against AbuseIPDB and VirusTotal |
| **Domain Reputation** | Check domains against VirusTotal threat feeds |
| **Log Analyzer** | Detect brute force, SQLi, XSS, command injection in logs |
| **Hash Checker** | Check file hashes against malware databases |
| **WHOIS Lookup** | Domain/IP registration information |
| **Geolocation** | IP geolocation with hosting/proxy detection |
| **Skills Library** | 762 cybersecurity skills for enhanced analysis context |

---

## Quick Start (One-Click Setup)

The fastest way to get running — handles everything automatically:

```
Double-click:  one_click_setup.bat
```

This will:
1. Check Python 3.10+ is installed
2. Create a virtual environment and install all dependencies
3. Prompt you to paste your **Anthropic API key** (get one at [console.anthropic.com](https://console.anthropic.com/))
4. Optionally configure VirusTotal, AbuseIPDB, and Shodan keys
5. Validate your API key against Anthropic's server
6. Optionally register auto-start on boot
7. Launch the agent (Web UI or CLI — your choice)

---

## Prerequisites

### 1. Python 3.10+

Download from [python.org/downloads](https://www.python.org/downloads/). During installation, **check "Add Python to PATH"**.

Verify:
```cmd
python --version
```

### 2. Anthropic API Key (Required)

1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Sign up or log in
3. Navigate to **API Keys**
4. Click **Create Key**
5. Copy the key (starts with `sk-ant-`)

### 3. Optional API Keys

| Key | Source | Enables |
|-----|--------|---------|
| VirusTotal | [virustotal.com](https://www.virustotal.com/) | Malware hash checks, domain reputation |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/) | IP reputation scoring |
| Shodan | [shodan.io](https://www.shodan.io/) | Internet-wide device scanning |

---

## Manual Setup (Step-by-Step)

If you prefer manual setup or the one-click script encounters issues:

### Step 1: Create Virtual Environment

```cmd
cd cyber_agent
python -m venv venv
venv\Scripts\activate
```

### Step 2: Install Dependencies

```cmd
pip install -r requirements.txt
```

### Step 3: Configure API Keys

```cmd
copy .env.example .env
notepad .env
```

Replace `your-anthropic-api-key-here` with your actual API key:
```
ANTHROPIC_API_KEY=sk-ant-your-actual-key-here
```

Save and close.

### Step 4: Verify Installation

```cmd
python -c "import langchain_anthropic; import langgraph; import fastapi; print('All packages OK')"
```

---

## Running the Agent

### Web UI (Recommended)

```cmd
start-web.bat
```

Opens a browser dashboard at [http://127.0.0.1:8000](http://127.0.0.1:8000) with chat interface, tool results, and report generation.

### CLI Chat

```cmd
start-cli.bat
```

Interactive terminal chat. Type security questions, get analysis. Type `exit` to quit.

### Quick Tool Tests

```cmd
test-tools.bat
```

Runs sample CVE search, DNS lookup, and agent query to verify everything works.

### Manual Commands

```cmd
venv\Scripts\activate

:: Interactive chat
python cli.py chat

:: Single query
python cli.py query "Search for CVEs related to OpenSSL"

:: Quick commands
python cli.py scan scanme.nmap.org
python cli.py cve "log4j"
python cli.py cve CVE-2021-44228
python cli.py dns example.com --security
python cli.py reputation 45.33.32.156

:: Start web server
python api.py
```

---

## Auto-Start on Boot

Register the agent to start automatically when your computer boots:

```cmd
auto_start_setup.bat
```

- **As Administrator:** Creates a system-level task (runs before login)
- **As Standard User:** Creates a user-level task (runs when you log in)

Includes port conflict detection — won't crash if already running.

To remove:
```cmd
auto_start_remove.bat
```

---

## Multi-Device Deployment

To access the agent from other devices on your network:

1. **Edit `.env`:**
   ```
   API_HOST=0.0.0.0
   SSL_ENABLED=true
   ```

2. **Generate TLS certificates:**
   ```cmd
   python generate_certs.py
   ```

3. **Open firewall port:**
   ```cmd
   netsh advfirewall firewall add rule name="CyberSecAgent" dir=in action=allow protocol=TCP localport=8000
   ```

4. **Connect from other devices:**
   ```
   https://SERVER_IP:8000
   ```

---

## API Reference

All endpoints under `/api/` require an `X-API-Key` header. The key is printed at server startup (or set `API_KEY` in `.env`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web dashboard |
| GET | `/health` | Health check + system info |
| GET | `/api/info` | API configuration info |
| GET | `/api/sessions` | List conversation sessions |
| GET | `/api/sessions/{id}` | Load conversation history |
| POST | `/api/chat` | Send query to AI agent |
| POST | `/api/scan` | Port scan a target |
| POST | `/api/cve` | Search CVE vulnerabilities |
| POST | `/api/dns` | DNS reconnaissance |
| POST | `/api/reputation` | Check IP/domain reputation |
| POST | `/api/logs/analyze` | Analyze security logs |
| POST | `/api/hash/check` | Check file hash |
| POST | `/api/whois` | WHOIS lookup |
| POST | `/api/geolocate` | IP geolocation |
| GET | `/api/reports` | List generated reports |
| POST | `/api/reports/generate` | Generate combined report |
| GET | `/docs` | Interactive API documentation (Swagger) |

### Example

```cmd
curl -X POST http://127.0.0.1:8000/api/cve ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: YOUR_KEY" ^
  -d "{\"keyword\": \"log4j\"}"
```

---

## Configuration

Edit `.env` to configure:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Claude API key |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal for hash/domain checks |
| `ABUSEIPDB_API_KEY` | No | — | AbuseIPDB for IP reputation |
| `SHODAN_API_KEY` | No | — | Shodan for internet scanning |
| `API_KEY` | No | Auto-generated | API authentication key |
| `API_HOST` | No | 127.0.0.1 | Bind address (0.0.0.0 for remote) |
| `API_PORT` | No | 8000 | Server port (auto-fallback if taken) |
| `RATE_LIMIT_RPM` | No | 30 | Rate limit per IP per minute |
| `AUTH_LOCKOUT_ATTEMPTS` | No | 10 | Failed auth before IP lockout |
| `AUTH_LOCKOUT_MINUTES` | No | 15 | Lockout duration |
| `SSL_ENABLED` | No | false | Enable HTTPS |
| `LOG_LEVEL` | No | INFO | Logging verbosity |

---

## Project Structure

```
cyber_agent/
├── agent/
│   ├── graph.py            # LangGraph agent orchestration (RAO loop)
│   ├── state.py            # Agent state schema
│   ├── prompts.py          # System prompts for Claude
│   └── skills_loader.py    # 762-skill cybersecurity knowledge base
├── tools/
│   ├── cve_lookup.py       # CVE/NVD search
│   ├── port_scanner.py     # Network port scanning (SSRF-protected)
│   ├── dns_recon.py        # DNS reconnaissance
│   ├── ip_reputation.py    # IP/Domain reputation
│   ├── log_analyzer.py     # Security log analysis (10 attack types)
│   ├── hash_checker.py     # Malware hash checking
│   └── network_utils.py    # WHOIS & geolocation
├── web/
│   └── index.html          # Browser dashboard UI
├── data/
│   └── agent_state.db      # SQLite persistence (auto-created)
├── reports/                # Generated HTML security reports
├── api.py                  # FastAPI REST API + web server
├── cli.py                  # Rich CLI interface
├── config.py               # Configuration (privilege detection, port fallback)
├── persistence.py          # SQLite state persistence across restarts
├── report_generator.py     # HTML report generation engine
├── generate_certs.py       # TLS certificate generator
├── one_click_setup.bat     # Automated one-click installer
├── setup.bat               # Manual setup script
├── start-web.bat           # Launch web UI
├── start-cli.bat           # Launch CLI
├── test-tools.bat          # Quick tool tests
├── auto_start_setup.bat    # Register auto-start on boot
├── auto_start_remove.bat   # Remove auto-start
├── requirements.txt        # Python dependencies
├── .env.example            # Configuration template
└── .env                    # Your configuration (created during setup)
```

---

## Security Features

- API authentication via `X-API-Key` header
- Rate limiting (configurable, default 30 req/min per IP)
- Brute-force lockout (10 failed attempts = 15 min IP ban)
- SSRF protection on port scanner (blocks localhost, link-local, reserved ranges)
- CORS restricted to localhost by default
- Binds to 127.0.0.1 by default (not exposed to network)
- TLS/HTTPS support for remote deployment
- SQLite persistence survives restarts with WAL mode
- Graceful shutdown with state preservation
- Admin/non-admin privilege detection with automatic port fallback
- Audit logging of all auth events

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Python not found" | Install Python 3.10+ and check "Add to PATH". Restart terminal. |
| pip install fails | Check internet. Behind proxy: `pip install --proxy http://proxy:port -r requirements.txt` |
| Port 8000 in use | Agent auto-tries 8001, 8080, 8443, 9000. Check console for actual port. |
| API key invalid | Verify at console.anthropic.com. Must start with `sk-ant-`. No extra spaces. |
| Agent crashes | Check `data/startup.log`. Try deleting `data/agent_state.db` and restart. |
| ModuleNotFoundError | Activate venv first: `venv\Scripts\activate` |
| Auto-start not working | Run `auto_start_setup.bat` as Administrator |

### Reset Everything

```cmd
rmdir /s /q venv
del .env
del data\agent_state.db
one_click_setup.bat
```

---

## Cloud Infrastructure & Kubernetes

This project includes full cloud-native deployment infrastructure for both AWS and GCP.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  CI/CD (GitHub Actions)                                     │
│  Build → Push → Terraform → Helm Deploy → Smoke Test       │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
    ┌──────────▼──────────┐    ┌──────────▼──────────┐
    │  AWS                │    │  GCP                │
    │  ├─ VPC (3 AZ)      │    │  ├─ VPC + Subnets   │
    │  ├─ EKS Cluster     │    │  ├─ GKE Cluster     │
    │  ├─ ECR Registry    │    │  ├─ Artifact Reg.   │
    │  ├─ CloudWatch      │    │  ├─ Cloud Monitor.  │
    │  └─ GuardDuty       │    │  └─ Cloud Armor     │
    └─────────────────────┘    └─────────────────────┘
```

### Quick Start (Docker)

```cmd
docker-compose up -d
```

### Deploy to AWS (EKS)

```bash
cd infrastructure/environments/aws
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform apply

# Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name cyber-agent-prod

# Deploy with Helm
helm upgrade --install cyber-agent ./k8s/helm-chart \
  -f ./k8s/helm-chart/values-aws.yaml \
  --set secrets.anthropicApiKey=YOUR_KEY
```

### Deploy to GCP (GKE)

```bash
cd infrastructure/environments/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform apply

# Configure kubectl
gcloud container clusters get-credentials cyber-agent-prod --region us-central1

# Deploy with Helm
helm upgrade --install cyber-agent ./k8s/helm-chart \
  -f ./k8s/helm-chart/values-gcp.yaml \
  --set secrets.anthropicApiKey=YOUR_KEY
```

### Cloud Security Tools

The agent includes cloud-native security scanning capabilities:

| Tool | Description |
|------|-------------|
| **GuardDuty Scanner** | List/analyze AWS GuardDuty findings and threat intel |
| **Security Hub** | AWS Security Hub findings summary |
| **GCP SCC** | Security Command Center findings and vulnerability reports |
| **GCP Asset Inventory** | Query Cloud Asset Inventory |
| **K8s RBAC Audit** | Detect overly permissive roles and bindings |
| **K8s Pod Security** | Audit pod security contexts and misconfigs |
| **K8s Exposed Services** | Find externally exposed services |
| **K8s Image Audit** | Check for untagged/latest images |
| **AWS IAM Audit** | Detect admin users, missing MFA, stale keys |
| **GCP IAM Audit** | Find primitive roles, public access, SA misuse |

### Infrastructure Structure

```
infrastructure/
├── modules/
│   ├── networking/          # VPC, subnets, NAT (AWS & GCP)
│   ├── eks-cluster/         # AWS EKS + node groups + IRSA
│   ├── gke-cluster/         # GCP GKE + Cloud Armor
│   ├── container-registry/  # ECR + Artifact Registry
│   └── monitoring/          # CloudWatch + Cloud Monitoring
├── environments/
│   ├── aws/                 # AWS production config
│   └── gcp/                 # GCP production config
k8s/
└── helm-chart/              # Kubernetes deployment (EKS/GKE)
    ├── templates/           # Deployment, HPA, NetworkPolicy, PDB
    ├── values-aws.yaml      # EKS overrides (ALB, IRSA)
    └── values-gcp.yaml      # GKE overrides (Workload Identity)
```

---

## Skills Library

Integrates with the [Anthropic Cybersecurity Skills](../Anthropic-Cybersecurity-Skills/) library (762 skills across 26+ security domains). The agent automatically loads relevant skill procedures as context, mapped to MITRE ATT&CK and NIST CSF frameworks.

---

## Legal Disclaimer

This tool is for **authorized security testing and research only**. Always ensure you have explicit permission before scanning or testing any systems you do not own.
