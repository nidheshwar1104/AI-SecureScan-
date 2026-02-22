# 🛡️ AI-SecureScan
### Agentic AI-Powered Vulnerability Scanner with Risk & Remediation Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![Groq](https://img.shields.io/badge/Groq-llama--3.3--70b--versatile-orange)](https://console.groq.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Safe Mode](https://img.shields.io/badge/Safe%20Mode-Enabled%20by%20Default-brightgreen)](.env.example)
[![Agents](https://img.shields.io/badge/Agents-8-green)]()
[![Tools](https://img.shields.io/badge/Tools-nmap%20%7C%20nikto%20%7C%20feroxbuster%20%7C%20enum4linux-red)]()
[![Kali](https://img.shields.io/badge/Kali-Linux-purple)]()

---

## 🎯 Overview

AI-SecureScan is a **production-quality, multi-agent AI system** that combines the power of Groq's ultra-fast LLM inference with deterministic security rules to deliver a comprehensive vulnerability scanning and risk remediation pipeline.

Built to showcase:
- **Agentic AI Architecture** — 8 specialized agents collaborating via shared memory
- **AI + Cybersecurity Integration** — LLMs augmenting deterministic rule engines
- **Secure Software Engineering** — no hardcoded secrets, injection prevention, safe subprocess execution
- **Clean Architecture** — fully modular, testable, and extensible

---

## ⚡ Why Groq?

- 🚀 **10x faster** than OpenAI for LLM inference
- 💰 **Free tier available** — get started at no cost
- 🧠 **llama-3.3-70b-versatile** — powerful open-source model
- 🔑 Get your free API key → [console.groq.com](https://console.groq.com)

---

## 🏗️ Architecture

```
AI-SecureScan/
│
├── agents/
│   ├── base_agent.py         # Abstract base with shared LLM + JSON parsing
│   ├── strategy_agent.py     # Generates safe nmap scan commands via LLM
│   ├── execution_agent.py    # Executes commands securely (respects SAFE_MODE)
│   ├── review_agent.py       # Determines if additional scanning is needed
│   ├── mitigation_agent.py   # AI risk classification + mitigation planning
│   ├── feroxbuster_agent.py  # Web directory brute-forcing
│   ├── enumeration_agent.py  # SMB/DNS/HTTP/SNMP enumeration
│   ├── nikto_agent.py        # Web vulnerability scanning
│   └── reporting_agent.py    # Generates professional Markdown reports
│
├── core/
│   ├── config.py             # Pydantic-based environment configuration
│   ├── llm_client.py         # Groq client with retry + token tracking
│   ├── memory.py             # Shared in-memory agent context store
│   └── risk_engine.py        # Deterministic mathematical scoring engine
│
├── reports/                  # Generated scan reports (gitignored)
├── logs/                     # Application logs (gitignored)
│
├── main.py                   # Pipeline orchestrator
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

### Pipeline Flow

```
Target IP/Host
        │
        ▼
[1] [StrategyAgent]    ── LLM generates safe nmap command ──► Validated Command
        │
        ▼
[2] [ExecutionAgent]   ── Runs nmap via subprocess ──────────► Scan Output
        │
        ▼
[3] [ReviewAgent]      ── LLM evaluates scan quality ────────► YES / NO
        │
        ▼
[4] [FeroxbusterAgent] ── Web directory brute-force ─────────► Hidden Paths
        │
        ▼
[5] [EnumerationAgent] ── SMB/DNS/HTTP/SNMP enum ────────────► Attack Surface
        │
        ▼
[6] [NiktoAgent]       ── Web vulnerability scan ────────────► CVEs & Misconfigs
        │
        ▼
[7] [MitigationAgent]  ── AI + Deterministic scoring ────────► Risk Report
        │
        ▼
[8] [ReportingAgent]   ── Unified Markdown report ───────────► Final Report
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.10+
- A free Groq API key → [console.groq.com](https://console.groq.com)
- `nmap`, `nikto`, `feroxbuster`, `enum4linux` (only required when `SAFE_MODE=false`)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/nidhesh1104/AI-SecureScan.git
cd AI-SecureScan

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### Install Scanning Tools (Kali Linux)

```bash
sudo apt update
sudo apt install nmap nikto feroxbuster enum4linux -y
```

### Run

```bash
# Scan with SAFE_MODE=true (default — no real execution, uses mock data)
python main.py 192.168.1.1

# Scan with specific port
python main.py 192.168.1.1 --port 80

# Scan with domain for DNS enumeration
python main.py 192.168.1.1 --port 80 --domain example.com

# Real scan (set SAFE_MODE=false in .env first)
python main.py 192.168.1.1 --port 80
```

---

## 🔐 Security Design

| Concern | Solution |
|---------|----------|
| API Key exposure | `python-dotenv` + `.gitignore` — never hardcoded |
| Shell injection | `shlex.split()` + `shell=False` in subprocess |
| Command validation | Regex blocklist on dangerous patterns/flags |
| Unsafe commands | Only `nmap` allowed as executable |
| Execution control | `SAFE_MODE=true` prevents all real execution |
| Subprocess timeout | 120-second hard timeout per scan |
| LLM output safety | JSON parsing with structured fallback |

---

## 🧠 Agent Responsibilities

### [1] StrategyAgent
- Uses Groq LLM to generate an optimized nmap command for the target
- Validates the command against a blocklist of dangerous patterns
- Ensures target appears in the generated command

### [2] ExecutionAgent
- Executes the validated command via `subprocess` with `shell=False`
- Returns realistic mock output in `SAFE_MODE=true`
- Captures stdout and stderr separately

### [3] ReviewAgent
- Analyzes scan output for completeness
- Returns binary `YES/NO` to indicate if re-scanning is needed

### [4] FeroxbusterAgent
- Recursively brute-forces web directories
- Discovers hidden admin panels, `.git/`, `.env`, backup files, API endpoints
- 14 deterministic critical-path detection rules

### [5] EnumerationAgent
- **SMB** — user accounts, shares, password policy (enum4linux)
- **DNS** — subdomains, MX records, zone transfer attempts (dnsrecon)
- **HTTP** — security headers, server info, cookie flags (curl)
- **SNMP** — system info, running processes (snmpwalk)

### [6] NiktoAgent
- Detects outdated server software (Apache, PHP, nginx)
- Finds missing HTTP security headers (CSP, HSTS, X-Frame-Options)
- Reports cookie security issues and CVE/OSVDB references
- Discovers WordPress, phpMyAdmin, and other CMS panels

### [7] MitigationAgent
- Calls Groq LLM for qualitative risk assessment (risk level, steps, patches, CIS)
- Calls deterministic RiskEngine for mathematical score
- Computes composite score from both

### [8] RiskEngine (Deterministic)
- Rule-based pattern matching on 50+ security indicators
- Scores critical ports, outdated services, insecure protocols, web vulnerabilities
- Produces point deductions with severity labels — fully auditable

### ReportingAgent
- Assembles all 8 agent outputs into a unified Markdown report
- Generates LLM-written executive summary for non-technical readers
- Saves to `reports/` with timestamp filename

---

## 📊 Scoring System

The composite Secure Score combines two independent signals:

```
AI Secure Score (Groq LLM judgment)  +  Deterministic Score (rule engine)
──────────────────────────────────────────────────────────────────────────
                    Composite Score = Average of both
```

**Score Interpretation:**
- **90–100** — Excellent: Well-hardened system
- **70–89**  — Good: Minor improvements needed
- **50–69**  — Fair: Moderate risk, action recommended
- **30–49**  — Poor: High risk, immediate action required
- **0–29**   — Critical: Severely exposed, urgent remediation needed

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | *(required)* | Your Groq API key — free at console.groq.com |
| `MODEL` | `llama-3.3-70b-versatile` | Groq model to use |
| `SAFE_MODE` | `true` | Disable real scan execution |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `REQUEST_TIMEOUT` | `60` | API request timeout (seconds) |

### .env Example

```env
GROQ_API_KEY=gsk_your_key_here
MODEL=llama-3.3-70b-versatile
SAFE_MODE=true
LOG_LEVEL=INFO
REQUEST_TIMEOUT=60
```

---

## 💡 Cost Optimization

- Uses `llama-3.3-70b-versatile` via Groq — **free tier available**
- Scan output truncated to 4000–5000 chars before LLM submission
- Single shared `LLMClient` instance (no redundant client initialization)
- Token usage and estimated cost printed at end of each run
- **Typical cost per full scan: ~$0.001**

---

## 🚀 Scaling to Enterprise

| Area | Recommendation |
|------|---------------|
| **Storage** | Replace `AgentMemory` with Redis for distributed deployments |
| **Queue** | Add Celery + RabbitMQ for async scan job queuing |
| **Database** | Store reports in PostgreSQL with pgvector for semantic search |
| **Auth** | Add JWT-based API authentication layer |
| **API** | Wrap pipeline in FastAPI for REST access |
| **Containerization** | Dockerize with multi-stage build; use `nmap` base image |
| **Orchestration** | Deploy to Kubernetes with HPA for scan workloads |
| **Secrets** | Use HashiCorp Vault or AWS Secrets Manager instead of `.env` |
| **LLM Routing** | Add LiteLLM for model fallback (Groq → OpenAI → Gemini) |
| **Monitoring** | Integrate OpenTelemetry + Grafana for pipeline observability |

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security assessments only**.
Scanning systems without explicit written permission is **illegal** in most jurisdictions.
The authors assume no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ using Python 3.10+ · Groq API · llama-3.3-70b-versatile · nmap · nikto · feroxbuster · enum4linux · Pydantic*
