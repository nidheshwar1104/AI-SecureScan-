# 🛡️ AI-SecureScan
### Agentic AI-Powered Vulnerability Scanner with Risk & Remediation Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-green)](https://openai.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Safe Mode](https://img.shields.io/badge/Safe%20Mode-Enabled%20by%20Default-brightgreen)](.env.example)

---

## 🎯 Overview

AI-SecureScan is a **production-quality, multi-agent AI system** that combines the power of OpenAI's language models with deterministic security rules to deliver a comprehensive vulnerability scanning and risk remediation pipeline.

Built to showcase:
- **Agentic AI Architecture** — specialized agents collaborating via shared memory
- **AI + Cybersecurity Integration** — LLMs augmenting deterministic rule engines
- **Secure Software Engineering** — no hardcoded secrets, injection prevention, safe subprocess execution
- **Clean Architecture** — fully modular, testable, and extensible

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
│   └── reporting_agent.py    # Generates professional Markdown reports
│
├── core/
│   ├── config.py             # Pydantic-based environment configuration
│   ├── llm_client.py         # OpenAI client with retry + token tracking
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
[StrategyAgent] ─── LLM generates safe nmap command ──► Validated Command
     │
     ▼
[ExecutionAgent] ── Runs command via subprocess (or mock) ──► Scan Output
     │
     ▼
[ReviewAgent] ───── LLM evaluates scan quality ──────────► YES / NO
     │
     ▼
[MitigationAgent] ─ LLM risk classification               ┐
                  ─ Deterministic risk engine score        ├──► Mitigation Report
                  ─ Composite score calculation            ┘
     │
     ▼
[ReportingAgent] ── LLM executive summary + assembly ────► Markdown Report
```

---

## ⚡ Quick Start

### Prerequisites

- Python 3.10+
- An [OpenAI API key](https://platform.openai.com/api-keys)
- `nmap` installed (only required when `SAFE_MODE=false`)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/AI-SecureScan.git
cd AI-SecureScan

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Run

```bash
# Scan with SAFE_MODE=true (default — no real nmap execution)
python main.py 192.168.1.1

# Scan a hostname
python main.py example.com

# Scan a CIDR range (set SAFE_MODE=false in .env first)
python main.py 10.0.0.0/24
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

### StrategyAgent
- Uses LLM to generate an optimized nmap command for the target
- Validates the command against a blocklist of dangerous patterns
- Ensures target appears in the generated command

### ExecutionAgent
- Executes the validated command via `subprocess` with `shell=False`
- Returns realistic mock output in `SAFE_MODE=true`
- Captures stdout and stderr separately

### ReviewAgent
- Analyzes scan output for completeness
- Returns binary `YES/NO` to indicate if re-scanning is needed

### MitigationAgent
- Calls LLM for qualitative risk assessment (risk level, steps, patches, CIS)
- Calls deterministic RiskEngine for mathematical score
- Computes composite score from both

### RiskEngine (Deterministic)
- Rule-based pattern matching on 30+ security indicators
- Scores critical ports, outdated services, insecure protocols
- Produces point deductions with severity labels — fully auditable

### ReportingAgent
- Assembles all agent outputs into a structured Markdown report
- Generates LLM-written executive summary for non-technical readers
- Saves to `reports/` with timestamp filename

---

## 📊 Scoring System

The composite Secure Score combines two independent signals:

```
AI Secure Score (LLM judgment)  +  Deterministic Score (rule engine)
─────────────────────────────────────────────────────────────────────
                    Composite Score = Average of both
```

**Score Interpretation:**
- **90–100** — Excellent: Well-hardened system
- **70–89** — Good: Minor improvements needed
- **50–69** — Fair: Moderate risk, action recommended
- **30–49** — Poor: High risk, immediate action required
- **0–29** — Critical: Severely exposed, urgent remediation needed

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | *(required)* | Your OpenAI API key |
| `MODEL` | `gpt-4o-mini` | OpenAI model to use |
| `SAFE_MODE` | `true` | Disable real scan execution |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `REQUEST_TIMEOUT` | `60` | OpenAI request timeout (seconds) |

---

## 💡 Cost Optimization

- Uses `gpt-4o-mini` by default (significantly cheaper than `gpt-4o`)
- Scan output truncated to 4000–5000 chars before LLM submission
- Single shared `LLMClient` instance (no redundant client initialization)
- Token usage and estimated cost printed at end of each run

---

## 🚀 Scaling to Enterprise

| Area | Recommendation |
|------|---------------|
| **Storage** | Replace `AgentMemory` with Redis for multi-process/distributed deployments |
| **Queue** | Add Celery + RabbitMQ for async scan job queuing |
| **Database** | Store reports in PostgreSQL with pgvector for semantic search |
| **Auth** | Add JWT-based API authentication layer |
| **API** | Wrap pipeline in FastAPI for REST access |
| **Containerization** | Dockerize with multi-stage build; use `nmap` base image |
| **Orchestration** | Deploy to Kubernetes with HPA for scan workloads |
| **Secrets** | Use HashiCorp Vault or AWS Secrets Manager instead of `.env` |
| **LLM Routing** | Add LiteLLM for model fallback (GPT-4o → Sonnet → Gemini) |
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

*Built with ❤️ using Python 3.10+ · OpenAI API · nmap · Pydantic*
