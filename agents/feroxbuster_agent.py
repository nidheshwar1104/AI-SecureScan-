"""
feroxbuster_agent.py
--------------------
Runs Feroxbuster for recursive web directory and file brute-forcing.
Discovers hidden endpoints, admin panels, config files, and sensitive paths.

Feroxbuster is a fast, recursive content discovery tool written in Rust.
Install: https://github.com/epi052/feroxbuster
  sudo apt install feroxbuster   (Kali/Ubuntu)
  cargo install feroxbuster      (from source)
"""

import re
import logging
from dataclasses import dataclass, field

from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.config import settings

logger = logging.getLogger("AI-SecureScan.FeroxbusterAgent")

# ── Mock output simulating a real feroxbuster scan ───────────────────────────
SAFE_MODE_MOCK_OUTPUT = """
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    |__) |  | /__` |__
|    |___ |  \ |  \ | \__,    |__) \__/ .__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1

Auto-filtering responses with: Len = 0; Words = 0; Lines = 0;
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
200      GET   admin/                    [Size: 2048]
200      GET   admin/login.php           [Size: 1337]
200      GET   admin/config.php          [Size: 512]
301      GET   images/                   [Size: 0]
200      GET   backup/                   [Size: 4096]
200      GET   backup/db_backup.sql      [Size: 204800]
200      GET   .git/                     [Size: 256]
200      GET   .git/config               [Size: 92]
200      GET   wp-admin/                 [Size: 3072]
200      GET   wp-login.php              [Size: 2891]
200      GET   phpinfo.php               [Size: 75000]
403      GET   cgi-bin/                  [Size: 289]
200      GET   uploads/                  [Size: 1024]
200      GET   api/v1/users              [Size: 532]
200      GET   api/v1/admin              [Size: 741]
200      GET   .env                      [Size: 312]
200      GET   config.yml                [Size: 128]
200      GET   server-status             [Size: 6792]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[####################] 100%  10000/10000 reqs/sec
""".strip()

# Critical paths that indicate serious security issues
CRITICAL_PATHS = [
    (r"\.git/",               "CRITICAL", "Git repository exposed — source code leak risk"),
    (r"\.env\b",              "CRITICAL", ".env file exposed — API keys/passwords at risk"),
    (r"db_backup|\.sql\b",   "CRITICAL", "Database backup file publicly accessible"),
    (r"phpinfo\.php",         "HIGH",     "phpinfo.php exposed — reveals server configuration"),
    (r"admin/",               "HIGH",     "Admin panel discovered"),
    (r"wp-admin|wp-login",    "HIGH",     "WordPress admin panel exposed"),
    (r"config\.php|config\.yml|config\.json", "HIGH", "Configuration file exposed"),
    (r"backup/",              "HIGH",     "Backup directory accessible"),
    (r"api/v\d+/admin",       "HIGH",     "Admin API endpoint discovered"),
    (r"api/v\d+/users",       "MEDIUM",   "User API endpoint discovered"),
    (r"server-status",        "MEDIUM",   "Apache server-status exposed"),
    (r"uploads/",             "MEDIUM",   "Uploads directory accessible"),
    (r"phpMyAdmin",           "HIGH",     "phpMyAdmin panel exposed"),
]

SYSTEM_PROMPT = """You are a web application security expert analyzing Feroxbuster directory enumeration results.
Review the discovered paths and provide a structured JSON security analysis.

Respond ONLY with valid JSON — no markdown, no explanation.

{
  "critical_findings": ["list of the most dangerous discovered paths"],
  "risk_summary": "2-3 sentence summary of web application exposure",
  "attack_vectors": ["potential attack paths an adversary could exploit"],
  "remediation": ["specific fixes for each critical finding"],
  "web_risk_score": <integer 0-100, 100=fully exposed>
}
"""

FALLBACK = {
    "critical_findings": ["Manual review required"],
    "risk_summary": "Unable to parse AI analysis. Review raw output manually.",
    "attack_vectors": ["Unknown"],
    "remediation": ["Review and restrict access to all discovered sensitive paths"],
    "web_risk_score": 50,
}


@dataclass
class FeroxbusterResult:
    """Structured result from a Feroxbuster scan."""
    raw_output: str
    discovered_paths: list[dict] = field(default_factory=list)
    critical_findings: list[str] = field(default_factory=list)
    ai_analysis: dict = field(default_factory=dict)
    safe_mode: bool = True


class FeroxbusterAgent(BaseAgent):
    """
    Performs recursive web directory brute-forcing using Feroxbuster.

    Discovers:
    - Hidden admin panels
    - Exposed configuration files
    - Git repositories and backup files
    - API endpoints
    - Sensitive directories

    In SAFE_MODE: returns realistic mock output for demonstration.
    """

    COMMAND_TIMEOUT = 300  # 5 minutes for deep scans
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("FeroxbusterAgent", llm_client, memory)

    def run(self, target: str, port: int = 80) -> FeroxbusterResult:
        """
        Run Feroxbuster against the target web server.

        Args:
            target: IP or hostname to scan.
            port: Web server port (default 80; use 443 for HTTPS).

        Returns:
            FeroxbusterResult with discovered paths and AI analysis.
        """
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}:{port}"
        self.logger.info(f"Starting Feroxbuster scan against: {url}")

        if settings.safe_mode:
            self.logger.warning("SAFE_MODE=true — returning mock Feroxbuster output")
            raw_output = SAFE_MODE_MOCK_OUTPUT
            safe_mode = True
        else:
            raw_output = self._run_feroxbuster(url)
            safe_mode = False

        # Parse discovered paths
        discovered = self._parse_paths(raw_output)

        # Flag critical findings deterministically
        critical = self._flag_critical(raw_output)

        # AI analysis
        ai_analysis = self._ai_analyze(raw_output, url)

        result = FeroxbusterResult(
            raw_output=raw_output,
            discovered_paths=discovered,
            critical_findings=critical,
            ai_analysis=ai_analysis,
            safe_mode=safe_mode,
        )

        self.memory.store("feroxbuster_result", {
            "url": url,
            "discovered_count": len(discovered),
            "critical_count": len(critical),
            "ai_analysis": ai_analysis,
            "raw_output": raw_output,
        })

        self.logger.info(
            f"Feroxbuster complete | Paths: {len(discovered)} | Critical: {len(critical)}"
        )
        return result

    def _run_feroxbuster(self, url: str) -> str:
        """Execute Feroxbuster via subprocess securely."""
        import shlex, subprocess
        command = (
            f"feroxbuster --url {url} "
            f"--wordlist {self.DEFAULT_WORDLIST} "
            f"--depth 3 --threads 50 --timeout 10 "
            f"--no-state --quiet"
        )
        args = shlex.split(command)
        if args[0] != "feroxbuster":
            raise ValueError("Only feroxbuster is permitted as executable.")
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True,
                timeout=self.COMMAND_TIMEOUT, shell=False
            )
            return proc.stdout or proc.stderr or "No output captured."
        except FileNotFoundError:
            return "ERROR: feroxbuster not found. Install: sudo apt install feroxbuster"
        except subprocess.TimeoutExpired:
            return "ERROR: Feroxbuster timed out after 5 minutes."
        except Exception as e:
            self.logger.exception(f"Feroxbuster execution error: {e}")
            return f"ERROR: {e}"

    def _parse_paths(self, output: str) -> list[dict]:
        """Extract status codes and paths from feroxbuster output."""
        paths = []
        pattern = re.compile(r"(\d{3})\s+GET\s+(.+?)\s+\[Size: (\d+)\]")
        for match in pattern.finditer(output):
            status, path, size = match.groups()
            paths.append({
                "status_code": int(status),
                "path": path.strip(),
                "size": int(size),
            })
        return paths

    def _flag_critical(self, output: str) -> list[str]:
        """Deterministically flag critical paths from the scan output."""
        findings = []
        for pattern, severity, description in CRITICAL_PATHS:
            if re.search(pattern, output, re.IGNORECASE):
                findings.append(f"[{severity}] {description}")
        return findings

    def _ai_analyze(self, output: str, url: str) -> dict:
        """Use LLM to provide qualitative analysis of discoveries."""
        user_prompt = (
            f"Target URL: {url}\n\n"
            f"Feroxbuster output:\n```\n{output[:4000]}\n```\n\n"
            f"Provide the JSON security analysis."
        )
        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        return self._parse_json_response(raw, FALLBACK)
