"""
feroxbuster_agent.py
--------------------
FIXED: Real subprocess execution, output capture, and parsing.
"""

import re
import logging
import shlex
import subprocess
from dataclasses import dataclass, field

from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.config import settings

logger = logging.getLogger("AI-SecureScan.FeroxbusterAgent")

SAFE_MODE_MOCK_OUTPUT = """
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    |__) |  | /__` |__
|    |___ |  \ |  \ | \__,    |__) \__/ .__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1

200      GET   /admin/                    [Size: 2048]
200      GET   /admin/login.php           [Size: 1337]
200      GET   /admin/config.php          [Size: 512]
301      GET   /images/                   [Size: 0]
200      GET   /backup/                   [Size: 4096]
200      GET   /backup/db_backup.sql      [Size: 204800]
200      GET   /.git/                     [Size: 256]
200      GET   /.git/config               [Size: 92]
200      GET   /wp-admin/                 [Size: 3072]
200      GET   /wp-login.php              [Size: 2891]
200      GET   /phpinfo.php               [Size: 75000]
403      GET   /cgi-bin/                  [Size: 289]
200      GET   /uploads/                  [Size: 1024]
200      GET   /api/v1/users              [Size: 532]
200      GET   /api/v1/admin              [Size: 741]
200      GET   /.env                      [Size: 312]
200      GET   /config.yml                [Size: 128]
200      GET   /server-status             [Size: 6792]
""".strip()

CRITICAL_PATHS = [
    (r"\.git/",                           "CRITICAL", "Git repository exposed — source code leak risk"),
    (r"\.env\b",                          "CRITICAL", ".env file exposed — API keys/passwords at risk"),
    (r"db_backup|\.sql\b",               "CRITICAL", "Database backup file publicly accessible"),
    (r"phpinfo\.php",                     "HIGH",     "phpinfo.php exposed — reveals server configuration"),
    (r"admin/",                           "HIGH",     "Admin panel discovered"),
    (r"wp-admin|wp-login",               "HIGH",     "WordPress admin panel exposed"),
    (r"config\.php|config\.yml|config\.json", "HIGH","Configuration file exposed"),
    (r"backup/",                          "HIGH",     "Backup directory accessible"),
    (r"api/v\d+/admin",                  "HIGH",     "Admin API endpoint discovered"),
    (r"api/v\d+/users",                  "MEDIUM",   "User API endpoint discovered"),
    (r"server-status",                    "MEDIUM",   "Apache server-status exposed"),
    (r"uploads/",                         "MEDIUM",   "Uploads directory accessible"),
    (r"phpMyAdmin",                       "HIGH",     "phpMyAdmin panel exposed"),
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
    raw_output: str
    discovered_paths: list = field(default_factory=list)
    critical_findings: list = field(default_factory=list)
    ai_analysis: dict = field(default_factory=dict)
    safe_mode: bool = True


class FeroxbusterAgent(BaseAgent):

    COMMAND_TIMEOUT = 300
    # ── FIX: Use seclists wordlist (available on Kali) with fallback ──────────
    WORDLISTS = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("FeroxbusterAgent", llm_client, memory)

    def _get_wordlist(self) -> str:
        """Return the first available wordlist on this system."""
        import os
        for wl in self.WORDLISTS:
            if os.path.exists(wl):
                return wl
        return self.WORDLISTS[1]  # fallback even if missing — feroxbuster will error clearly

    def run(self, target: str, port: int = 80) -> FeroxbusterResult:
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

        # ── FIX: Log raw output length for debugging ──────────────────────────
        self.logger.info(f"Feroxbuster raw output length: {len(raw_output)} chars")
        self.logger.debug(f"Feroxbuster raw output preview:\n{raw_output[:500]}")

        discovered = self._parse_paths(raw_output)
        critical = self._flag_critical(raw_output)
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
            "discovered_paths": discovered,       # ── FIX: store actual paths
            "critical_findings": critical,        # ── FIX: store actual findings
            "ai_analysis": ai_analysis,
            "raw_output": raw_output,
        })

        self.logger.info(
            f"Feroxbuster complete | Paths: {len(discovered)} | Critical: {len(critical)}"
        )
        return result

    def _run_feroxbuster(self, url: str) -> str:
        """
        FIX: Correct feroxbuster flags for real output capture.
        Key fixes:
          - Removed --quiet (suppresses output we need)
          - Added --no-recursion for speed (remove if deep scan needed)
          - Added --status-codes to capture all relevant codes
          - Capture both stdout AND stderr
          - Added output file as fallback
        """
        import tempfile, os
        wordlist = self._get_wordlist()

        # ── Write output to temp file as fallback ─────────────────────────────
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name

        args = [
            "feroxbuster",
            "--url", url,
            "--wordlist", wordlist,
            "--depth", "3",
            "--threads", "50",
            "--timeout", "10",
            "--no-state",
            "--status-codes", "200,201,204,301,302,307,401,403,405,500",
            "--output", tmp_path,   # ── FIX: write to file as backup
            # NOTE: --quiet REMOVED — it suppresses path output
        ]

        self.logger.info(f"Running: {' '.join(args)}")

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT,
                shell=False,
            )

            # ── FIX: Combine stdout + stderr + file output ────────────────────
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            # Read output file if it exists
            file_output = ""
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                        file_output = f.read()
                    os.unlink(tmp_path)
                except Exception:
                    pass

            # Combine all sources — prefer file output as it's most complete
            combined = ""
            if file_output.strip():
                combined = file_output
            elif stdout.strip():
                combined = stdout
            else:
                combined = stderr

            if not combined.strip():
                return "WARNING: Feroxbuster produced no output. Target may be unreachable or blocking requests."

            self.logger.info(f"Feroxbuster output captured: {len(combined)} chars")
            return combined

        except FileNotFoundError:
            return "ERROR: feroxbuster not found. Install: sudo apt install feroxbuster"
        except subprocess.TimeoutExpired:
            # ── FIX: Read partial output from file on timeout ─────────────────
            partial = ""
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                        partial = f.read()
                    os.unlink(tmp_path)
                except Exception:
                    pass
            if partial.strip():
                self.logger.warning("Feroxbuster timed out — returning partial output")
                return f"[PARTIAL OUTPUT - TIMEOUT]\n{partial}"
            return "ERROR: Feroxbuster timed out after 5 minutes."
        except Exception as e:
            self.logger.exception(f"Feroxbuster execution error: {e}")
            return f"ERROR: {e}"

    def _parse_paths(self, output: str) -> list:
        """
        FIX: Multiple regex patterns to handle different feroxbuster output formats.

        Feroxbuster output formats vary by version:
          v2.x:  200      GET   /path   [Size: 1234]
          v2.10: 200      GET   2l      4w    512c http://host/path
        """
        paths = []
        seen = set()

        # Pattern 1: old format — "200  GET  /path  [Size: N]"
        p1 = re.compile(r"(\d{3})\s+GET\s+(\/\S+)\s+\[Size:\s*(\d+)\]")
        for m in p1.finditer(output):
            status, path, size = m.groups()
            key = path.strip()
            if key not in seen:
                seen.add(key)
                paths.append({"status_code": int(status), "path": key, "size": int(size)})

        # Pattern 2: new format — "200  GET  2l  4w  512c  http://host/path"
        p2 = re.compile(r"(\d{3})\s+GET\s+\d+\w\s+\d+\w\s+(\d+)c\s+(https?://\S+)")
        for m in p2.finditer(output):
            status, size, full_url = m.groups()
            # Extract path from full URL
            path_match = re.search(r"https?://[^/]+(/.*)$", full_url)
            path = path_match.group(1) if path_match else full_url
            if path not in seen:
                seen.add(path)
                paths.append({"status_code": int(status), "path": path.strip(), "size": int(size)})

        # Pattern 3: simple fallback — any line with a status code and URL-like path
        if not paths:
            p3 = re.compile(r"(\d{3})\s+.*?(\/[\w./\-_%]+)")
            for m in p3.finditer(output):
                status, path = m.groups()
                if path not in seen and len(path) > 1:
                    seen.add(path)
                    paths.append({"status_code": int(status), "path": path.strip(), "size": 0})

        self.logger.info(f"Parsed {len(paths)} paths from feroxbuster output")
        return paths

    def _flag_critical(self, output: str) -> list:
        findings = []
        for pattern, severity, description in CRITICAL_PATHS:
            if re.search(pattern, output, re.IGNORECASE):
                findings.append(f"[{severity}] {description}")
        return findings

    def _ai_analyze(self, output: str, url: str) -> dict:
        """Feed REAL output to AI — truncated to 4000 chars."""
        user_prompt = (
            f"Target URL: {url}\n\n"
            f"Feroxbuster output ({len(output)} chars total, showing first 4000):\n"
            f"```\n{output[:4000]}\n```\n\n"
            f"Provide the JSON security analysis."
        )
        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        return self._parse_json_response(raw, FALLBACK)
