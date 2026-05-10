"""
nikto_agent.py
--------------
FIXED: Real subprocess execution, output capture, and parsing.
"""

import re
import logging
import subprocess
from dataclasses import dataclass, field

from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.config import settings

logger = logging.getLogger("AI-SecureScan.NiktoAgent")

SAFE_MODE_MOCK_OUTPUT = """
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.1
+ Target Hostname:    192.168.1.1
+ Target Port:        80
+ Start Time:         2024-01-01 12:00:00 (GMT)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined.
+ The X-Content-Type-Options header is not set.
+ PHP/5.4.16 appears to be outdated (current is at least PHP 8.1.0)
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54)
+ OSVDB-3268: /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3233: /phpinfo.php: PHP is installed, and a phpinfo() file was found.
+ OSVDB-3092: /phpmyadmin/: phpMyAdmin is the default file name.
+ Cookie PHPSESSID created without the httponly flag.
+ Cookie session created without the secure flag.
+ /login.php: Admin login page found.
+ /wp-login.php: Wordpress login found.
+ /config.php: PHP config file was found.
+ OSVDB-27071: /phpmyadmin/calendarbase.php?goroot=http://cirt.net/rfiinc.txt?: RFI vulnerability.
+ 8345 requests: 0 error(s) and 26 item(s) reported on remote host
+ End Time: 2024-01-01 12:05:43 (GMT) (343 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
""".strip()

NIKTO_FLAGS = [
    (r"PHP/[45]\.",                        "CRITICAL", "Critically outdated PHP version detected"),
    (r"Apache/2\.[0-3]\.",                 "HIGH",     "Outdated Apache version with known CVEs"),
    (r"phpMyAdmin",                        "HIGH",     "phpMyAdmin panel accessible"),
    (r"phpinfo\.php",                      "HIGH",     "phpinfo.php reveals server configuration"),
    (r"RFI|Remote File Inclus",            "CRITICAL", "Remote File Inclusion vulnerability detected"),
    (r"X-Frame-Options.*not present",      "MEDIUM",   "Clickjacking protection missing"),
    (r"X-XSS-Protection.*not defined",     "MEDIUM",   "XSS protection header missing"),
    (r"httponly.*flag|HttpOnly",            "MEDIUM",   "Session cookie missing HttpOnly flag"),
    (r"secure.*flag|without.*secure",      "HIGH",     "Session cookie missing Secure flag"),
    (r"Directory indexing",                "MEDIUM",   "Directory listing enabled"),
    (r"\.htaccess",                        "MEDIUM",   ".htaccess file accessible"),
    (r"wp-login\.php|wordpress",           "MEDIUM",   "WordPress installation detected"),
    (r"default.*file|README.*found",       "LOW",      "Default server files accessible"),
    (r"inodes.*ETag|ETag.*inode",          "LOW",      "Server leaking inode information via ETags"),
    (r"login\.php.*found|admin.*login",    "MEDIUM",   "Login page discovered"),
    (r"CGI.*found|cgi-bin",               "MEDIUM",   "CGI scripts found"),
    (r"config\.php",                       "HIGH",     "PHP config file accessible"),
    (r"OSVDB-\d+",                         "INFO",     "OSVDB vulnerability reference found"),
]

SYSTEM_PROMPT = """You are a web application penetration tester analyzing Nikto scan results.
Analyze the vulnerabilities and return structured JSON only — no markdown, no explanation.

{
  "cve_references": ["CVE or OSVDB IDs mentioned in the scan"],
  "critical_vulnerabilities": ["list of the most critical findings with brief explanation"],
  "misconfigurations": ["server/application misconfigurations found"],
  "outdated_software": ["outdated software versions with risk explanation"],
  "cookie_issues": ["cookie security issues"],
  "header_issues": ["missing or misconfigured HTTP security headers"],
  "remediation_priority": [
    {"issue": "<issue name>", "fix": "<specific fix>", "priority": "<Critical|High|Medium|Low>"}
  ],
  "nikto_risk_score": <integer 0-100, 100=fully exposed>,
  "executive_finding": "One sentence: the single most dangerous finding"
}
"""

FALLBACK = {
    "cve_references": [],
    "critical_vulnerabilities": ["Manual review required"],
    "misconfigurations": [],
    "outdated_software": [],
    "cookie_issues": [],
    "header_issues": [],
    "remediation_priority": [],
    "nikto_risk_score": 50,
    "executive_finding": "Unable to parse AI analysis. Review raw Nikto output manually.",
}


@dataclass
class NiktoResult:
    raw_output: str
    target_url: str
    critical_flags: list = field(default_factory=list)
    osvdb_ids: list = field(default_factory=list)
    ai_analysis: dict = field(default_factory=dict)
    total_findings: int = 0
    safe_mode: bool = True


class NiktoAgent(BaseAgent):

    COMMAND_TIMEOUT = 360

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("NiktoAgent", llm_client, memory)

    def run(self, target: str, port: int = 80) -> NiktoResult:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}"
        self.logger.info(f"Starting Nikto scan against: {url}:{port}")

        if settings.safe_mode:
            self.logger.warning("SAFE_MODE=true — using mock Nikto output")
            raw_output = SAFE_MODE_MOCK_OUTPUT
            safe_mode = True
        else:
            raw_output = self._run_nikto(target, port)
            safe_mode = False

        # ── FIX: Log raw output for debugging ────────────────────────────────
        self.logger.info(f"Nikto raw output length: {len(raw_output)} chars")
        self.logger.debug(f"Nikto raw output preview:\n{raw_output[:500]}")

        flags = self._flag_findings(raw_output)
        osvdb_ids = self._extract_osvdb(raw_output)
        total = self._count_findings(raw_output)
        ai_analysis = self._ai_analyze(raw_output, url)

        result = NiktoResult(
            raw_output=raw_output,
            target_url=f"{url}:{port}",
            critical_flags=flags,
            osvdb_ids=osvdb_ids,
            ai_analysis=ai_analysis,
            total_findings=total,
            safe_mode=safe_mode,
        )

        # ── FIX: Store all real parsed data in memory ─────────────────────────
        self.memory.store("nikto_result", {
            "url": f"{url}:{port}",
            "total_findings": total,
            "critical_flags": flags,
            "osvdb_ids": osvdb_ids,
            "ai_analysis": ai_analysis,
            "raw_output": raw_output,
        })

        self.logger.info(
            f"Nikto complete | Total findings: {total} | "
            f"Critical flags: {len(flags)} | OSVDB refs: {len(osvdb_ids)}"
        )
        return result

    def _run_nikto(self, target: str, port: int) -> str:
        """
        FIX: Proper nikto execution with output file for reliable capture.
        Key fixes:
          - Use -output flag to write to file (most reliable)
          - Use -Format txt for parseable output
          - Capture both stdout and stderr
          - Read output file after scan completes
        """
        import tempfile, os

        # ── Write to temp file for reliable output capture ────────────────────
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name

        args = [
            "nikto",
            "-h", target,
            "-p", str(port),
            "-nointeractive",
            "-C", "all",
            "-maxtime", "300s",
            "-output", tmp_path,   # ── FIX: write output to file
            "-Format", "txt",      # ── FIX: plain text format for easy parsing
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

            # ── FIX: Combine stdout + file output ─────────────────────────────
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            file_output = ""
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                        file_output = f.read()
                    os.unlink(tmp_path)
                except Exception as e:
                    self.logger.warning(f"Could not read nikto output file: {e}")

            # Prefer file output, fallback to stdout, then stderr
            if file_output.strip():
                combined = file_output
                if stdout.strip():
                    combined = stdout + "\n" + file_output
            elif stdout.strip():
                combined = stdout
            else:
                combined = stderr

            if not combined.strip():
                return "WARNING: Nikto produced no output. Target may be unreachable."

            self.logger.info(f"Nikto output captured: {len(combined)} chars")
            return combined.strip()

        except FileNotFoundError:
            return "ERROR: nikto not installed. Install: sudo apt install nikto"
        except subprocess.TimeoutExpired:
            # ── FIX: Read partial output on timeout ───────────────────────────
            partial = ""
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                        partial = f.read()
                    os.unlink(tmp_path)
                except Exception:
                    pass
            if partial.strip():
                self.logger.warning("Nikto timed out — returning partial output")
                return f"[PARTIAL OUTPUT - TIMEOUT]\n{partial}"
            return f"ERROR: Nikto timed out after {self.COMMAND_TIMEOUT}s."
        except Exception as e:
            self.logger.exception(f"Nikto execution error: {e}")
            return f"ERROR: {e}"

    def _flag_findings(self, output: str) -> list:
        findings = []
        seen = set()
        for pattern, severity, description in NIKTO_FLAGS:
            if re.search(pattern, output, re.IGNORECASE) and description not in seen:
                findings.append(f"[{severity}] {description}")
                seen.add(description)
        return findings

    def _extract_osvdb(self, output: str) -> list:
        osvdb = re.findall(r"OSVDB-\d+", output)
        cves = re.findall(r"CVE-\d{4}-\d+", output)
        return list(set(osvdb + cves))

    def _count_findings(self, output: str) -> int:
        """FIX: Multiple patterns to count findings reliably."""
        # Pattern 1: "N item(s) reported"
        match = re.search(r"(\d+)\s+item\(s\)\s+reported", output)
        if match:
            return int(match.group(1))
        # Pattern 2: count lines starting with '+'
        plus_lines = [l for l in output.splitlines() if l.strip().startswith("+")]
        if plus_lines:
            return len(plus_lines)
        # Pattern 3: count OSVDB references
        osvdb_count = len(re.findall(r"OSVDB-\d+", output))
        return osvdb_count

    def _ai_analyze(self, output: str, url: str) -> dict:
        """Feed REAL output to AI."""
        user_prompt = (
            f"Target URL: {url}\n\n"
            f"Nikto scan output ({len(output)} chars total, showing first 5000):\n"
            f"```\n{output[:5000]}\n```\n\n"
            f"Provide the JSON security analysis."
        )
        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        return self._parse_json_response(raw, FALLBACK)
