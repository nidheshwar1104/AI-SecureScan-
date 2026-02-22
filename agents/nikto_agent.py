"""
nikto_agent.py
--------------
Web vulnerability scanning agent using Nikto.
Identifies server misconfigurations, outdated software, dangerous files,
default credentials, XSS vectors, and CVE-referenced vulnerabilities.

Nikto is an open-source web server scanner.
Install: sudo apt install nikto
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

logger = logging.getLogger("AI-SecureScan.NiktoAgent")

# ── Realistic mock Nikto output ───────────────────────────────────────────────
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
+ No CGI Directories found
+ PHP/5.4.16 appears to be outdated (current is at least PHP 8.1.0)
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54)
+ OSVDB-3268: /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting...
+ OSVDB-3233: /phpinfo.php: PHP is installed, and a phpinfo() file was found.
+ OSVDB-3092: /phpmyadmin/: phpMyAdmin is the default file name.
+ OSVDB-12184: /index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive info via certain HTTP requests.
+ OSVDB-3092: /.htaccess: .htaccess file was found, may contain interesting information.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-5292: /?_CONFIG[files][functions_page]=http://cirt.net/rfiinc.txt?: RFI from RSnake's list.
+ /login.php: Admin login page found.
+ /wp-login.php: Wordpress login found.
+ /config.php: PHP config file was found.
+ Cookie PHPSESSID created without the httponly flag.
+ Cookie session created without the secure flag.
+ /cgi-bin/test.cgi: CGI script found.
+ OSVDB-27071: /phpmyadmin/calendarbase.php?goroot=http://cirt.net/rfiinc.txt?: phpMyAdmin is vulnerable to Remote File Inclusion (RFI).
+ Server leaks inodes via ETags, header found with file /index.html, inode: 12345.
+ OSVDB-3268: /js/: Directory indexing found.
+ 8345 requests: 0 error(s) and 26 item(s) reported on remote host
+ End Time: 2024-01-01 12:05:43 (GMT) (343 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
""".strip()

# ── Deterministic severity rules ──────────────────────────────────────────────
NIKTO_FLAGS = [
    (r"PHP/[45]\.",                       "CRITICAL", "Critically outdated PHP version detected"),
    (r"Apache/2\.[0-3]\.",                "HIGH",     "Outdated Apache version with known CVEs"),
    (r"phpMyAdmin",                        "HIGH",     "phpMyAdmin panel accessible"),
    (r"phpinfo\.php",                      "HIGH",     "phpinfo.php reveals server configuration"),
    (r"RFI|Remote File Inclus",            "CRITICAL", "Remote File Inclusion vulnerability detected"),
    (r"X-Frame-Options.*not present",      "MEDIUM",   "Clickjacking protection missing"),
    (r"X-XSS-Protection.*not defined",     "MEDIUM",   "XSS protection header missing"),
    (r"httponly.*flag|HttpOnly",           "MEDIUM",   "Session cookie missing HttpOnly flag"),
    (r"secure.*flag|without.*secure",      "HIGH",     "Session cookie missing Secure flag"),
    (r"Directory indexing",                "MEDIUM",   "Directory listing enabled — exposes file structure"),
    (r"\.htaccess",                        "MEDIUM",   ".htaccess file accessible"),
    (r"wp-login\.php|wordpress",           "MEDIUM",   "WordPress installation detected"),
    (r"default.*file|README.*found",       "LOW",      "Default server files accessible"),
    (r"inodes.*ETag|ETag.*inode",         "LOW",      "Server leaking inode information via ETags"),
    (r"login\.php.*found|admin.*login",    "MEDIUM",   "Login page discovered"),
    (r"CGI.*found|cgi-bin",               "MEDIUM",   "CGI scripts found — check for shellshock"),
    (r"config\.php",                       "HIGH",     "PHP config file accessible"),
    (r"OSVDB-\d+",                         "INFO",     "OSVDB vulnerability reference found in results"),
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
    """Structured result from a Nikto web vulnerability scan."""
    raw_output: str
    target_url: str
    critical_flags: list[str] = field(default_factory=list)
    osvdb_ids: list[str] = field(default_factory=list)
    ai_analysis: dict = field(default_factory=dict)
    total_findings: int = 0
    safe_mode: bool = True


class NiktoAgent(BaseAgent):
    """
    Web vulnerability scanner using Nikto.

    Detects:
    - Outdated server software (Apache, PHP, nginx)
    - Dangerous default files (.htaccess, phpinfo.php, README)
    - Missing HTTP security headers (CSP, HSTS, X-Frame-Options)
    - Cookie security issues (HttpOnly, Secure flags)
    - Known CVEs and OSVDB references
    - Directory listing, RFI, LFI indicators
    - CMS installations (WordPress, phpMyAdmin)
    - CGI script vulnerabilities
    """

    COMMAND_TIMEOUT = 360  # Nikto can be slow on thorough scans

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("NiktoAgent", llm_client, memory)

    def run(self, target: str, port: int = 80) -> NiktoResult:
        """
        Run Nikto web vulnerability scan against the target.

        Args:
            target: IP address or hostname.
            port: Web server port (80 for HTTP, 443 for HTTPS).

        Returns:
            NiktoResult with findings and AI analysis.
        """
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
        Execute Nikto securely via subprocess.

        Uses:
        - -h (host), -p (port)
        - -nointeractive (no prompts)
        - -C all (scan all CGI dirs)
        - Output format: plain text
        """
        args = [
            "nikto",
            "-h", target,
            "-p", str(port),
            "-nointeractive",
            "-C", "all",
            "-maxtime", "300s",
        ]
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True,
                timeout=self.COMMAND_TIMEOUT, shell=False
            )
            return (proc.stdout + proc.stderr).strip() or "No output from Nikto."
        except FileNotFoundError:
            return "ERROR: nikto not installed. Install: sudo apt install nikto"
        except subprocess.TimeoutExpired:
            return f"ERROR: Nikto timed out after {self.COMMAND_TIMEOUT}s."
        except Exception as e:
            self.logger.exception(f"Nikto execution error: {e}")
            return f"ERROR: {e}"

    def _flag_findings(self, output: str) -> list[str]:
        """Deterministically flag critical findings from Nikto output."""
        findings = []
        seen = set()
        for pattern, severity, description in NIKTO_FLAGS:
            if re.search(pattern, output, re.IGNORECASE) and description not in seen:
                findings.append(f"[{severity}] {description}")
                seen.add(description)
        return findings

    def _extract_osvdb(self, output: str) -> list[str]:
        """Extract all OSVDB and CVE IDs referenced in the scan output."""
        osvdb = re.findall(r"OSVDB-\d+", output)
        cves = re.findall(r"CVE-\d{4}-\d+", output)
        return list(set(osvdb + cves))

    def _count_findings(self, output: str) -> int:
        """Count total reported items from Nikto output."""
        match = re.search(r"(\d+)\s+item\(s\)\s+reported", output)
        if match:
            return int(match.group(1))
        # Fallback: count lines starting with '+'
        return len([l for l in output.splitlines() if l.strip().startswith("+")])

    def _ai_analyze(self, output: str, url: str) -> dict:
        """Use LLM for deep qualitative analysis of Nikto findings."""
        user_prompt = (
            f"Target URL: {url}\n\n"
            f"Nikto scan output:\n```\n{output[:5000]}\n```\n\n"
            f"Provide the JSON security analysis."
        )
        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        return self._parse_json_response(raw, FALLBACK)
