"""
enumeration_agent.py
--------------------
FIXED: Real subprocess execution, output capture, and structured parsing.
"""

import re
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.config import settings

logger = logging.getLogger("AI-SecureScan.EnumerationAgent")

MOCK_SMB_OUTPUT = """
Starting enum4linux v0.9.1

 ==========================
|    Target Information    |
 ==========================
Target ........... 192.168.1.1

 ======================================================
|    Users on 192.168.1.1 via RID cycling             |
 ======================================================
S-1-5-21-1234567890-500 WORKGROUP\\Administrator (Local User)
S-1-5-21-1234567890-501 WORKGROUP\\Guest (Local User)
S-1-5-21-1234567890-1000 WORKGROUP\\john (Local User)
S-1-5-21-1234567890-1001 WORKGROUP\\sarah (Local User)

 ==================
|    Share Enum    |
 ==================
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	SharedDocs      Disk      Company Documents
	Backup          Disk      Backup Files

[+] Attempting to map shares on 192.168.1.1
//192.168.1.1/SharedDocs  Mapping: OK, Listing: OK
//192.168.1.1/Backup      Mapping: OK, Listing: OK

 ==========================
|    Password Policy Info  |
 ==========================
[+] Minimum password length: 0
[+] Password Complexity Flags: 000000

enum4linux complete.
""".strip()

MOCK_DNS_OUTPUT = """
[*] A www.test.local 192.168.1.1
[*] A mail.test.local 192.168.1.5
[*] A dev.test.local 192.168.1.10
[*] A staging.test.local 192.168.1.11
[*] A admin.test.local 192.168.1.1
[*] MX test.local 10 mail.test.local
""".strip()

MOCK_HTTP_HEADERS_OUTPUT = """
HTTP/1.1 200 OK
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Content-Type: text/html; charset=UTF-8
X-Frame-Options: MISSING
X-XSS-Protection: MISSING
Content-Security-Policy: MISSING
Strict-Transport-Security: MISSING
Access-Control-Allow-Origin: *
Set-Cookie: PHPSESSID=abc123; path=/
""".strip()

MOCK_SNMP_OUTPUT = """
SNMPv2-MIB::sysDescr.0 = STRING: Linux server01 3.10.0-957.el7.x86_64
SNMPv2-MIB::sysContact.0 = STRING: admin@company.com
SNMPv2-MIB::sysName.0 = STRING: server01.test.local
HOST-RESOURCES-MIB::hrSWRunName.2 = STRING: "httpd"
HOST-RESOURCES-MIB::hrSWRunName.3 = STRING: "mysqld"
""".strip()

SYSTEM_PROMPT = """You are a senior penetration tester analyzing enumeration results from multiple tools.
Analyze the combined enumeration data and return structured JSON only — no markdown, no preamble.

{
  "users_discovered": ["list of usernames found"],
  "shares_discovered": ["list of SMB shares or network resources"],
  "dns_records": ["significant DNS records found"],
  "security_headers_missing": ["list of missing security headers"],
  "snmp_info": "summary of SNMP data gathered",
  "critical_findings": ["most dangerous discoveries"],
  "attack_surface_summary": "2-3 sentence overview of the attack surface",
  "recommended_attacks": ["potential attack vectors based on findings"],
  "enumeration_risk_score": <integer 0-100>
}
"""

FALLBACK = {
    "users_discovered": [],
    "shares_discovered": [],
    "dns_records": [],
    "security_headers_missing": [],
    "snmp_info": "SNMP data unavailable",
    "critical_findings": ["Manual review required"],
    "attack_surface_summary": "Enumeration complete. Manual review required.",
    "recommended_attacks": [],
    "enumeration_risk_score": 50,
}

ENUM_FLAGS = [
    (r"Administrator.*Local User",                    "CRITICAL", "Administrator account enumerated via RID cycling"),
    (r"minimum password length: 0|Password Complexity.*000000", "CRITICAL", "Weak/no password policy detected"),
    (r"Mapping: OK.*Backup|Backup.*Mapping: OK",      "HIGH",     "Backup share accessible anonymously"),
    (r"zone transfer",                                "HIGH",     "DNS zone transfer attempted"),
    (r"dev\.|staging\.",                              "MEDIUM",   "Development/staging subdomains discovered"),
    (r"X-Frame-Options: MISSING",                    "MEDIUM",   "Clickjacking protection missing"),
    (r"Content-Security-Policy: MISSING",            "MEDIUM",   "CSP header missing — XSS risk"),
    (r"Strict-Transport-Security: MISSING",          "HIGH",     "HSTS missing — SSL stripping possible"),
    (r"X-Powered-By: PHP/5\.",                       "HIGH",     "Old PHP version exposed in headers"),
    (r"community string|public|private",             "HIGH",     "SNMP community string detected"),
    (r"sysContact|sysLocation",                      "MEDIUM",   "SNMP leaking admin contact/location"),
    (r"Access-Control-Allow-Origin: \*",             "MEDIUM",   "CORS wildcard — potential data exposure"),
]


@dataclass
class EnumerationResult:
    smb_output: str = ""
    dns_output: str = ""
    http_headers: str = ""
    snmp_output: str = ""
    critical_flags: list = field(default_factory=list)
    ai_analysis: dict = field(default_factory=dict)
    safe_mode: bool = True


class EnumerationAgent(BaseAgent):

    COMMAND_TIMEOUT = 120

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("EnumerationAgent", llm_client, memory)

    def run(self, target: str, domain: Optional[str] = None, port: int = 80) -> EnumerationResult:
        self.logger.info(f"Starting full enumeration against: {target}")

        if settings.safe_mode:
            self.logger.warning("SAFE_MODE=true — using mock enumeration output")
            smb = MOCK_SMB_OUTPUT
            dns = MOCK_DNS_OUTPUT
            http = MOCK_HTTP_HEADERS_OUTPUT
            snmp = MOCK_SNMP_OUTPUT
            safe_mode = True
        else:
            smb = self._run_smb_enum(target)
            dns = self._run_dns_enum(domain or target)
            http = self._run_http_headers(target, port)
            snmp = self._run_snmp_enum(target)
            safe_mode = False

        # ── FIX: Log each module output length ───────────────────────────────
        self.logger.info(f"SMB output: {len(smb)} chars")
        self.logger.info(f"DNS output: {len(dns)} chars")
        self.logger.info(f"HTTP output: {len(http)} chars")
        self.logger.info(f"SNMP output: {len(snmp)} chars")

        combined = (
            f"=== SMB (enum4linux) ===\n{smb}\n\n"
            f"=== DNS (dnsrecon) ===\n{dns}\n\n"
            f"=== HTTP HEADERS (curl) ===\n{http}\n\n"
            f"=== SNMP (snmpwalk) ===\n{snmp}"
        )

        flags = self._flag_findings(combined)
        ai_analysis = self._ai_analyze(combined, target)

        # ── FIX: Parse structured data from real outputs ──────────────────────
        parsed_users = self._parse_smb_users(smb)
        parsed_shares = self._parse_smb_shares(smb)
        parsed_headers = self._parse_missing_headers(http)

        result = EnumerationResult(
            smb_output=smb,
            dns_output=dns,
            http_headers=http,
            snmp_output=snmp,
            critical_flags=flags,
            ai_analysis=ai_analysis,
            safe_mode=safe_mode,
        )

        # ── FIX: Store ALL real parsed data in memory ─────────────────────────
        self.memory.store("enumeration_result", {
            "target": target,
            "critical_flags": flags,
            "ai_analysis": ai_analysis,
            "combined_output": combined,
            "parsed_users": parsed_users,       # ── real parsed users
            "parsed_shares": parsed_shares,     # ── real parsed shares
            "parsed_headers": parsed_headers,   # ── real missing headers
            "smb_output": smb,
            "dns_output": dns,
            "http_output": http,
            "snmp_output": snmp,
        })

        self.logger.info(
            f"Enumeration complete | Flags: {len(flags)} | "
            f"Users: {len(parsed_users)} | Shares: {len(parsed_shares)}"
        )
        return result

    # ── Module runners ──────────────────────────────────────────────────────

    def _run_smb_enum(self, target: str) -> str:
        """
        FIX: enum4linux with proper flags and output capture.
        -a = all simple enumeration
        -v = verbose output
        """
        self.logger.info(f"Running enum4linux against {target}")
        return self._safe_run(
            ["enum4linux", "-a", "-v", target],
            "enum4linux"
        )

    def _run_dns_enum(self, domain: str) -> str:
        """
        FIX: dnsrecon with std enumeration + fallback to dig.
        """
        self.logger.info(f"Running dnsrecon against {domain}")
        result = self._safe_run(
            ["dnsrecon", "-d", domain, "-t", "std"],
            "dnsrecon"
        )
        # FIX: If dnsrecon fails, fallback to dig
        if result.startswith("ERROR"):
            self.logger.warning("dnsrecon failed, falling back to dig")
            result = self._safe_run(
                ["dig", "ANY", domain, "+noall", "+answer"],
                "dig"
            )
        return result

    def _run_http_headers(self, target: str, port: int) -> str:
        """
        FIX: curl with verbose headers + check for missing security headers.
        """
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}:{port}"
        self.logger.info(f"Grabbing HTTP headers from {url}")

        raw = self._safe_run(
            ["curl", "-sI", "--max-time", "15", "--connect-timeout", "10", url],
            "curl"
        )

        # ── FIX: Annotate missing security headers in output ──────────────────
        important_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        missing_annotations = []
        for header in important_headers:
            if header.lower() not in raw.lower():
                missing_annotations.append(f"{header}: MISSING")

        if missing_annotations:
            raw += "\n\n[MISSING SECURITY HEADERS DETECTED]\n" + "\n".join(missing_annotations)

        return raw

    def _run_snmp_enum(self, target: str) -> str:
        """Run snmpwalk with public community string."""
        self.logger.info(f"Running snmpwalk against {target}")
        return self._safe_run(
            ["snmpwalk", "-v2c", "-c", "public", "-t", "5", target],
            "snmpwalk"
        )

    def _safe_run(self, args: list, tool_name: str) -> str:
        """
        FIX: Improved subprocess runner with better error messages
        and combined stdout+stderr capture.
        """
        try:
            self.logger.debug(f"Executing: {' '.join(args)}")
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT,
                shell=False,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            # Combine both — enum4linux writes useful info to stderr too
            combined = (stdout + "\n" + stderr).strip()

            if not combined:
                return f"{tool_name}: No output captured (return code: {proc.returncode})"

            self.logger.info(f"{tool_name} output: {len(combined)} chars")
            return combined

        except FileNotFoundError:
            msg = f"ERROR: {tool_name} not installed. Install: sudo apt install {tool_name}"
            self.logger.warning(msg)
            return msg
        except subprocess.TimeoutExpired:
            msg = f"ERROR: {tool_name} timed out after {self.COMMAND_TIMEOUT}s."
            self.logger.warning(msg)
            return msg
        except Exception as e:
            self.logger.exception(f"{tool_name} error: {e}")
            return f"ERROR: {e}"

    # ── Parsers ─────────────────────────────────────────────────────────────

    def _parse_smb_users(self, smb_output: str) -> list:
        """FIX: Extract real usernames from enum4linux output."""
        users = []
        # Pattern: "S-1-5-21-xxx-500 DOMAIN\Username (Local User)"
        pattern = re.compile(
            r"S-1-5-\d+-\d+-\d+\s+\S+\\(\w+)\s+\(Local User\)",
            re.IGNORECASE
        )
        for match in pattern.finditer(smb_output):
            users.append(match.group(1))

        # Fallback: lines with "username:" pattern
        if not users:
            for line in smb_output.splitlines():
                if "username" in line.lower() and ":" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        user = parts[1].strip().strip("'\"")
                        if user:
                            users.append(user)
        return list(set(users))

    def _parse_smb_shares(self, smb_output: str) -> list:
        """FIX: Extract real SMB shares from enum4linux output."""
        shares = []
        # Pattern: "ShareName    Type    Comment"
        pattern = re.compile(r"^\s+(\w[\w$]+)\s+(Disk|IPC|Printer)\s+(.*)$", re.MULTILINE)
        for match in pattern.finditer(smb_output):
            shares.append({
                "name": match.group(1),
                "type": match.group(2),
                "comment": match.group(3).strip(),
            })
        return shares

    def _parse_missing_headers(self, http_output: str) -> list:
        """FIX: Extract list of missing security headers."""
        missing = []
        for line in http_output.splitlines():
            if "MISSING" in line:
                header = line.split(":")[0].strip()
                missing.append(header)
        return missing

    def _flag_findings(self, combined_output: str) -> list:
        findings = []
        for pattern, severity, description in ENUM_FLAGS:
            if re.search(pattern, combined_output, re.IGNORECASE):
                findings.append(f"[{severity}] {description}")
        return findings

    def _ai_analyze(self, combined: str, target: str) -> dict:
        """Feed REAL combined output to AI."""
        user_prompt = (
            f"Target: {target}\n\n"
            f"Combined enumeration output ({len(combined)} chars total, showing first 5000):\n"
            f"```\n{combined[:5000]}\n```\n\n"
            f"Provide the JSON security analysis."
        )
        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        return self._parse_json_response(raw, FALLBACK)
