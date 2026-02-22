"""
enumeration_agent.py
--------------------
Comprehensive service enumeration agent combining multiple tools:
  - SMB enumeration (enum4linux / smbclient)
  - DNS enumeration (dnsrecon / dig)
  - SNMP enumeration (snmpwalk)
  - HTTP header enumeration (curl)
  - Banner grabbing (netcat simulation)

Enumerates users, shares, services, DNS records, and system info
to build a complete picture of the target attack surface.
"""

import re
import logging
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.config import settings

logger = logging.getLogger("AI-SecureScan.EnumerationAgent")

# ── Mock outputs per enumeration type ────────────────────────────────────────
MOCK_SMB_OUTPUT = """
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ )

 ==========================
|    Target Information    |
 ==========================
Target ........... 192.168.1.1
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''

 ======================================================
|    Users on 192.168.1.1 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================
[I] Found new SID: S-1-5-21-1234567890
[I] Found new SID: S-1-5-21-0987654321
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
[+] Password history length: 0
[+] Maximum password age: No maximum age
[+] Password Complexity Flags: 000000
    Domain Refuse Password Change: 0
    Domain Password Store Cleartext: 0
    Domain Password Lockout Admins: 0
    Domain Password No Clear Change: 0
    Domain Password No Anon Change: 0
    Domain Password Complex: 0

enum4linux complete.
""".strip()

MOCK_DNS_OUTPUT = """
[*] Testing NS Servers for zone transfer
[*] Checking for Zone Transfer for test.local
[-] Zone Transfer Failed

[*] Brute forcing with /usr/share/dnsrecon/namelist.txt:
[*] A test.local 192.168.1.1
[*] A www.test.local 192.168.1.1
[*] A mail.test.local 192.168.1.5
[*] A ftp.test.local 192.168.1.6
[*] A dev.test.local 192.168.1.10
[*] A staging.test.local 192.168.1.11
[*] A admin.test.local 192.168.1.1
[*] MX test.local 10 mail.test.local
[*] TXT test.local v=spf1 ip4:192.168.1.5 ~all

[*] Enumerating SRV Records:
[*] SRV _kerberos._tcp.test.local 192.168.1.1 88 0 100
[*] SRV _ldap._tcp.test.local 192.168.1.1 389 0 100
""".strip()

MOCK_HTTP_HEADERS_OUTPUT = """
HTTP/1.1 200 OK
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Content-Type: text/html; charset=UTF-8
X-Frame-Options: MISSING
X-XSS-Protection: MISSING
X-Content-Type-Options: MISSING
Content-Security-Policy: MISSING
Strict-Transport-Security: MISSING
Access-Control-Allow-Origin: *
Set-Cookie: PHPSESSID=abc123; path=/
Set-Cookie: session=xyz789; path=/; HttpOnly
""".strip()

MOCK_SNMP_OUTPUT = """
SNMPv2-MIB::sysDescr.0 = STRING: Linux server01 3.10.0-957.el7.x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
SNMPv2-MIB::sysUpTime.0 = Timeticks: (123456789) 14 days, 6:56:07.89
SNMPv2-MIB::sysContact.0 = STRING: admin@company.com
SNMPv2-MIB::sysName.0 = STRING: server01.test.local
SNMPv2-MIB::sysLocation.0 = STRING: Server Room A, Rack 3
HOST-RESOURCES-MIB::hrSWRunName.1 = STRING: "init"
HOST-RESOURCES-MIB::hrSWRunName.2 = STRING: "httpd"
HOST-RESOURCES-MIB::hrSWRunName.3 = STRING: "mysqld"
HOST-RESOURCES-MIB::hrSWRunName.4 = STRING: "sshd"
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

# Deterministic flags for enumeration findings
ENUM_FLAGS = [
    (r"Administrator.*Local User",          "CRITICAL", "Administrator account enumerated via RID cycling"),
    (r"Password Complexity.*000000|minimum password length: 0", "CRITICAL", "Weak/no password policy detected"),
    (r"Mapping: OK.*Backup|Backup.*Mapping: OK", "HIGH", "Backup share accessible anonymously"),
    (r"zone transfer",                       "HIGH",    "DNS zone transfer attempted"),
    (r"dev\.|staging\.",                     "MEDIUM",  "Development/staging subdomains discovered"),
    (r"X-Frame-Options: MISSING",           "MEDIUM",  "Clickjacking protection missing"),
    (r"Content-Security-Policy: MISSING",   "MEDIUM",  "CSP header missing — XSS risk"),
    (r"Strict-Transport-Security: MISSING", "HIGH",    "HSTS missing — SSL stripping possible"),
    (r"X-Powered-By: PHP/5\.",              "HIGH",    "Old PHP version exposed in headers"),
    (r"community string|public|private",    "HIGH",    "SNMP community string detected"),
    (r"sysContact|sysLocation",             "MEDIUM",  "SNMP leaking admin contact/location"),
    (r"Access-Control-Allow-Origin: \*",    "MEDIUM",  "CORS wildcard — potential data exposure"),
]


@dataclass
class EnumerationResult:
    """Combined results from all enumeration modules."""
    smb_output: str = ""
    dns_output: str = ""
    http_headers: str = ""
    snmp_output: str = ""
    critical_flags: list[str] = field(default_factory=list)
    ai_analysis: dict = field(default_factory=dict)
    safe_mode: bool = True


class EnumerationAgent(BaseAgent):
    """
    Multi-protocol enumeration agent.

    Modules:
    - SMB/NetBIOS: user accounts, shares, password policy (enum4linux)
    - DNS: subdomains, MX, TXT, zone transfer attempts (dnsrecon)
    - HTTP: security headers, server info, cookie flags (curl)
    - SNMP: system info, running processes (snmpwalk)

    All modules run in parallel conceptually; results are combined
    and analyzed by LLM for a unified attack surface assessment.
    """

    COMMAND_TIMEOUT = 120

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("EnumerationAgent", llm_client, memory)

    def run(self, target: str, domain: Optional[str] = None, port: int = 80) -> EnumerationResult:
        """
        Run all enumeration modules against the target.

        Args:
            target: IP address or hostname.
            domain: Domain name for DNS enumeration (optional).
            port: HTTP port for header enumeration.

        Returns:
            EnumerationResult with all module outputs and AI analysis.
        """
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

        combined = f"=== SMB ===\n{smb}\n\n=== DNS ===\n{dns}\n\n=== HTTP HEADERS ===\n{http}\n\n=== SNMP ===\n{snmp}"

        flags = self._flag_findings(combined)
        ai_analysis = self._ai_analyze(combined, target)

        result = EnumerationResult(
            smb_output=smb,
            dns_output=dns,
            http_headers=http,
            snmp_output=snmp,
            critical_flags=flags,
            ai_analysis=ai_analysis,
            safe_mode=safe_mode,
        )

        self.memory.store("enumeration_result", {
            "target": target,
            "critical_flags": flags,
            "ai_analysis": ai_analysis,
            "combined_output": combined,
        })

        self.logger.info(f"Enumeration complete | Flags: {len(flags)}")
        return result

    # ── Module runners ──────────────────────────────────────────────────────

    def _run_smb_enum(self, target: str) -> str:
        """Run enum4linux for SMB/NetBIOS enumeration."""
        return self._safe_run(["enum4linux", "-a", target], "enum4linux")

    def _run_dns_enum(self, domain: str) -> str:
        """Run dnsrecon for DNS enumeration."""
        return self._safe_run(["dnsrecon", "-d", domain, "-t", "brt"], "dnsrecon")

    def _run_http_headers(self, target: str, port: int) -> str:
        """Use curl to grab HTTP response headers."""
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}:{port}"
        return self._safe_run(
            ["curl", "-sI", "--max-time", "10", url], "curl"
        )

    def _run_snmp_enum(self, target: str) -> str:
        """Run snmpwalk with public community string."""
        return self._safe_run(
            ["snmpwalk", "-v2c", "-c", "public", target], "snmpwalk"
        )

    def _safe_run(self, args: list[str], tool_name: str) -> str:
        """
        Securely run an enumeration tool via subprocess.

        Args:
            args: Command arguments list (no shell=True).
            tool_name: Name for error messages.

        Returns:
            Combined stdout/stderr output string.
        """
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True,
                timeout=self.COMMAND_TIMEOUT, shell=False
            )
            return (proc.stdout + proc.stderr).strip() or f"{tool_name}: No output."
        except FileNotFoundError:
            return f"ERROR: {tool_name} not installed. Install guide in README."
        except subprocess.TimeoutExpired:
            return f"ERROR: {tool_name} timed out after {self.COMMAND_TIMEOUT}s."
        except Exception as e:
            self.logger.exception(f"{tool_name} error: {e}")
            return f"ERROR: {e}"

    def _flag_findings(self, combined_output: str) -> list[str]:
        """Deterministically flag critical findings from all module output."""
        findings = []
        for pattern, severity, description in ENUM_FLAGS:
            if re.search(pattern, combined_output, re.IGNORECASE):
                findings.append(f"[{severity}] {description}")
        return findings

    def _ai_analyze(self, combined: str, target: str) -> dict:
        """LLM analysis of combined enumeration data."""
        user_prompt = (
            f"Target: {target}\n\n"
            f"Combined enumeration output:\n```\n{combined[:5000]}\n```\n\n"
            f"Provide the JSON security analysis."
        )
        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.2)
        return self._parse_json_response(raw, FALLBACK)
