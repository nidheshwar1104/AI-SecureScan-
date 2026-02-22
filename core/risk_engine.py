"""
risk_engine.py
--------------
Deterministic, mathematical vulnerability scoring engine.
Does NOT rely on LLM — uses regex-based port/service detection
and a rule-based deduction system to calculate a Secure Score.

This is intentionally separate from AI-based scoring to provide
an objective, auditable baseline risk metric.
"""

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("AI-SecureScan.RiskEngine")


@dataclass
class ScoreDeduction:
    """Represents a single scoring deduction."""
    reason: str
    points: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class RiskReport:
    """Output of the deterministic risk engine."""
    secure_score: int
    deductions: list[dict]
    detected_issues: list[str]
    raw_score: int = 100


# ─── Scoring Rules ────────────────────────────────────────────────────────────
# Each rule: (pattern_to_match_in_output, deduction_points, severity, description)

PORT_RULES: list[tuple[str, int, str, str]] = [
    # Critical ports / dangerous services
    (r"\b23/tcp\s+open\b",                  25, "CRITICAL", "Telnet port open (unencrypted, legacy)"),
    (r"\b21/tcp\s+open\b",                  20, "HIGH",     "FTP port open (unencrypted file transfer)"),
    (r"\b512/tcp\s+open\b",                 20, "HIGH",     "rexec port open (remote execution, insecure)"),
    (r"\b513/tcp\s+open\b",                 20, "HIGH",     "rlogin port open (insecure remote login)"),
    (r"\b514/tcp\s+open\b",                 20, "HIGH",     "rsh port open (remote shell, no auth)"),
    (r"\b1433/tcp\s+open\b",                15, "HIGH",     "MSSQL port exposed to network"),
    (r"\b3389/tcp\s+open\b",                15, "HIGH",     "RDP port exposed (common attack vector)"),
    (r"\b5900/tcp\s+open\b",                15, "HIGH",     "VNC port open (remote desktop, often unencrypted)"),
    # Medium risk
    (r"\b3306/tcp\s+open\b",                12, "MEDIUM",   "MySQL/MariaDB exposed on network"),
    (r"\b5432/tcp\s+open\b",                12, "MEDIUM",   "PostgreSQL exposed on network"),
    (r"\b27017/tcp\s+open\b",               12, "MEDIUM",   "MongoDB exposed on network"),
    (r"\b6379/tcp\s+open\b",                12, "MEDIUM",   "Redis exposed on network (often no auth)"),
    (r"\b8080/tcp\s+open\b",                 8, "MEDIUM",   "HTTP proxy/alt port open"),
    (r"\b8443/tcp\s+open\b",                 8, "MEDIUM",   "HTTPS alt port open"),
    (r"\b9200/tcp\s+open\b",                12, "MEDIUM",   "Elasticsearch API exposed"),
    # Low risk
    (r"\b25/tcp\s+open\b",                   5, "LOW",      "SMTP port open (check relay configuration)"),
    (r"\b110/tcp\s+open\b",                  5, "LOW",      "POP3 open (prefer POPS/995)"),
    (r"\b143/tcp\s+open\b",                  5, "LOW",      "IMAP open (prefer IMAPS/993)"),
    (r"\b53/tcp\s+open\b",                   5, "LOW",      "DNS TCP open (check for zone transfer)"),
]

SERVICE_VERSION_RULES: list[tuple[str, int, str, str]] = [
    # Outdated / vulnerable service versions
    (r"OpenSSH [1-6]\.",                    15, "HIGH",     "Outdated OpenSSH version detected"),
    (r"Apache/[01]\.",                      15, "HIGH",     "Critically outdated Apache version"),
    (r"Apache/2\.[012]\.",                  10, "MEDIUM",   "Outdated Apache 2.x version"),
    (r"Apache/2\.4\.[0-3][0-9]\b",          5, "LOW",      "Older Apache 2.4.x — check for patches"),
    (r"nginx/[01]\.",                       10, "MEDIUM",   "Outdated nginx version"),
    (r"MySQL 5\.[0-5]\.",                   15, "HIGH",     "Outdated MySQL 5.x version (EOL)"),
    (r"MySQL 5\.6\.",                       12, "HIGH",     "MySQL 5.6 — EOL since Feb 2021"),
    (r"MySQL 5\.7\.",                        8, "MEDIUM",   "MySQL 5.7 — approaching EOL"),
    (r"vsftpd 2\.",                         10, "MEDIUM",   "Older vsftpd version detected"),
    (r"ProFTPD 1\.[23]\.",                  10, "MEDIUM",   "Outdated ProFTPD version"),
    (r"Squid http proxy [0-3]\.",           10, "MEDIUM",   "Outdated Squid proxy version"),
    (r"Linux telnetd",                      20, "CRITICAL", "Telnet daemon running (unencrypted protocol)"),
]

WEB_RULES: list[tuple[str, int, str, str]] = [
    # Feroxbuster findings
    (r"\.git/.*config|\.git/.*HEAD",        25, "CRITICAL", "Git repository exposed publicly"),
    (r"\.env\b.*200|200.*\.env\b",          25, "CRITICAL", ".env file accessible — secrets exposed"),
    (r"db_backup.*200|\.sql.*200",          22, "CRITICAL", "Database backup file publicly accessible"),
    (r"phpinfo\.php.*200",                  18, "HIGH",     "phpinfo.php exposes server internals"),
    (r"phpmyadmin|phpMyAdmin",              18, "HIGH",     "phpMyAdmin panel exposed"),
    (r"wp-login\.php|wp-admin",             12, "HIGH",     "WordPress admin panel accessible"),
    (r"backup/.*200|200.*backup/",          15, "HIGH",     "Backup directory publicly accessible"),
    (r"config\.php.*200|config\.yml.*200",  15, "HIGH",     "Configuration file exposed"),
    (r"api/v\d+/admin",                     15, "HIGH",     "Admin API endpoint exposed"),
    (r"server-status.*200",                 10, "MEDIUM",   "Apache server-status exposed"),
    # Nikto findings
    (r"PHP/[45]\.",                         20, "CRITICAL", "End-of-life PHP version running"),
    (r"Remote File Inclus|RFI",             25, "CRITICAL", "Remote File Inclusion vulnerability"),
    (r"X-Frame-Options.*not present",        8, "MEDIUM",   "Clickjacking protection absent"),
    (r"httponly.*flag|without.*httponly",    10, "MEDIUM",   "Cookie missing HttpOnly flag"),
    (r"secure.*flag|without.*secure flag",  12, "HIGH",     "Cookie missing Secure flag"),
    (r"Directory indexing",                  8, "MEDIUM",   "Directory listing enabled"),
    # Enumeration findings
    (r"minimum password length: 0|Password Complexity.*000000", 20, "CRITICAL", "No password complexity policy"),
    (r"Anonymous.*Mapping: OK|Backup.*Mapping: OK",             18, "HIGH",     "Anonymous SMB share access"),
    (r"zone transfer",                      10, "HIGH",     "DNS zone transfer attempted"),
    (r"Access-Control-Allow-Origin: \*",    10, "MEDIUM",   "CORS wildcard misconfiguration"),
    (r"X-Powered-By: PHP/[45]\.",           12, "HIGH",     "Outdated PHP version in HTTP headers"),
    (r"Strict-Transport-Security: MISSING", 12, "HIGH",     "HSTS not configured"),
]

PROTOCOL_RULES: list[tuple[str, int, str, str]] = [
    (r"ssl.*SSLv2",                         20, "CRITICAL", "SSLv2 enabled — critically broken protocol"),
    (r"ssl.*SSLv3",                         18, "CRITICAL", "SSLv3 enabled — POODLE vulnerable"),
    (r"ssl.*TLSv1\.0",                      12, "HIGH",     "TLSv1.0 enabled — deprecated, insecure"),
    (r"ssl.*TLSv1\.1",                      10, "MEDIUM",   "TLSv1.1 enabled — deprecated"),
    (r"http-auth: Basic",                    8, "MEDIUM",   "HTTP Basic auth detected — prefer token/cert"),
    (r"anonymous.*ftp|ftp.*anonymous",      15, "HIGH",     "Anonymous FTP login allowed"),
]


class RiskEngine:
    """
    Deterministic vulnerability scoring engine.

    Algorithm:
        1. Start with a base score of 100.
        2. Parse the scan output against all rule sets.
        3. Deduct points for each matched rule (capped at minimum 0).
        4. Produce a RiskReport with full deduction breakdown.

    This engine is entirely rule-based — it never calls an LLM.
    """

    BASE_SCORE = 100

    def calculate(self, scan_output: str) -> RiskReport:
        """
        Calculate a deterministic secure score from scan output.

        Args:
            scan_output: Raw nmap stdout string.

        Returns:
            RiskReport with score, deductions, and detected issues.
        """
        logger.info("Running deterministic risk engine scoring.")
        score = self.BASE_SCORE
        deductions: list[dict] = []
        detected_issues: list[str] = []

        all_rules = [
            ("Port Risk", PORT_RULES),
            ("Service Version Risk", SERVICE_VERSION_RULES),
            ("Protocol Risk", PROTOCOL_RULES),
            ("Web Application Risk", WEB_RULES),
        ]

        for category, rules in all_rules:
            for pattern, points, severity, description in rules:
                if re.search(pattern, scan_output, re.IGNORECASE):
                    score -= points
                    deductions.append({
                        "category": category,
                        "reason": description,
                        "points": points,
                        "severity": severity,
                    })
                    detected_issues.append(f"[{severity}] {description}")
                    logger.debug(f"Rule matched: {description} (-{points} pts)")

        final_score = max(0, score)
        logger.info(
            f"Risk Engine complete | Base: {self.BASE_SCORE} | "
            f"Deductions: {self.BASE_SCORE - final_score} | Final: {final_score}/100"
        )

        return RiskReport(
            secure_score=final_score,
            deductions=deductions,
            detected_issues=detected_issues,
            raw_score=self.BASE_SCORE,
        )

    @staticmethod
    def score_to_risk_level(score: int) -> str:
        """
        Convert a numeric score to a risk level label.

        Args:
            score: Integer 0-100.

        Returns:
            Risk level string.
        """
        if score >= 90:
            return "Low"
        elif score >= 70:
            return "Medium"
        elif score >= 50:
            return "High"
        else:
            return "Critical"
