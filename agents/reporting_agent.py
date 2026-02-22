"""
reporting_agent.py
------------------
Generates a professional, timestamped Markdown security report.
Assembles all agent outputs into a structured, readable document.
"""

import os
import logging
from datetime import datetime, timezone
from pathlib import Path

from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory

logger = logging.getLogger("AI-SecureScan.ReportingAgent")

REPORTS_DIR = Path("reports")


class ReportingAgent(BaseAgent):
    """
    Produces a professional Markdown security report.

    Assembles:
    - Executive summary (LLM-generated)
    - Scan metadata and raw output
    - Risk assessment and scoring
    - Mitigation steps
    - Patch commands and firewall rules
    - CIS Control mappings
    """

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("ReportingAgent", llm_client, memory)
        REPORTS_DIR.mkdir(exist_ok=True)

    def run(
        self,
        target: str,
        scan_command: str,
        scan_output: str,
        mitigation: dict,
        feroxbuster_result: dict | None = None,
        enumeration_result: dict | None = None,
        nikto_result: dict | None = None,
    ) -> str:
        """
        Generate and save the Markdown report.

        Args:
            target: The scanned target.
            scan_command: The nmap command that was used.
            scan_output: Raw scan output.
            mitigation: Structured mitigation dict from MitigationAgent.
            feroxbuster_result: Optional Feroxbuster findings dict.
            enumeration_result: Optional Enumeration findings dict.
            nikto_result: Optional Nikto findings dict.

        Returns:
            Absolute path to the saved report file.
        """
        self.logger.info("Generating security report.")
        timestamp = datetime.now(timezone.utc)
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
        filename = REPORTS_DIR / f"SecureScan_Report_{timestamp_str}.md"

        exec_summary = self._generate_executive_summary(target, mitigation)
        report_content = self._build_report(
            target, scan_command, scan_output, mitigation, exec_summary, timestamp,
            feroxbuster_result, enumeration_result, nikto_result,
        )

        filename.write_text(report_content, encoding="utf-8")
        self.memory.store("report_path", str(filename.resolve()))
        self.logger.info(f"Report saved to: {filename.resolve()}")
        return str(filename.resolve())

    def _generate_executive_summary(self, target: str, mitigation: dict) -> str:
        """
        Use LLM to write a concise executive summary paragraph.

        Args:
            target: Scanned target.
            mitigation: Mitigation data dict.

        Returns:
            A plain-text executive summary string.
        """
        system_prompt = (
            "You are a cybersecurity report writer. Write a concise 3-4 sentence executive summary "
            "for a non-technical audience. Focus on the risk level, key findings, and urgency of action. "
            "Do not use bullet points. Write in professional prose only."
        )
        user_prompt = (
            f"Target: {target}\n"
            f"Risk Level: {mitigation.get('risk_level', 'Unknown')}\n"
            f"Composite Secure Score: {mitigation.get('composite_secure_score', 'N/A')}/100\n"
            f"Key Issues: {', '.join(mitigation.get('detected_issues', ['No issues detected']))}\n"
            f"Write the executive summary now."
        )
        return self._call_llm(system_prompt, user_prompt, temperature=0.4)

    def _build_report(
        self,
        target: str,
        scan_command: str,
        scan_output: str,
        mitigation: dict,
        exec_summary: str,
        timestamp: datetime,
        feroxbuster_result: dict | None = None,
        enumeration_result: dict | None = None,
        nikto_result: dict | None = None,
    ) -> str:
        """
        Assemble the full Markdown report string.
        """
        risk_level = mitigation.get("risk_level", "Unknown")
        confidence = mitigation.get("confidence_score", "N/A")
        risk_explanation = mitigation.get("risk_explanation", "N/A")
        ai_score = mitigation.get("ai_secure_score", "N/A")
        det_score = mitigation.get("deterministic_secure_score", "N/A")
        composite = mitigation.get("composite_secure_score", "N/A")
        deductions = mitigation.get("risk_deductions", [])
        detected = mitigation.get("detected_issues", [])

        mitigation_steps = mitigation.get("mitigation_steps", [])
        patch_cmds = mitigation.get("linux_patch_commands", [])
        firewall_rules = mitigation.get("firewall_recommendations", [])
        cis_controls = mitigation.get("cis_control_mapping", [])

        # Build deductions table
        deductions_rows = "\n".join(
            f"| {d.get('reason', 'N/A')} | -{d.get('points', 0)} |" for d in deductions
        ) or "| No deductions | 0 |"

        # Build CIS table
        cis_rows = "\n".join(
            f"| {c.get('control_id', '')} | {c.get('description', '')} | {c.get('relevance', '')} |"
            for c in cis_controls
        ) or "| N/A | N/A | N/A |"

        detected_list = "\n".join(f"- {issue}" for issue in detected) or "- None detected"
        mitigation_list = "\n".join(f"- {step}" for step in mitigation_steps) or "- None"
        patch_block = "\n".join(patch_cmds) or "# No commands generated"
        firewall_block = "\n".join(firewall_rules) or "# No rules generated"

        # ── Build optional web tool sections ──────────────────────────────────
        ferox_section = self._build_feroxbuster_section(feroxbuster_result)
        enum_section = self._build_enumeration_section(enumeration_result)
        nikto_section = self._build_nikto_section(nikto_result)

        report = f"""# 🛡️ AI-SecureScan — Vulnerability Assessment Report

---

**Report Generated:** {timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Target:** `{target}`  
**Scan Tool:** nmap  
**Analysis Engine:** AI-SecureScan v1.0  

---

## 📋 Executive Summary

{exec_summary}

---

## 🔍 Scan Details

| Field | Value |
|-------|-------|
| Target | `{target}` |
| Command Used | `{scan_command}` |
| Timestamp | {timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")} |

### Raw Scan Output

```
{scan_output}
```

---

## ⚠️ Risk Assessment

| Metric | Value |
|--------|-------|
| **Risk Level** | {risk_level} |
| **AI Confidence** | {confidence}% |
| **AI Secure Score** | {ai_score}/100 |
| **Deterministic Secure Score** | {det_score}/100 |
| **Composite Secure Score** | {composite}/100 |

### Risk Explanation

{risk_explanation}

### Detected Issues

{detected_list}

---

## 📉 Score Deductions (Deterministic Engine)

| Reason | Points Deducted |
|--------|----------------|
{deductions_rows}

---

## 🔧 Mitigation Plan

### Recommended Actions

{mitigation_list}

### Linux Patch Commands

```bash
{patch_block}
```

### Firewall Recommendations

```bash
{firewall_block}
```

---

## 🏛️ CIS Controls Mapping

| Control ID | Description | Relevance to Findings |
|------------|-------------|----------------------|
{cis_rows}

---

## 📊 Secure Score Summary

```
AI Secure Score          : {ai_score}/100
Deterministic Score      : {det_score}/100
─────────────────────────────────────────
Composite Secure Score   : {composite}/100
```

> **Score Interpretation:**
> - 90–100: Excellent — Well-hardened system
> - 70–89:  Good — Minor improvements needed
> - 50–69:  Fair — Moderate risk, action recommended
> - 30–49:  Poor — High risk, immediate action required
> - 0–29:   Critical — Severely exposed, urgent remediation needed

---

## ⚠️ Disclaimer

This report was generated by an automated AI-assisted tool. Results should be reviewed by a 
qualified security professional before taking action. This tool is intended for authorized 
security assessments only. Unauthorized scanning is illegal.

---

*Generated by AI-SecureScan | Powered by OpenAI | Architecture: Multi-Agent*
"""
        # Insert web tool sections before disclaimer
        insert_before = "## ⚠️ Disclaimer"
        report = report.replace(insert_before, ferox_section + "\n" + enum_section + "\n" + nikto_section + "\n" + insert_before)
        return report

    def _build_feroxbuster_section(self, result: dict | None) -> str:
        if not result:
            return ""
        ai = result.get("ai_analysis", {})
        critical = result.get("critical_flags", [])
        flags_md = "\n".join(f"- {f}" for f in critical) or "- None"
        attack_vecs = "\n".join(f"- {v}" for v in ai.get("attack_vectors", [])) or "- None"
        remed = "\n".join(f"- {r}" for r in ai.get("remediation", [])) or "- None"
        return f"""---

## 🗂️ Feroxbuster — Web Directory Enumeration

| Metric | Value |
|--------|-------|
| Discovered Paths | {result.get('discovered_count', 'N/A')} |
| Critical Findings | {result.get('critical_count', 'N/A')} |
| Web Risk Score | {ai.get('web_risk_score', 'N/A')}/100 |
| Target URL | `{result.get('url', 'N/A')}` |

### Critical Path Findings
{flags_md}

### Risk Summary
{ai.get('risk_summary', 'N/A')}

### Attack Vectors
{attack_vecs}

### Remediation
{remed}

"""

    def _build_enumeration_section(self, result: dict | None) -> str:
        if not result:
            return ""
        ai = result.get("ai_analysis", {})
        flags = result.get("critical_flags", [])
        flags_md = "\n".join(f"- {f}" for f in flags) or "- None"
        users = "\n".join(f"- `{u}`" for u in ai.get("users_discovered", [])) or "- None discovered"
        shares = "\n".join(f"- `{s}`" for s in ai.get("shares_discovered", [])) or "- None"
        headers = "\n".join(f"- {h}" for h in ai.get("security_headers_missing", [])) or "- None missing"
        attacks = "\n".join(f"- {a}" for a in ai.get("recommended_attacks", [])) or "- None"
        return f"""---

## 🔎 Enumeration — SMB / DNS / HTTP / SNMP

| Metric | Value |
|--------|-------|
| Enumeration Risk Score | {ai.get('enumeration_risk_score', 'N/A')}/100 |
| Target | `{result.get('target', 'N/A')}` |

### Critical Flags
{flags_md}

### Users Discovered (SMB)
{users}

### Accessible Shares
{shares}

### Missing Security Headers
{headers}

### Attack Surface Summary
{ai.get('attack_surface_summary', 'N/A')}

### Recommended Attack Vectors
{attacks}

"""

    def _build_nikto_section(self, result: dict | None) -> str:
        if not result:
            return ""
        ai = result.get("ai_analysis", {})
        flags = result.get("critical_flags", [])
        flags_md = "\n".join(f"- {f}" for f in flags) or "- None"
        osvdb = ", ".join(result.get("osvdb_ids", [])) or "None"
        vulns = "\n".join(f"- {v}" for v in ai.get("critical_vulnerabilities", [])) or "- None"
        misconf = "\n".join(f"- {m}" for m in ai.get("misconfigurations", [])) or "- None"
        cookie = "\n".join(f"- {c}" for c in ai.get("cookie_issues", [])) or "- None"

        # Build remediation priority table
        remed_rows = ""
        for item in ai.get("remediation_priority", []):
            remed_rows += f"| {item.get('priority','?')} | {item.get('issue','?')} | {item.get('fix','?')} |\n"
        remed_table = (
            "| Priority | Issue | Fix |\n|----------|-------|-----|\n" + remed_rows
            if remed_rows else "No remediation data available."
        )

        return f"""---

## 🌐 Nikto — Web Vulnerability Scan

| Metric | Value |
|--------|-------|
| Total Findings | {result.get('total_findings', 'N/A')} |
| Nikto Risk Score | {ai.get('nikto_risk_score', 'N/A')}/100 |
| OSVDB/CVE References | {osvdb} |
| Target URL | `{result.get('url', 'N/A')}` |

### ⚡ Executive Finding
> {ai.get('executive_finding', 'N/A')}

### Critical Vulnerabilities
{vulns}

### Misconfigurations
{misconf}

### Cookie Security Issues
{cookie}

### Remediation Priority Table
{remed_table}

### Critical Flags (Deterministic)
{flags_md}

"""
