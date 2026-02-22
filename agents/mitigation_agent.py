"""
mitigation_agent.py
-------------------
AI-powered risk classification and structured mitigation planning.

STRICT EVIDENCE MODE:
- Only analyzes vulnerabilities explicitly present in scan output.
- Prevents AI hallucination of services, login pages, or software.
- Combines LLM qualitative analysis + deterministic risk engine scoring.
"""

import logging
from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.risk_engine import RiskEngine, RiskReport

logger = logging.getLogger("AI-SecureScan.MitigationAgent")


# ─────────────────────────────────────────────────────────────
# 🔒 STRICT SYSTEM PROMPT (Anti-Hallucination Version)
# ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a senior cybersecurity risk analyst.

STRICT ANALYSIS RULES:
- ONLY analyze vulnerabilities explicitly visible in the provided scan output.
- DO NOT assume additional services.
- DO NOT invent login pages, CGI paths, admin panels, or hidden endpoints.
- DO NOT assume outdated software unless version evidence is present.
- If something is not directly shown in the scan output, DO NOT mention it.
- Every risk must be traceable to specific evidence from the scan text.

You MUST respond with ONLY a valid JSON object.
No markdown. No explanations. No extra text.

The JSON schema must follow EXACTLY:

{
  "risk_level": "<Low|Medium|High|Critical>",
  "confidence_score": <integer 0-100>,
  "risk_explanation": "<detailed explanation strictly based on scan evidence>",
  "mitigation_steps": [
    "<step 1>",
    "<step 2>"
  ],
  "linux_patch_commands": [
    "<real runnable shell command>"
  ],
  "firewall_recommendations": [
    "<iptables or ufw rule>"
  ],
  "cis_control_mapping": [
    {
      "control_id": "<CIS Control v8 ID>",
      "description": "<official control description>",
      "relevance": "<how it directly relates to detected issue>"
    }
  ],
  "ai_secure_score": <integer 0-100>
}

Guidelines:
- risk_level must reflect ONLY confirmed findings.
- confidence_score depends on completeness of scan data.
- linux_patch_commands must be real apt/yum/systemctl commands.
- firewall_recommendations must use iptables or ufw syntax.
- ai_secure_score: 100 = hardened, 0 = critically exposed.
"""


# ─────────────────────────────────────────────────────────────
# Fallback if JSON parsing fails
# ─────────────────────────────────────────────────────────────
FALLBACK_MITIGATION: dict = {
    "risk_level": "Unknown",
    "confidence_score": 0,
    "risk_explanation": "Unable to parse AI risk assessment. Manual review required.",
    "mitigation_steps": ["Perform manual security audit."],
    "linux_patch_commands": ["sudo apt update && sudo apt upgrade -y"],
    "firewall_recommendations": ["sudo ufw enable", "sudo ufw default deny incoming"],
    "cis_control_mapping": [
        {
            "control_id": "CIS Control 4.1",
            "description": "Establish and Maintain a Secure Configuration Process",
            "relevance": "Apply baseline security configurations to all systems.",
        }
    ],
    "ai_secure_score": 0,
}


class MitigationAgent(BaseAgent):
    """
    Generates structured risk assessment + mitigation plan.

    Combines:
    - LLM-based qualitative analysis (STRICT evidence mode)
    - Deterministic risk engine scoring
    """

    def __init__(
        self,
        llm_client: LLMClient,
        memory: AgentMemory,
        risk_engine: RiskEngine,
    ) -> None:
        super().__init__("MitigationAgent", llm_client, memory)
        self.risk_engine = risk_engine

    def run(self, scan_output: str) -> dict:
        """
        Analyze scan output and produce mitigation report.

        Args:
            scan_output: Raw nmap stdout

        Returns:
            Structured dict containing risk + mitigation plan
        """

        self.logger.info("Running AI risk classification and mitigation planning.")

        # ─────────────────────────────────────────────
        # Step 1: STRICT LLM Evidence-Based Assessment
        # ─────────────────────────────────────────────
        user_prompt = (
            "Analyze the following nmap scan output. "
            "Only use evidence explicitly present in the text.\n\n"
            f"{scan_output[:5000]}"
        )

        raw_response = self._call_llm(
            SYSTEM_PROMPT,
            user_prompt,
            temperature=0.1  # lower temp = more deterministic
        )

        mitigation_data = self._parse_json_response(
            raw_response,
            FALLBACK_MITIGATION
        )

        # ─────────────────────────────────────────────
        # Step 2: Deterministic Risk Engine Overlay
        # ─────────────────────────────────────────────
        risk_report: RiskReport = self.risk_engine.calculate(scan_output)

        mitigation_data["deterministic_secure_score"] = risk_report.secure_score
        mitigation_data["risk_deductions"] = risk_report.deductions
        mitigation_data["detected_issues"] = risk_report.detected_issues

        # ─────────────────────────────────────────────
        # Step 3: Composite Secure Score
        # ─────────────────────────────────────────────
        ai_score = mitigation_data.get("ai_secure_score", 50)
        composite = round((ai_score + risk_report.secure_score) / 2)

        mitigation_data["composite_secure_score"] = composite

        self.memory.store("mitigation_report", mitigation_data)

        self.logger.info(
            f"Risk Level: {mitigation_data.get('risk_level')} | "
            f"Composite Score: {composite}/100"
        )

        return mitigation_data
