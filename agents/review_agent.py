"""
review_agent.py
---------------
Evaluates scan output quality and determines if additional scanning is needed.
Returns a strict YES or NO decision with structured reasoning.
"""

import logging
from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory

logger = logging.getLogger("AI-SecureScan.ReviewAgent")

SYSTEM_PROMPT = """You are a senior penetration testing expert reviewing nmap scan output.
Your job is to determine if additional scanning is required to achieve a comprehensive security assessment.

Evaluate:
1. Are there services detected that commonly hide vulnerabilities (e.g., SSH, HTTP, MySQL, Telnet)?
2. Are there ports with unknown services that need further probing?
3. Was OS detection successful?
4. Are there signs of filtered ports that a deeper scan might reveal?

Respond with ONLY one of these two answers:
YES
NO

Do not add any explanation. Do not add punctuation. Just YES or NO.
"""


class ReviewAgent(BaseAgent):
    """
    Reviews scan results to determine if additional scanning is warranted.

    Responsibilities:
    - Analyze the initial scan output
    - Ask the LLM for a clear YES/NO verdict
    - Normalize the response defensively
    """

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("ReviewAgent", llm_client, memory)

    def run(self, scan_output: str) -> bool:
        """
        Determine if additional scanning is required.

        Args:
            scan_output: The raw stdout from the execution agent.

        Returns:
            True if additional scanning is recommended, False otherwise.
        """
        self.logger.info("Reviewing scan output for completeness.")

        if not scan_output or len(scan_output.strip()) < 20:
            self.logger.warning("Scan output is empty or too short. Skipping review.")
            return False

        user_prompt = (
            f"Review the following nmap scan output and decide if additional scanning is required:\n\n"
            f"```\n{scan_output[:4000]}\n```"  # Truncate to manage token cost
        )

        raw = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.0)
        decision = self._normalize_decision(raw)

        self.memory.store("additional_scan_required", decision)
        self.logger.info(f"Review decision: {'Additional scan recommended' if decision else 'No additional scan needed'}")
        return decision

    def _normalize_decision(self, raw: str) -> bool:
        """
        Safely extract YES/NO from potentially noisy LLM output.

        Args:
            raw: Raw LLM response string.

        Returns:
            True if YES, False otherwise.
        """
        cleaned = raw.strip().upper().splitlines()[0][:10]  # Take first line, first 10 chars
        if "YES" in cleaned:
            return True
        elif "NO" in cleaned:
            return False
        else:
            self.logger.warning(f"Unexpected review response: {raw!r}. Defaulting to NO.")
            return False
