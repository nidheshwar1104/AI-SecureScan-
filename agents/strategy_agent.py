"""
strategy_agent.py
-----------------
Generates a safe, optimized nmap scan command for a given target.
Validates the command to ensure it is non-destructive before returning.
"""

import re
import logging
from agents.base_agent import BaseAgent
from core.llm_client import LLMClient
from core.memory import AgentMemory

logger = logging.getLogger("AI-SecureScan.StrategyAgent")

# Patterns that would indicate dangerous or destructive commands
BLOCKED_PATTERNS = [
    r"--script.*exploit",
    r"--script.*brute",
    r"--script.*dos",
    r"-A\b.*--script",  # aggressive + script combo
    r"rm\s",
    r"mkfs",
    r"dd\s+if=",
    r";\s*\w+",          # command chaining
    r"\|\s*\w+",         # piping to other commands
    r"&&",
    r"\|\|",
    r"`",
    r"\$\(",
]

SYSTEM_PROMPT = """You are a senior cybersecurity architect specializing in network reconnaissance.
Your task is to generate a single, safe, non-destructive nmap command to scan a target.

Rules:
- Output ONLY the raw nmap command string, nothing else. No explanation, no markdown.
- Never include exploit scripts, brute force scripts, or denial-of-service flags.
- Use -sV for version detection, -O for OS detection (optional), --open to show only open ports.
- Use timing template -T3 (default) or lower.
- Include --script=safe or avoid --script entirely unless using well-known safe scripts.
- Target must be embedded exactly as provided.
- Command must start with: nmap
"""


class StrategyAgent(BaseAgent):
    """
    Plans the vulnerability scan strategy.

    Responsibilities:
    - Accepts a target (IP / hostname / CIDR)
    - Uses LLM to generate an optimized scan command
    - Validates command safety before returning
    """

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("StrategyAgent", llm_client, memory)

    def run(self, target: str) -> str:
        """
        Generate and validate a scan command for the given target.

        Args:
            target: IP address, hostname, or CIDR range to scan.

        Returns:
            A validated, safe nmap command string.

        Raises:
            ValueError: If the generated command fails safety validation.
        """
        self.logger.info(f"Generating scan strategy for target: {target}")

        user_prompt = f"Generate a safe, comprehensive nmap scan command for this target: {target}"
        raw_command = self._call_llm(SYSTEM_PROMPT, user_prompt, temperature=0.1)
        command = raw_command.strip().splitlines()[0].strip()  # take only first line

        self.logger.debug(f"LLM proposed command: {command}")
        self._validate_command(command, target)

        self.memory.store("scan_command", command)
        self.memory.store("target", target)
        self.logger.info(f"Validated scan command: {command}")
        return command

    def _validate_command(self, command: str, target: str) -> None:
        """
        Enforce safety rules on the generated command.

        Args:
            command: The nmap command string to validate.
            target: The intended scan target.

        Raises:
            ValueError: If the command violates any safety rule.
        """
        if not command.startswith("nmap"):
            raise ValueError(f"Command must start with 'nmap'. Got: {command!r}")

        # Ensure the target appears in the command
        if target not in command:
            raise ValueError(f"Target '{target}' not found in command: {command!r}")

        # Check for blocked dangerous patterns
        for pattern in BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                raise ValueError(f"Command contains blocked pattern '{pattern}': {command!r}")

        # Disallow flags known to be destructive or intrusive
        blocked_flags = {"--script=exploit", "-sS --privileged", "--flood"}
        for flag in blocked_flags:
            if flag in command:
                raise ValueError(f"Command contains blocked flag '{flag}'")
