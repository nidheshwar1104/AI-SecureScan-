"""
base_agent.py
-------------
Abstract base class for all agents in AI-SecureScan.
Provides shared logging, LLM invocation, and structured JSON parsing.
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

from core.llm_client import LLMClient
from core.memory import AgentMemory


class BaseAgent(ABC):
    """
    Abstract base for all scanning agents.

    Every agent shares:
    - A named logger
    - Access to the shared LLM client
    - Access to shared agent memory/context
    - Helpers for safe JSON parsing with fallback
    """

    def __init__(self, name: str, llm_client: LLMClient, memory: AgentMemory) -> None:
        self.name = name
        self.llm = llm_client
        self.memory = memory
        self.logger = logging.getLogger(f"AI-SecureScan.{name}")
        self.logger.info(f"{self.name} initialized.")

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> Any:
        """
        Entry point for agent execution.
        Must be implemented by each subclass.
        """
        ...

    def _call_llm(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        """
        Invoke the LLM and return the raw response string.

        Args:
            system_prompt: System-level instruction for the model.
            user_prompt: The user/task prompt.
            temperature: Sampling temperature (lower = more deterministic).

        Returns:
            Raw text content from the LLM response.
        """
        self.logger.debug(f"Calling LLM | system={system_prompt[:80]}...")
        response = self.llm.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
        )
        return response

    def _parse_json_response(self, raw: str, fallback: dict) -> dict:
        """
        Safely parse JSON from LLM response with fallback.

        Handles common LLM quirks:
        - Markdown code fences (```json ... ```)
        - Leading/trailing whitespace
        - Invalid JSON → returns fallback dict

        Args:
            raw: Raw string from LLM.
            fallback: Default dict to return on parse failure.

        Returns:
            Parsed dict or fallback dict.
        """
        try:
            # Strip markdown code fences if present
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.splitlines()
                # Remove first and last fence lines
                cleaned = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError) as exc:
            self.logger.warning(f"JSON parse failed: {exc}. Using fallback.")
            return fallback
