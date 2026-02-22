"""
llm_client.py
-------------
Thin, reusable wrapper around the Groq API (OpenAI-compatible).
Implements retry logic, timeout handling, and cost-aware token logging.
"""

import logging
import time
from typing import Optional

from openai import OpenAI, APITimeoutError, APIConnectionError, RateLimitError, APIStatusError

from core.config import settings

logger = logging.getLogger("AI-SecureScan.LLMClient")


class LLMClient:
    """
    Centralized Groq API client for all agents.

    Design decisions:
    - Single client instance shared across all agents (passed via DI)
    - Retry with exponential backoff on transient errors
    - Token usage logged for cost monitoring
    - Timeout enforced per request
    """

    MAX_RETRIES = 3
    RETRY_BASE_DELAY = 2.0  # seconds

    def __init__(self) -> None:
        self._client = OpenAI(
            api_key=settings.groq_api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=settings.request_timeout,
        )
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0
        logger.info(f"LLMClient initialized | model={settings.model}")

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: Optional[int] = 2048,
    ) -> str:
        """
        Send a chat completion request with retry logic.

        Args:
            system_prompt: System role instruction.
            user_prompt: User message content.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Maximum tokens in response.

        Returns:
            Response content string from the model.

        Raises:
            RuntimeError: If all retries are exhausted.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        last_error: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                logger.debug(f"LLM request attempt {attempt}/{self.MAX_RETRIES}")
                response = self._client.chat.completions.create(
                    model=settings.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                self._log_token_usage(response)
                content = response.choices[0].message.content or ""
                return content.strip()

            except RateLimitError as e:
                wait = self.RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(f"Rate limit hit. Retrying in {wait}s... ({e})")
                time.sleep(wait)
                last_error = e

            except APITimeoutError as e:
                logger.warning(f"Request timed out (attempt {attempt}). ({e})")
                last_error = e

            except APIConnectionError as e:
                logger.warning(f"Connection error (attempt {attempt}). ({e})")
                last_error = e

            except APIStatusError as e:
                logger.error(f"Groq API status error {e.status_code}: {e.message}")
                raise RuntimeError(
                    f"Groq API error: {e.status_code} — {e.message}"
                ) from e

        raise RuntimeError(
            f"LLM request failed after {self.MAX_RETRIES} attempts. "
            f"Last error: {last_error}"
        )

    def _log_token_usage(self, response) -> None:
        """
        Track cumulative token usage for cost monitoring.

        Args:
            response: Groq ChatCompletion response object.
        """
        if response.usage:
            pt = response.usage.prompt_tokens
            ct = response.usage.completion_tokens
            self._total_prompt_tokens += pt
            self._total_completion_tokens += ct
            logger.debug(
                f"Tokens used — prompt: {pt}, completion: {ct} | "
                f"session total — prompt: {self._total_prompt_tokens}, "
                f"completion: {self._total_completion_tokens}"
            )

    @property
    def session_token_summary(self) -> dict:
        """Return a summary of tokens used in this session."""
        return {
            "prompt_tokens": self._total_prompt_tokens,
            "completion_tokens": self._total_completion_tokens,
            "total_tokens": self._total_prompt_tokens + self._total_completion_tokens,
            # Groq free tier — extremely low cost
            "estimated_cost_usd": round(
                (self._total_prompt_tokens * 0.05 / 1_000_000)
                + (self._total_completion_tokens * 0.08 / 1_000_000),
                6,
            ),
        }
