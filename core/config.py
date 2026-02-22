"""
config.py
---------
Centralized, validated environment-based configuration using pydantic-settings.
All configuration is loaded from environment variables / .env file.
No hardcoded secrets. Fail fast on missing required values.
"""

import logging
from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables or .env file.

    Fields:
        groq_api_key: Required Groq API key.
        model: Groq model name to use (default: llama-3.3-70b-versatile).
        safe_mode: If True, disables real command execution.
        log_level: Logging verbosity (DEBUG, INFO, WARNING, ERROR).
        request_timeout: Max seconds for Groq API calls.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    groq_api_key: str = Field(..., description="Groq API key — required")
    model: str = Field(default="llama-3.3-70b-versatile", description="Groq model to use")
    safe_mode: bool = Field(default=True, description="Disable real command execution if True")
    log_level: str = Field(default="INFO", description="Logging level")
    request_timeout: int = Field(default=60, description="Groq API request timeout in seconds")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}, got: {v!r}")
        return upper

    @field_validator("model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("model cannot be empty")
        return v.strip()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    Call this everywhere instead of instantiating Settings directly.
    """
    return Settings()


# Module-level singleton for convenience imports
settings = get_settings()


def configure_logging() -> None:
    """
    Configure the root logger based on settings.
    Call once at application startup.
    """
    numeric_level = getattr(logging, settings.log_level, logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/ai_securescan.log", encoding="utf-8"),
        ],
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("groq").setLevel(logging.WARNING)
