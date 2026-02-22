"""
execution_agent.py
------------------
Securely executes the validated scan command using subprocess.
Respects SAFE_MODE to prevent real execution in controlled environments.
Includes timeout protection and strict injection prevention.
"""

import shlex
import logging
import subprocess
from dataclasses import dataclass

from agents.base_agent import BaseAgent
from core.config import settings
from core.llm_client import LLMClient
from core.memory import AgentMemory

logger = logging.getLogger("AI-SecureScan.ExecutionAgent")

SAFE_MODE_MOCK_OUTPUT = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.6 (CentOS)
443/tcp  open  ssl/https  Apache httpd 2.4.6
3306/tcp open  mysql      MySQL 5.6.44
8080/tcp open  http-proxy Squid http proxy 3.5.20
23/tcp   open  telnet     Linux telnetd

Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
""".strip()


@dataclass
class ExecutionResult:
    """Holds stdout, stderr, and return code from command execution."""
    stdout: str
    stderr: str
    returncode: int
    safe_mode: bool


class ExecutionAgent(BaseAgent):
    """
    Executes the nmap scan command securely.

    In SAFE_MODE=true: returns a realistic mock output without executing anything.
    In SAFE_MODE=false: runs the command via subprocess with timeout and injection prevention.
    """

    COMMAND_TIMEOUT_SECONDS: int = 120

    def __init__(self, llm_client: LLMClient, memory: AgentMemory) -> None:
        super().__init__("ExecutionAgent", llm_client, memory)

    def run(self, command: str) -> ExecutionResult:
        """
        Execute the scan command and capture output.

        Args:
            command: Validated nmap command string.

        Returns:
            ExecutionResult with stdout, stderr, returncode, and safe_mode flag.
        """
        if settings.safe_mode:
            self.logger.warning("SAFE_MODE=true — skipping real execution, returning mock output.")
            result = ExecutionResult(
                stdout=SAFE_MODE_MOCK_OUTPUT,
                stderr="",
                returncode=0,
                safe_mode=True,
            )
        else:
            self.logger.info(f"Executing command: {command}")
            result = self._run_subprocess(command)

        self.memory.store("scan_output", result.stdout)
        self.memory.store("scan_stderr", result.stderr)
        return result

    def _run_subprocess(self, command: str) -> ExecutionResult:
        """
        Run the command using subprocess with security best practices.

        Security measures:
        - Uses shlex.split() to prevent shell injection
        - shell=False to avoid shell interpretation
        - Explicit timeout to prevent hanging
        - Captures stderr separately

        Args:
            command: Raw command string.

        Returns:
            ExecutionResult populated from process output.
        """
        try:
            args = shlex.split(command)
            # Extra safety: ensure first arg is nmap binary
            if args[0] != "nmap":
                raise ValueError(f"Only 'nmap' is permitted as executable. Got: {args[0]!r}")

            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
                shell=False,  # Critical: never use shell=True
            )
            self.logger.info(f"Scan completed. Return code: {process.returncode}")
            return ExecutionResult(
                stdout=process.stdout,
                stderr=process.stderr,
                returncode=process.returncode,
                safe_mode=False,
            )

        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out after {self.COMMAND_TIMEOUT_SECONDS}s.")
            return ExecutionResult(
                stdout="",
                stderr=f"Command timed out after {self.COMMAND_TIMEOUT_SECONDS} seconds.",
                returncode=-1,
                safe_mode=False,
            )
        except FileNotFoundError:
            self.logger.error("nmap binary not found on this system.")
            return ExecutionResult(
                stdout="",
                stderr="nmap is not installed or not in PATH.",
                returncode=-2,
                safe_mode=False,
            )
        except Exception as exc:
            self.logger.exception(f"Unexpected error during execution: {exc}")
            return ExecutionResult(
                stdout="",
                stderr=str(exc),
                returncode=-3,
                safe_mode=False,
            )
