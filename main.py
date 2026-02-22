"""
main.py
-------
AI-SecureScan — Entry point and pipeline orchestrator.

Coordinates the multi-agent scanning pipeline:
  StrategyAgent → ExecutionAgent → ReviewAgent → MitigationAgent → ReportingAgent

Handles graceful shutdown, top-level error handling, and final reporting.
"""

import sys
import signal
import logging
import argparse

from core.config import configure_logging, settings
from core.llm_client import LLMClient
from core.memory import AgentMemory
from core.risk_engine import RiskEngine
from agents.strategy_agent import StrategyAgent
from agents.execution_agent import ExecutionAgent
from agents.review_agent import ReviewAgent
from agents.mitigation_agent import MitigationAgent
from agents.reporting_agent import ReportingAgent
from agents.feroxbuster_agent import FeroxbusterAgent
from agents.enumeration_agent import EnumerationAgent
from agents.nikto_agent import NiktoAgent

# ─── Logging must be configured before any other imports use loggers ───────────
import os
os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)
configure_logging()

logger = logging.getLogger("AI-SecureScan.Main")

# ─── Graceful Shutdown ─────────────────────────────────────────────────────────
_shutdown_requested = False


def _handle_signal(signum: int, frame) -> None:
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    global _shutdown_requested
    logger.warning(f"Received signal {signum}. Initiating graceful shutdown...")
    _shutdown_requested = True


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ─── Pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(target: str, port: int = 80, domain: str | None = None) -> None:
    """
    Execute the full AI-SecureScan multi-agent pipeline.

    Pipeline stages:
    1. StrategyAgent     → Generate safe nmap scan command
    2. ExecutionAgent    → Execute command (or mock in SAFE_MODE)
    3. ReviewAgent       → Evaluate if re-scan is needed
    4. FeroxbusterAgent  → Web directory brute-force
    5. EnumerationAgent  → SMB / DNS / HTTP / SNMP enumeration
    6. NiktoAgent        → Web vulnerability scanning
    7. MitigationAgent   → AI risk classification + deterministic scoring
    8. ReportingAgent    → Generate unified Markdown report

    Args:
        target: The IP address, hostname, or CIDR range to scan.
        port: HTTP port for web scans (default 80).
        domain: Domain name for DNS enumeration (optional).
    """
    logger.info("=" * 60)
    logger.info("🛡  AI-SecureScan Pipeline Starting")
    logger.info(f"   Target      : {target}")
    logger.info(f"   Port        : {port}")
    logger.info(f"   Model       : {settings.model}")
    logger.info(f"   Safe Mode   : {settings.safe_mode}")
    logger.info("=" * 60)

    memory = AgentMemory()
    llm = LLMClient()
    risk_engine = RiskEngine()

    # ── Stage 1: Strategy ─────────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[1/8] StrategyAgent — Generating scan command...")
    strategy_agent = StrategyAgent(llm_client=llm, memory=memory)
    try:
        scan_command = strategy_agent.run(target=target)
        print(f"\n✅ Scan Command: {scan_command}\n")
    except ValueError as e:
        logger.error(f"StrategyAgent rejected command: {e}")
        sys.exit(1)

    # ── Stage 2: Execution ────────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[2/8] ExecutionAgent — Running nmap scan...")
    execution_agent = ExecutionAgent(llm_client=llm, memory=memory)
    exec_result = execution_agent.run(command=scan_command)
    if exec_result.safe_mode:
        print("⚠️  SAFE_MODE=true — Using mock scan output\n")
    if not exec_result.stdout:
        logger.error("Scan produced no output. Aborting.")
        sys.exit(1)
    print(f"📡 Nmap Preview:\n{exec_result.stdout[:400]}...\n")

    # ── Stage 3: Review ───────────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[3/8] ReviewAgent — Evaluating scan completeness...")
    review_agent = ReviewAgent(llm_client=llm, memory=memory)
    needs_rescan = review_agent.run(scan_output=exec_result.stdout)
    status = "🔁 Additional scan recommended" if needs_rescan else "✅ Scan sufficient"
    print(f"{status}\n")

    # ── Stage 4: Feroxbuster ──────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[4/8] FeroxbusterAgent — Web directory enumeration...")
    ferox_agent = FeroxbusterAgent(llm_client=llm, memory=memory)
    ferox_result_obj = ferox_agent.run(target=target, port=port)
    ferox_data = memory.retrieve("feroxbuster_result")
    print(f"🗂️  Feroxbuster: {ferox_result_obj.total_findings if hasattr(ferox_result_obj, 'total_findings') else len(ferox_result_obj.discovered_paths)} paths | {len(ferox_result_obj.critical_findings)} critical\n")

    # ── Stage 5: Enumeration ──────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[5/8] EnumerationAgent — SMB/DNS/HTTP/SNMP enumeration...")
    enum_agent = EnumerationAgent(llm_client=llm, memory=memory)
    enum_result_obj = enum_agent.run(target=target, domain=domain, port=port)
    enum_data = memory.retrieve("enumeration_result")
    print(f"🔎  Enumeration: {len(enum_result_obj.critical_flags)} critical flags found\n")

    # ── Stage 6: Nikto ───────────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[6/8] NiktoAgent — Web vulnerability scanning...")
    nikto_agent = NiktoAgent(llm_client=llm, memory=memory)
    nikto_result_obj = nikto_agent.run(target=target, port=port)
    nikto_data = memory.retrieve("nikto_result")
    print(f"🌐  Nikto: {nikto_result_obj.total_findings} findings | {len(nikto_result_obj.osvdb_ids)} OSVDB refs\n")

    # ── Stage 7: Mitigation ───────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[7/8] MitigationAgent — Risk classification...")
    # Combine all scan outputs for holistic risk scoring
    combined_output = (
        exec_result.stdout + "\n" +
        ferox_result_obj.raw_output + "\n" +
        enum_result_obj.smb_output + "\n" +
        nikto_result_obj.raw_output
    )
    mitigation_agent = MitigationAgent(llm_client=llm, memory=memory, risk_engine=risk_engine)
    mitigation_report = mitigation_agent.run(scan_output=combined_output)
    print(f"⚠️  Risk Level       : {mitigation_report.get('risk_level', 'Unknown')}")
    print(f"🎯 Confidence Score : {mitigation_report.get('confidence_score', 'N/A')}%")
    print(f"📊 Composite Score  : {mitigation_report.get('composite_secure_score', 'N/A')}/100\n")

    # ── Stage 8: Reporting ────────────────────────────────────────────────────
    if _shutdown_requested: return
    logger.info("[8/8] ReportingAgent — Generating unified report...")
    reporting_agent = ReportingAgent(llm_client=llm, memory=memory)
    report_path = reporting_agent.run(
        target=target,
        scan_command=scan_command,
        scan_output=exec_result.stdout,
        mitigation=mitigation_report,
        feroxbuster_result=ferox_data,
        enumeration_result=enum_data,
        nikto_result=nikto_data,
    )
    print(f"📄 Report saved to: {report_path}\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    token_summary = llm.session_token_summary
    logger.info(f"Token usage: {token_summary}")
    print("=" * 60)
    print("🛡  AI-SecureScan Complete")
    print(f"   Report : {report_path}")
    print(f"   Tokens : {token_summary['total_tokens']}")
    print(f"   Cost   : ${token_summary['estimated_cost_usd']}")
    print("=" * 60)
    logger.debug("\n" + memory.summary())


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ai-securescan",
        description="🛡 AI-SecureScan — Agentic AI-Powered Vulnerability Scanner",
    )
    parser.add_argument(
        "target",
        type=str,
        help="Target IP address, hostname, or CIDR range (e.g., 192.168.1.1)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=80,
        help="HTTP port for web scanning tools (default: 80, use 443 for HTTPS)",
    )
    parser.add_argument(
        "--domain", "-d",
        type=str,
        default=None,
        help="Domain name for DNS enumeration (e.g., example.com)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        run_pipeline(target=args.target, port=args.port, domain=args.domain)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(0)
    except RuntimeError as e:
        logger.error(f"Pipeline failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)
