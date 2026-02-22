"""
memory.py
---------
Shared in-memory context store for inter-agent communication.
Acts as the "working memory" of the multi-agent system —
agents write results here and downstream agents read from it.
"""

import logging
from typing import Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("AI-SecureScan.Memory")


class AgentMemory:
    """
    Thread-safe key-value memory store shared across all agents.

    Design rationale:
    - Avoids tight coupling between agents (no direct agent-to-agent calls)
    - Provides full audit trail with timestamps
    - Simple enough for single-process use; can be backed by Redis for distributed deployments

    Usage:
        memory = AgentMemory()
        memory.store("scan_output", "nmap output here...")
        output = memory.retrieve("scan_output")
    """

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self._metadata: dict[str, dict] = {}
        logger.debug("AgentMemory initialized.")

    def store(self, key: str, value: Any, agent: str = "system") -> None:
        """
        Store a value under the given key.

        Args:
            key: Unique key for this memory entry.
            value: Value to store (any serializable type).
            agent: Name of the agent writing this entry (for audit trail).
        """
        self._store[key] = value
        self._metadata[key] = {
            "written_by": agent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.debug(f"Memory.store: key={key!r} by {agent!r}")

    def retrieve(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Retrieve a value from memory.

        Args:
            key: The key to look up.
            default: Value to return if key is not found.

        Returns:
            Stored value or default.
        """
        value = self._store.get(key, default)
        if value is default:
            logger.debug(f"Memory.retrieve: key={key!r} not found, returning default.")
        return value

    def get_all(self) -> dict[str, Any]:
        """Return a shallow copy of the full memory store."""
        return dict(self._store)

    def get_audit_trail(self) -> dict[str, dict]:
        """Return write metadata for all keys (agent name + timestamp)."""
        return dict(self._metadata)

    def clear(self) -> None:
        """Clear all memory entries."""
        self._store.clear()
        self._metadata.clear()
        logger.debug("AgentMemory cleared.")

    def summary(self) -> str:
        """Return a human-readable summary of stored keys."""
        lines = [f"AgentMemory ({len(self._store)} keys):"]
        for key, meta in self._metadata.items():
            lines.append(f"  - {key!r} | written_by={meta['written_by']} | at={meta['timestamp']}")
        return "\n".join(lines)
