"""Remediation models and data structures.

This module contains dataclasses for remediation results processing.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any
from contextlib import suppress


@dataclass
class FixResult:
    """
    Remediation execution result for a single vulnerability.

    Attributes:
        vid: Vulnerability ID (e.g., "V-123456")
        ts: Timestamp of remediation execution
        ok: Whether remediation was successful
        message: Human-readable status message
        output: Command output/logs
        error: Error message if failed
    """
    vid: str
    ts: datetime
    ok: bool
    message: str = ""
    output: str = ""
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation
        """
        return {
            "vid": self.vid,
            "ts": self.ts.isoformat(),
            "ok": self.ok,
            "msg": self.message,
            "out": self.output,
            "err": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FixResult":
        """
        Create FixResult from dictionary.

        Args:
            data: Dictionary with result data

        Returns:
            FixResult instance

        Raises:
            ValidationError: If data is invalid
        """
        # Import here to avoid circular dependency
        from STIG_Script import ValidationError, San

        if not isinstance(data, dict):
            raise ValidationError("Result entry must be object")

        vid = San.vuln(data.get("vid", ""))
        ts = datetime.now(timezone.utc)
        ts_str = data.get("ts")

        if ts_str:
            with suppress(Exception):
                ts = datetime.fromisoformat(ts_str.rstrip("Z"))

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return cls(
            vid=vid,
            ts=ts,
            ok=bool(data.get("ok", False)),
            message=str(data.get("msg", "") or ""),
            output=str(data.get("out", "") or ""),
            error=str(data.get("err", "") or ""),
        )


__all__ = ["FixResult"]
