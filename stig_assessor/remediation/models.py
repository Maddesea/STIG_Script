"""Remediation models for STIG fix tracking and processing."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Fix:
    """
    Represents a single STIG remediation fix extracted from XCCDF.

    Contains both metadata (VID, severity, title) and actionable commands
    for remediating security findings.

    Thread-safe: Yes (immutable after creation)
    """
    vid: str
    rule_id: str
    severity: str
    title: str
    group_title: str
    fix_text: str
    fix_command: Optional[str] = None
    check_command: Optional[str] = None
    platform: str = "generic"
    rule_version: str = ""
    cci: List[str] = field(default_factory=list)
    legacy: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """
        Convert Fix to dictionary for JSON serialization.

        Returns:
            Dictionary representation with truncated fields for size limits
        """
        return {
            "vid": self.vid,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title[:200],
            "group_title": self.group_title,
            "fix_text": self.fix_text,
            "fix_command": self.fix_command,
            "check_command": self.check_command,
            "platform": self.platform,
            "rule_version": self.rule_version,
            "cci": self.cci[:10],
            "legacy": self.legacy[:10],
        }


@dataclass
class FixResult:
    """
    Represents the result of a remediation fix execution.

    Contains execution metadata (timestamp, success/failure) and output
    details for tracking remediation results.

    Thread-safe: Yes (immutable after creation)
    """
    vid: str
    ts: datetime
    ok: bool
    message: str = ""
    output: str = ""
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """
        Convert FixResult to dictionary for JSON serialization.

        Returns:
            Dictionary representation with ISO-formatted timestamp
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
        Create FixResult from dictionary (JSON deserialization).

        Args:
            data: Dictionary with keys: vid, ts, ok, msg, out, err

        Returns:
            FixResult instance

        Raises:
            ValidationError: If data is not a dictionary or vid is missing
        """
        from STIG_Script import San, ValidationError

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


__all__ = ["Fix", "FixResult"]
