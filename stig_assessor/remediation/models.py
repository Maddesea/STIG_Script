"""Remediation models for STIG fix tracking and processing."""

from __future__ import annotations

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
    Represents the result of a remediation action.

    Contains the outcome of applying a fix, including success/failure status,
    messages, and any output or errors.

    Thread-safe: Yes (immutable after creation)
    """
    vid: str
    ok: bool
    message: str
    ts: datetime
    output: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """
        Convert FixResult to dictionary for JSON serialization.

        Returns:
            Dictionary representation with ISO format timestamp
        """
        return {
            "vid": self.vid,
            "ok": self.ok,
            "message": self.message,
            "ts": self.ts.isoformat(),
            "output": self.output,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FixResult":
        """
        Create FixResult from dictionary.

        Supports multiple key formats for flexibility:
        - vid/vuln_id/vulnerability_id
        - ok/success/passed
        - message/msg/status_message

        Args:
            data: Dictionary containing result data

        Returns:
            New FixResult instance

        Raises:
            ValueError: If required fields are missing
        """
        # Extract VID with multiple key support
        vid = data.get("vid") or data.get("vuln_id") or data.get("vulnerability_id")
        if not vid:
            raise ValueError("Missing vulnerability ID (vid/vuln_id/vulnerability_id)")

        # Extract success status with multiple key support
        ok = data.get("ok")
        if ok is None:
            ok = data.get("success")
        if ok is None:
            ok = data.get("passed")
        if ok is None:
            # Try to infer from status string
            status = data.get("status", "").lower()
            ok = status in ("success", "passed", "notafinding", "not_a_finding", "true")

        # Ensure boolean
        if isinstance(ok, str):
            ok = ok.lower() in ("true", "yes", "1", "success", "passed")

        # Extract message with multiple key support
        message = data.get("message") or data.get("msg") or data.get("status_message") or ""

        # Parse timestamp
        ts = datetime.now(timezone.utc)
        ts_str = data.get("ts") or data.get("timestamp")
        if ts_str:
            try:
                if isinstance(ts_str, str):
                    ts = datetime.fromisoformat(ts_str.rstrip("Z"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                pass  # Use default timestamp

        # Extract optional fields
        output = data.get("output") or data.get("stdout")
        error = data.get("error") or data.get("stderr")

        return cls(
            vid=str(vid).strip(),
            ok=bool(ok),
            message=str(message),
            ts=ts,
            output=str(output) if output else None,
            error=str(error) if error else None,
        )
