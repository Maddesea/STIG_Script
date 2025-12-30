"""Remediation models for STIG fix tracking and processing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from contextlib import suppress


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

    Contains the outcome of applying a remediation fix, including success/failure
    status, timestamps, output, and error information.

    Thread-safe: Yes (immutable after creation)

    Attributes:
        vid: Vulnerability ID (e.g., "V-123456")
        ok: Whether the remediation was successful
        ts: Timestamp of the remediation (UTC, timezone-aware)
        message: Summary message about the result
        output: Standard output from the remediation command
        error: Error output or exception message
    """
    vid: str
    ok: bool
    ts: datetime
    message: str = ""
    output: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        """Ensure timestamp is timezone-aware."""
        if self.ts.tzinfo is None:
            self.ts = self.ts.replace(tzinfo=timezone.utc)

    def as_dict(self) -> Dict[str, Any]:
        """
        Convert FixResult to dictionary for JSON serialization.

        Returns:
            Dictionary representation with ISO format timestamp
        """
        return {
            "vid": self.vid,
            "ok": self.ok,
            "ts": self.ts.isoformat(),
            "msg": self.message,
            "output": self.output,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FixResult":
        """
        Create FixResult from dictionary (JSON deserialization).

        Args:
            data: Dictionary with result data. Supports multiple key formats
                  for compatibility with different JSON schemas.

        Returns:
            FixResult instance

        Raises:
            ValidationError: If data is invalid or missing required fields
        """
        # Import here to avoid circular imports
        try:
            from stig_assessor.xml.sanitizer import San
            from stig_assessor.exceptions import ValidationError
        except ImportError:
            class ValidationError(Exception):
                pass

            class San:
                @staticmethod
                def vuln(s):
                    return str(s).strip()

        if not isinstance(data, dict):
            raise ValidationError("Result entry must be object")

        # Extract VID with multiple key support
        vid = data.get("vid") or data.get("vuln_id") or data.get("vulnerability_id")
        if not vid:
            raise ValidationError("Result entry missing 'vid'")
        vid = San.vuln(str(vid))

        # Extract success status with multiple key support
        ok = data.get("ok")
        if ok is None:
            ok = data.get("success")
        if ok is None:
            ok = data.get("passed")
        if ok is None:
            ok = data.get("result") == "pass"
        ok = bool(ok)

        # Parse timestamp
        ts = datetime.now(timezone.utc)
        ts_val = data.get("ts") or data.get("timestamp") or data.get("time")
        if ts_val:
            with suppress(Exception):
                if isinstance(ts_val, str):
                    ts = datetime.fromisoformat(ts_val.rstrip("Z"))
                elif isinstance(ts_val, (int, float)):
                    ts = datetime.fromtimestamp(ts_val, tz=timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        # Extract message
        message = data.get("msg") or data.get("message") or data.get("summary") or ""

        # Extract output
        output = data.get("output") or data.get("stdout") or ""

        # Extract error
        error = data.get("error") or data.get("stderr") or data.get("err") or ""

        return cls(
            vid=vid,
            ok=ok,
            ts=ts,
            message=str(message),
            output=str(output),
            error=str(error),
        )
