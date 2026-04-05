"""Remediation models for STIG fix tracking and processing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union
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
    """Vulnerability ID (e.g., 'V-12345')."""
    rule_id: str
    """Associated Rule ID."""
    severity: str
    """Severity classification (e.g., 'high', 'medium')."""
    title: str
    """Vulnerability title/description."""
    group_title: str
    """Title of the containing group."""
    fix_text: str
    """Human-readable remediation instructions."""
    fix_command: Optional[str] = None
    """Machine-readable fix command."""
    check_command: Optional[str] = None
    """Machine-readable check command."""
    platform: str = "generic"
    """Target platform."""
    rule_version: str = ""
    """Version of the application rule."""
    cci: List[str] = field(default_factory=list)
    """List of mapped CCIs."""
    legacy: List[str] = field(default_factory=list)
    """List of legacy IDs."""

    def as_dict(self) -> Dict[str, Union[str, List[str], None]]:
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

    def as_dict(self) -> Dict[str, Union[str, bool]]:
        """
        Convert FixResult to dictionary for JSON serialization.
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
    def from_dict(cls, data: Dict[str, Union[str, bool, int, float]]) -> "FixResult":
        """
        Create FixResult from dictionary.
        """
        # Local imports to avoid circular dependencies
        from stig_assessor.xml.sanitizer import San
        from stig_assessor.exceptions import ValidationError

        if not isinstance(data, dict):
            raise ValidationError("Result entry must be an object")

        vid = data.get("vid") or data.get("vuln_id")
        if not vid:
            raise ValidationError("Result missing 'vid'")

        vid = San.vuln(str(vid))

        ok = data.get("ok", False)
        if isinstance(ok, str):
            ok = ok.lower() in ("true", "success", "passed")

        ts_str = data.get("ts") or data.get("timestamp")
        ts = datetime.now(timezone.utc)
        if ts_str:
            with suppress(ValueError, AttributeError):
                ts = datetime.fromisoformat(str(ts_str).rstrip("Z"))

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return cls(
            vid=vid,
            ok=bool(ok),
            ts=ts,
            message=str(data.get("msg") or ""),
            output=str(data.get("output") or ""),
            error=str(data.get("error") or ""),
        )
