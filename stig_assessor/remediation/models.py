"""Remediation models for STIG fix tracking and processing."""

from __future__ import annotations

from dataclasses import dataclass, field
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
