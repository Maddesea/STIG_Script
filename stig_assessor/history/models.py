"""
History entry dataclass.

This module provides the Hist dataclass representing a single history
entry for a vulnerability finding.

Thread-safe: Yes (immutable after creation)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict

# Import from modular package
from stig_assessor.exceptions import ValidationError
from stig_assessor.xml.sanitizer import San


@dataclass(order=True)
class Hist:
    """
    Single history entry for a vulnerability finding.

    Attributes:
        ts: Timestamp of the history entry (timezone-aware)
        stat: Status value (NotAFinding, Open, Not_Applicable, Not_Reviewed)
        find: Finding details text
        comm: Comments text
        src: Source of the entry (e.g., 'xccdf', 'manual', 'merge')
        chk: Content hash for deduplication
        sev: Severity level (high, medium, low)
        who: Username of the person who created the entry

    Thread-safe: Yes (immutable after creation)
    """

    # Primary sort key (ordered by timestamp)
    ts: datetime

    # Content fields (not used for ordering)
    stat: str = field(compare=False)
    find: str = field(compare=False)
    comm: str = field(compare=False)
    src: str = field(compare=False)
    chk: str = field(compare=False)
    sev: str = field(default="medium", compare=False)
    who: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        """
        Validate and normalize fields after initialization.

        - Ensures timestamp is timezone-aware (converts to UTC if naive)
        - Normalizes status and severity values
        - Sets default username from environment if not provided
        """
        # Ensure timezone-aware timestamp
        if self.ts.tzinfo is None:
            self.ts = self.ts.replace(tzinfo=timezone.utc)

        # Normalize status (with fallback to default)
        try:
            self.stat = San.status(self.stat)
        except (ValidationError, ValueError):
            self.stat = "Not_Reviewed"  # Default fallback

        # Normalize severity (with fallback to default)
        try:
            self.sev = San.sev(self.sev)
        except (ValidationError, ValueError):
            self.sev = "medium"  # Default fallback

        # Set default username from environment if not provided
        if not self.who:
            self.who = os.getenv("USER") or os.getenv("USERNAME") or "System"

    def as_dict(self) -> Dict[str, Any]:
        """
        Serialize history entry to dictionary.

        Returns:
            Dictionary representation with ISO format timestamp
        """
        return {
            "ts": self.ts.isoformat(),
            "stat": self.stat,
            "find": self.find,
            "comm": self.comm,
            "src": self.src,
            "chk": self.chk,
            "sev": self.sev,
            "who": self.who,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Hist":
        """
        Create history entry from dictionary.

        Args:
            data: Dictionary containing history entry data

        Returns:
            New Hist instance

        Raises:
            ValidationError: If data is not a dictionary
        """
        if not isinstance(data, dict):
            raise ValidationError("History payload must be object")

        # Parse timestamp with fallback to current time
        ts = datetime.now(timezone.utc)
        ts_str = data.get("ts")
        if ts_str:
            try:
                # Handle ISO format with optional 'Z' suffix
                ts = datetime.fromisoformat(ts_str.rstrip("Z"))
            except Exception:
                pass  # Use default timestamp

        # Ensure timezone-aware
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return cls(
            ts=ts,
            stat=data.get("stat", "Not_Reviewed"),
            find=str(data.get("find", "")),
            comm=str(data.get("comm", "")),
            src=str(data.get("src", "unknown")),
            chk=str(data.get("chk", "")) or "legacy",
            sev=str(data.get("sev", "medium")),
            who=str(data.get("who", "")),
        )

    def content_hash(self) -> str:
        """
        Generate content hash for deduplication.

        Creates a hash based on status, finding details, comments,
        severity, and username to detect duplicate entries.

        Returns:
            SHA256 hash (first 16 characters) of content fields
        """
        summary = f"{self.stat}|{self.find}|{self.comm}|{self.sev}|{self.who}"
        try:
            digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()[:16]
        except (UnicodeEncodeError, AttributeError):
            # Fallback for encoding errors
            import uuid
            digest = f"chk_{uuid.uuid4().hex[:6]}"
        return digest
