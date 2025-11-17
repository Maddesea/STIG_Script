"""Evidence metadata models.

This module provides data structures for tracking evidence files
associated with STIG vulnerabilities.

Source Lines: 4292-4336 (STIG_Script.py)
Team: 9 - Evidence Management
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any
from contextlib import suppress


@dataclass
class EvidenceMeta:
    """Evidence file metadata.

    Attributes:
        vid: Vulnerability ID (e.g., "V-123456")
        filename: Evidence filename (timestamped)
        imported: Import timestamp (UTC, timezone-aware)
        file_hash: SHA256 hash of file content
        file_size: File size in bytes
        description: Human-readable description
        category: Evidence category (e.g., "config", "screenshot")
        who: User who imported the evidence
    """

    vid: str
    filename: str
    imported: datetime
    file_hash: str
    file_size: int
    description: str = ""
    category: str = "general"
    who: str = "System"

    def as_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation
        """
        return {
            "vid": self.vid,
            "filename": self.filename,
            "imported": self.imported.isoformat(),
            "hash": self.file_hash,
            "size": self.file_size,
            "description": self.description,
            "category": self.category,
            "who": self.who,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceMeta":
        """Create from dictionary (JSON deserialization).

        Args:
            data: Dictionary with evidence metadata

        Returns:
            EvidenceMeta instance

        Raises:
            ValidationError: If data is invalid
        """
        # Import dependencies here to avoid circular imports
        try:
            from stig_assessor.xml.sanitizer import San
            from stig_assessor.exceptions import ValidationError
        except ImportError:
            # Fallback for when dependencies aren't available yet
            class ValidationError(Exception):
                pass

            class San:
                @staticmethod
                def vuln(s):
                    return str(s).strip()

        if not isinstance(data, dict):
            raise ValidationError("Evidence metadata must be object")

        vid = San.vuln(data.get("vid", ""))
        imported = datetime.now(timezone.utc)
        imported_str = data.get("imported")

        if imported_str:
            with suppress(Exception):
                imported = datetime.fromisoformat(imported_str.rstrip("Z"))

        if imported.tzinfo is None:
            imported = imported.replace(tzinfo=timezone.utc)

        return cls(
            vid=vid,
            filename=str(data.get("filename", "")),
            imported=imported,
            file_hash=str(data.get("hash", "")),
            file_size=int(data.get("size", 0)),
            description=str(data.get("description", "")),
            category=str(data.get("category", "general")),
            who=str(data.get("who", "System")),
        )
