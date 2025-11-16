"""
STIG Assessor Constants and Enumerations.

Application-wide constants, configuration values, and enumerations.
"""

from __future__ import annotations
from enum import Enum
from typing import FrozenSet

# ──────────────────────────────────────────────────────────────────────────────
# VERSION INFORMATION
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "8.0.0"
BUILD_DATE = "2025-11-16"
APP_NAME = "STIG Assessor Complete"
STIG_VIEWER_VERSION = "2.18"

# ──────────────────────────────────────────────────────────────────────────────
# FILE OPERATION LIMITS
# ──────────────────────────────────────────────────────────────────────────────

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
CHUNK_SIZE = 8192  # 8 KB chunks for streaming
MAX_RETRIES = 3  # Retry attempts for I/O operations
RETRY_DELAY = 0.5  # Initial retry delay in seconds
MAX_XML_SIZE = 500 * 1024 * 1024  # 500 MB maximum XML file size

# ──────────────────────────────────────────────────────────────────────────────
# ENCODING DETECTION
# ──────────────────────────────────────────────────────────────────────────────

ENCODINGS = [
    "utf-8",
    "utf-8-sig",
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "latin-1",
    "cp1252",
    "iso-8859-1",
    "ascii",
]

# ──────────────────────────────────────────────────────────────────────────────
# ENUMERATIONS
# ──────────────────────────────────────────────────────────────────────────────


class Status(str, Enum):
    """STIG finding status values (STIG Viewer compatible)."""
    NOT_A_FINDING = "NotAFinding"
    OPEN = "Open"
    NOT_REVIEWED = "Not_Reviewed"
    NOT_APPLICABLE = "Not_Applicable"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a status value is valid."""
        return value in cls._value2member_map_

    @classmethod
    def all_values(cls) -> FrozenSet[str]:
        """Return all valid status values."""
        return frozenset(m.value for m in cls)


class Severity(str, Enum):
    """STIG severity levels (CAT I/II/III)."""
    HIGH = "high"      # CAT I
    MEDIUM = "medium"  # CAT II
    LOW = "low"        # CAT III

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a severity value is valid."""
        return value in cls._value2member_map_

    @classmethod
    def all_values(cls) -> FrozenSet[str]:
        """Return all valid severity values."""
        return frozenset(m.value for m in cls)
