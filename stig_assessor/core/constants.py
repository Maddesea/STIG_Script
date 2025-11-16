"""Constants and enumerations for STIG Assessor."""

from __future__ import annotations
from enum import Enum

# ──────────────────────────────────────────────────────────────────────────────
# APPLICATION METADATA
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "7.3.0"
BUILD_DATE = "2025-11-16"
APP_NAME = "STIG Assessor Complete"
STIG_VIEWER_VERSION = "2.18"

# ──────────────────────────────────────────────────────────────────────────────
# FILE OPERATION CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50MB
CHUNK_SIZE = 8192
MAX_RETRIES = 3
RETRY_DELAY = 0.5
MAX_XML_SIZE = 500 * 1024 * 1024  # 500MB

# ──────────────────────────────────────────────────────────────────────────────
# CHARACTER ENCODINGS
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
    def all_values(cls) -> frozenset:
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
    def all_values(cls) -> frozenset:
        """Return all valid severity values."""
        return frozenset(m.value for m in cls)
