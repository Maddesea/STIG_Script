"""STIG Assessor constants module.

This module defines all application constants, enumerations, and configuration values.
These values control file handling, validation thresholds, and STIG Viewer compatibility.
"""

from __future__ import annotations

import platform
import sys
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
# PLATFORM DETECTION
# ──────────────────────────────────────────────────────────────────────────────

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"
PLATFORM = platform.system()
PYTHON_VERSION = sys.version_info
MIN_PYTHON_VERSION = (3, 9)


# ──────────────────────────────────────────────────────────────────────────────
# FILE OPERATION CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50MB - triggers chunked processing
CHUNK_SIZE = 8192  # Bytes per read chunk
MAX_RETRIES = 3  # Number of retry attempts for I/O operations
RETRY_DELAY = 0.5  # Seconds between retries
MAX_XML_SIZE = 500 * 1024 * 1024  # 500MB - maximum XML file size


# ──────────────────────────────────────────────────────────────────────────────
# ENCODINGS
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
# PROCESSING LIMITS
# ──────────────────────────────────────────────────────────────────────────────

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB maximum file size
MAX_HISTORY_ENTRIES = 200  # Maximum history entries per vulnerability
MAX_FINDING_LENGTH = 65_000  # Maximum characters in finding details
MAX_COMMENT_LENGTH = 32_000  # Maximum characters in comments
MAX_MERGE_FILES = 100  # Maximum number of files to merge at once
MAX_VULNERABILITIES = 15_000  # Maximum vulnerabilities per checklist
KEEP_BACKUPS = 30  # Number of backup files to retain
KEEP_LOGS = 15  # Number of log files to retain


# ──────────────────────────────────────────────────────────────────────────────
# PROCESSING THRESHOLDS
# ──────────────────────────────────────────────────────────────────────────────

ERROR_THRESHOLD = 0.25  # Fail if >25% of vulnerabilities have errors
DEDUP_WINDOW = 20  # Number of history entries to check for deduplication
COMPRESSION_THRESHOLD = 1024  # Bytes before considering compression


# ──────────────────────────────────────────────────────────────────────────────
# ENUMERATIONS
# ──────────────────────────────────────────────────────────────────────────────


class Status(str, Enum):
    """STIG finding status values (STIG Viewer compatible).

    These status values are defined by STIG Viewer and must match exactly
    for compatibility. Status values are case-sensitive.
    """

    NOT_A_FINDING = "NotAFinding"
    OPEN = "Open"
    NOT_REVIEWED = "Not_Reviewed"
    NOT_APPLICABLE = "Not_Applicable"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a status value is valid.

        Args:
            value: The status string to validate

        Returns:
            True if the status is valid, False otherwise
        """
        return value in cls._value2member_map_

    @classmethod
    def all_values(cls) -> FrozenSet[str]:
        """Return all valid status values as a frozen set.

        Returns:
            Frozen set of all valid status strings
        """
        return frozenset(m.value for m in cls)


class Severity(str, Enum):
    """STIG severity levels (CAT I/II/III).

    Severity levels correspond to DISA CAT classifications:
    - HIGH = CAT I (critical findings)
    - MEDIUM = CAT II (significant findings)
    - LOW = CAT III (minor findings)
    """

    HIGH = "high"      # CAT I
    MEDIUM = "medium"  # CAT II
    LOW = "low"        # CAT III

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a severity value is valid.

        Args:
            value: The severity string to validate

        Returns:
            True if the severity is valid, False otherwise
        """
        return value in cls._value2member_map_

    @classmethod
    def all_values(cls) -> FrozenSet[str]:
        """Return all valid severity values as a frozen set.

        Returns:
            Frozen set of all valid severity strings
        """
        return frozenset(m.value for m in cls)
