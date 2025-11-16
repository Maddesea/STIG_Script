"""Core infrastructure modules.

This package contains fundamental infrastructure components used throughout
the STIG Assessor application.
"""

from __future__ import annotations

from stig_assessor.core.constants import (
    VERSION,
    BUILD_DATE,
    APP_NAME,
    STIG_VIEWER_VERSION,
    Status,
    Severity,
    ENCODINGS,
    MAX_FILE_SIZE,
    MAX_HISTORY_ENTRIES,
    MAX_FINDING_LENGTH,
    MAX_COMMENT_LENGTH,
    MAX_MERGE_FILES,
    MAX_VULNERABILITIES,
    KEEP_BACKUPS,
    KEEP_LOGS,
    LARGE_FILE_THRESHOLD,
    CHUNK_SIZE,
    MAX_RETRIES,
    RETRY_DELAY,
    MAX_XML_SIZE,
    ERROR_THRESHOLD,
    DEDUP_WINDOW,
    COMPRESSION_THRESHOLD,
)

__all__ = [
    "VERSION",
    "BUILD_DATE",
    "APP_NAME",
    "STIG_VIEWER_VERSION",
    "Status",
    "Severity",
    "ENCODINGS",
    "MAX_FILE_SIZE",
    "MAX_HISTORY_ENTRIES",
    "MAX_FINDING_LENGTH",
    "MAX_COMMENT_LENGTH",
    "MAX_MERGE_FILES",
    "MAX_VULNERABILITIES",
    "KEEP_BACKUPS",
    "KEEP_LOGS",
    "LARGE_FILE_THRESHOLD",
    "CHUNK_SIZE",
    "MAX_RETRIES",
    "RETRY_DELAY",
    "MAX_XML_SIZE",
    "ERROR_THRESHOLD",
    "DEDUP_WINDOW",
    "COMPRESSION_THRESHOLD",
]
