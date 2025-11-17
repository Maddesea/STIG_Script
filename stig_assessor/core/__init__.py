"""Core infrastructure modules.

Provides foundational components including configuration, logging,
state management, and dependency detection.
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
)
from stig_assessor.core.state import GlobalState, GLOBAL_STATE
from stig_assessor.core.deps import Deps
from stig_assessor.core.config import Cfg
from stig_assessor.core.logging import Log, LOG

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
    "GlobalState",
    "GLOBAL_STATE",
    "Deps",
    "Cfg",
    "Log",
    "LOG",
]
