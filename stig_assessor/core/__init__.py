"""Core infrastructure modules.

This package contains fundamental infrastructure components used throughout
the STIG Assessor application.

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
    ERROR_THRESHOLD,
    DEDUP_WINDOW,
    COMPRESSION_THRESHOLD,
)
from stig_assessor.core.state import GlobalState, GLOBAL_STATE
from stig_assessor.core.deps import Deps
from stig_assessor.core.config import Cfg, CFG
from stig_assessor.core.logging import Log, LOG

# Initialize configuration and dependencies
Deps.check()
Deps.warn_if_unsafe()

try:
    Cfg.init()
except Exception as e:
    import sys
    print(f"FATAL: Config initialization failed: {e}", file=sys.stderr)
    sys.exit(1)

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
    "GlobalState",
    "GLOBAL_STATE",
    "Deps",
    "Cfg",
    "CFG",
    "Log",
    "LOG",
]
