"""Core infrastructure modules.

This package contains fundamental infrastructure components used throughout
the STIG Assessor application, including configuration, logging, state management,
and dependency detection.
"""

from __future__ import annotations

from stig_assessor.core.config import CFG, Cfg
from stig_assessor.core.constants import (APP_NAME, BUILD_DATE, CHUNK_SIZE,
                                          COMPRESSION_THRESHOLD, DEDUP_WINDOW,
                                          ENCODINGS, ERROR_THRESHOLD, IS_LINUX,
                                          IS_MACOS, IS_WINDOWS, KEEP_BACKUPS,
                                          KEEP_LOGS, LARGE_FILE_THRESHOLD,
                                          MAX_COMMENT_LENGTH, MAX_FILE_SIZE,
                                          MAX_FINDING_LENGTH,
                                          MAX_HISTORY_ENTRIES, MAX_MERGE_FILES,
                                          MAX_RETRIES, MAX_VULNERABILITIES,
                                          MAX_XML_SIZE, RETRY_DELAY,
                                          STIG_VIEWER_VERSION, VERSION,
                                          Severity, Status)
from stig_assessor.core.deps import Deps
from stig_assessor.core.logging import LOG, Log
from stig_assessor.core.state import GLOBAL_STATE, GlobalState

# Initialize configuration and dependencies
Deps.check()
Deps.warn_if_unsafe()

try:
    Cfg.init()
except (RuntimeError, OSError, ValueError) as e:
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
    "IS_WINDOWS",
    "IS_LINUX",
    "IS_MACOS",
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
