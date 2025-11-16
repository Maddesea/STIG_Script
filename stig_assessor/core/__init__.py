"""Core infrastructure modules."""

from __future__ import annotations

from stig_assessor.core.constants import (
    VERSION,
    BUILD_DATE,
    APP_NAME,
    STIG_VIEWER_VERSION,
    Status,
    Severity,
    ENCODINGS,
    LARGE_FILE_THRESHOLD,
    CHUNK_SIZE,
    MAX_RETRIES,
    RETRY_DELAY,
    MAX_XML_SIZE,
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
    "LARGE_FILE_THRESHOLD",
    "CHUNK_SIZE",
    "MAX_RETRIES",
    "RETRY_DELAY",
    "MAX_XML_SIZE",
    "GlobalState",
    "GLOBAL_STATE",
    "Deps",
    "Cfg",
    "CFG",
    "Log",
    "LOG",
]
