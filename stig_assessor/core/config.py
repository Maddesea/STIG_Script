"""
STIG Assessor Configuration.

Application configuration and runtime settings.
This is a minimal version for modularization Phase 0-2.
"""

from __future__ import annotations
import platform
import sys
from pathlib import Path
from typing import Optional
import threading


class Cfg:
    """
    Application configuration and directory management.

    Provides:
    - Platform detection (Windows/Linux/macOS)
    - Directory management for application data
    - File size and processing limits
    - Configuration constants

    Thread-safe: Yes (uses RLock for initialization)
    """

    # Platform detection
    IS_WIN = platform.system() == "Windows"
    IS_LIN = platform.system() == "Linux"
    IS_MAC = platform.system() == "Darwin"
    PY_VER = sys.version_info
    MIN_PY = (3, 9)
    PLATFORM = platform.system()

    # Directory paths (initialized on first use)
    HOME: Optional[Path] = None
    APP_DIR: Optional[Path] = None
    LOG_DIR: Optional[Path] = None
    BACKUP_DIR: Optional[Path] = None
    EVIDENCE_DIR: Optional[Path] = None
    TEMPLATE_DIR: Optional[Path] = None
    PRESET_DIR: Optional[Path] = None
    FIX_DIR: Optional[Path] = None
    EXPORT_DIR: Optional[Path] = None
    BOILERPLATE_FILE: Optional[Path] = None

    # Limits and thresholds
    MAX_FILE = 500 * 1024 * 1024  # 500 MB
    MAX_HIST = 200
    MAX_FIND = 65000
    MAX_COMM = 32000
    MAX_MERGE = 100
    MAX_VULNS = 15000
    KEEP_BACKUPS = 30
    KEEP_LOGS = 15

    # History deduplication and compression constants
    DEDUP_CHECK_WINDOW = 20
    HIST_COMPRESS_HEAD = 15
    HIST_COMPRESS_TAIL = 100

    # Error rate thresholds for validation
    ERROR_RATE_WARN_THRESHOLD = 10.0  # Warn at 10% error rate
    ERROR_RATE_FAIL_THRESHOLD = 25.0  # Fail at 25% error rate

    _lock = threading.RLock()
    _done = False

    @classmethod
    def init(cls) -> None:
        """
        Initialize configuration directories.

        This is a minimal stub for Phase 0-2 modularization.
        Full implementation will be provided by Team 1.
        """
        with cls._lock:
            if cls._done:
                return

            # For now, just set HOME to avoid errors
            cls.HOME = Path.home()
            cls.APP_DIR = cls.HOME / ".stig_assessor"
            cls.LOG_DIR = cls.APP_DIR / "logs"
            cls.BACKUP_DIR = cls.APP_DIR / "backups"
            cls.EVIDENCE_DIR = cls.APP_DIR / "evidence"
            cls.TEMPLATE_DIR = cls.APP_DIR / "templates"
            cls.PRESET_DIR = cls.APP_DIR / "presets"
            cls.FIX_DIR = cls.APP_DIR / "fixes"
            cls.EXPORT_DIR = cls.APP_DIR / "exports"
            cls.BOILERPLATE_FILE = cls.TEMPLATE_DIR / "boilerplate.json"

            cls._done = True


# Initialize configuration on module import
Cfg.init()
