"""
STIG Assessor Configuration.

Application configuration and runtime settings.
This is a minimal version for modularization Phase 0-2.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import threading
from contextlib import suppress
from pathlib import Path
from typing import List, Optional, Tuple


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
    DEDUP_CHECK_WINDOW = 20  # Check last N entries for duplicate prevention
    HIST_COMPRESS_HEAD = 15  # Keep first N entries when compressing history
    HIST_COMPRESS_TAIL = 100  # Keep last N entries when compressing history

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

            # Find writable home directory
            candidates: List[Path] = []

            with suppress(Exception):
                candidates.append(Path.home())

            for env_var in ("USERPROFILE", "HOME"):
                val = os.environ.get(env_var)
                if val and os.path.exists(val):
                    candidates.append(Path(val))

            candidates.append(Path(tempfile.gettempdir()) / "stig_user")
            with suppress(Exception):
                candidates.append(Path.cwd() / ".stig_home")

            attempted_paths: List[str] = []
            for candidate in candidates:
                attempted_paths.append(str(candidate))
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    tmp = candidate / f".stig_test_{os.getpid()}"
                    tmp.write_text("ok", encoding="utf-8")
                    tmp.unlink()
                    cls.HOME = candidate
                    break
                except (OSError, PermissionError, IOError):
                    continue
                except Exception:
                    continue

            if not cls.HOME:
                raise RuntimeError(
                    f"Cannot find writable home directory. Tried: {', '.join(attempted_paths[:5])}. "
                    f"Please ensure write permissions on one of these directories or set $HOME/$USERPROFILE."
                )

            # Set up directory structure
            cls.APP_DIR = cls.HOME / ".stig_assessor"
            cls.LOG_DIR = cls.APP_DIR / "logs"
            cls.BACKUP_DIR = cls.APP_DIR / "backups"
            cls.EVIDENCE_DIR = cls.APP_DIR / "evidence"
            cls.TEMPLATE_DIR = cls.APP_DIR / "templates"
            cls.PRESET_DIR = cls.APP_DIR / "presets"
            cls.FIX_DIR = cls.APP_DIR / "fixes"
            cls.EXPORT_DIR = cls.APP_DIR / "exports"
            cls.BOILERPLATE_FILE = cls.TEMPLATE_DIR / "boilerplate.json"

            # Create required directories
            required = [cls.APP_DIR, cls.LOG_DIR, cls.BACKUP_DIR]
            optional = [
                cls.EVIDENCE_DIR,
                cls.TEMPLATE_DIR,
                cls.PRESET_DIR,
                cls.FIX_DIR,
                cls.EXPORT_DIR,
            ]

            for directory in required:
                directory.mkdir(parents=True, exist_ok=True)
                tmp = directory / f".write_test_{os.getpid()}"
                tmp.write_text("ok", encoding="utf-8")
                tmp.unlink()

            for directory in optional:
                directory.mkdir(parents=True, exist_ok=True)

            cls._done = True

    @classmethod
    def check(cls) -> Tuple[bool, List[str]]:
        """Check if all required dependencies and permissions are available."""
        from stig_assessor.core.deps import Deps

        ET, _ = Deps.get_xml()
        errs: List[str] = []

        if cls.PY_VER < cls.MIN_PY:
            errs.append(f"Python {cls.MIN_PY[0]}.{cls.MIN_PY[1]}+ required")

        for module in ("json", "hashlib", "pathlib", "logging", "zipfile", "csv", "uuid"):
            try:
                __import__(module)
            except Exception:
                errs.append(f"Missing stdlib module: {module}")

        try:
            ET.Element("test")
        except Exception:
            errs.append("XML parser failed")

        if cls.APP_DIR and not os.access(cls.APP_DIR, os.W_OK):
            errs.append(f"No write permission: {cls.APP_DIR}")

        return len(errs) == 0, errs

    @classmethod
    def cleanup_old(cls) -> Tuple[int, int]:
        """Clean up old backup and log files."""
        def clean(directory: Path, keep: int, pattern: str) -> int:
            if not directory or not directory.exists():
                return 0
            removed = 0
            files = sorted(
                directory.glob(pattern),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in files[keep:]:
                with suppress(Exception):
                    old.unlink()
                    removed += 1
            return removed

        backups = clean(cls.BACKUP_DIR, cls.KEEP_BACKUPS, "*.bak")
        logs = clean(cls.LOG_DIR, cls.KEEP_LOGS, "*.log")
        return backups, logs


# Module-level singleton instance (initialized on first import)
CFG = Cfg
Cfg.init()
