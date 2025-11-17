"""
STIG Assessor Logging System.

Thread-safe logging with contextual metadata support.
"""

from __future__ import annotations
import logging
import logging.handlers
import sys
import threading
from contextlib import suppress
from typing import Any, Dict, Optional


class Log:
    """
    Thread-safe logger with contextual metadata.

    Provides a singleton-like logger per name with support for
    contextual key-value pairs that are automatically included
    in log messages.

    Thread-safe: Yes
    """

    _instances: Dict[str, "Log"] = {}
    _lock = threading.RLock()

    def __new__(cls, name: str) -> "Log":
        with cls._lock:
            if name not in cls._instances:
                inst = super().__new__(cls)
                inst._initialised = False
                cls._instances[name] = inst
            return cls._instances[name]

    def __init__(self, name: str):
        if getattr(self, "_initialised", False):
            return

        with self._lock:
            if getattr(self, "_initialised", False):
                return
            self._initialised = True
            self.name = name
            self.log = logging.getLogger(name)
            self.log.setLevel(logging.INFO)
            self.log.handlers.clear()
            self.log.propagate = False
            self._ctx = threading.local()
            self._setup()

    def _setup(self) -> None:
        """Set up console and file handlers."""
        with suppress(Exception):
            console = logging.StreamHandler(sys.stderr)
            console.setLevel(logging.WARNING)
            console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.log.addHandler(console)

        with suppress(Exception):
            # Import here to avoid circular dependency
            from stig_assessor.core.config import Cfg

            file_handler = logging.handlers.RotatingFileHandler(
                str(Cfg.LOG_DIR / f"{self.name}.log"),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)-8s] %(message)s",
                    "%Y-%m-%d %H:%M:%S",
                )
            )
            self.log.addHandler(file_handler)

    def ctx(self, **kw: Any) -> None:
        """Add contextual metadata to log messages."""
        if not hasattr(self._ctx, "data"):
            self._ctx.data = {}
        self._ctx.data.update(kw)

    def clear(self) -> None:
        """Clear contextual metadata."""
        if hasattr(self._ctx, "data"):
            self._ctx.data.clear()

    def _context_str(self) -> str:
        """Get context string for log messages."""
        try:
            data = getattr(self._ctx, "data", {})
            if data:
                return "[" + ", ".join(f"{k}={v}" for k, v in data.items()) + "] "
        except Exception:
            pass
        return ""

    def _log(self, level: str, message: str, exc: bool = False) -> None:
        """Internal logging method."""
        try:
            getattr(self.log, level)(self._context_str() + str(message), exc_info=exc)
        except Exception:
            print(f"[{level.upper()}] {message}", file=sys.stderr)

    def debug(self, msg: str) -> None:
        """Log debug message."""
        self._log("debug", msg)

    def info(self, msg: str) -> None:
        """Log info message."""
        self._log("info", msg)

    def warning(self, msg: str) -> None:
        """Log warning message."""
        self._log("warning", msg)

    def error(self, msg: str, exc_info: bool = False) -> None:
        """Log error message."""
        self._log("error", msg, exc_info)

    def critical(self, msg: str, exc_info: bool = False) -> None:
        """Log critical message."""
        self._log("critical", msg, exc_info)

    def d(self, msg: str) -> None:
        """Debug (short form)."""
        self.debug(msg)

    def i(self, msg: str) -> None:
        """Info (short form)."""
        self.info(msg)

    def w(self, msg: str) -> None:
        """Warning (short form)."""
        self.warning(msg)

    def e(self, msg: str, exc: bool = False) -> None:
        """Error (short form)."""
        self.error(msg, exc_info=exc)

    def c(self, msg: str, exc: bool = False) -> None:
        """Critical (short form)."""
        self.critical(msg, exc_info=exc)


# Module-level logger instance
LOG = Log("stig_assessor")
